"""Check every artifact a lockfile pins: fetch it from PyPI, check its hash, scan it.

Network goes only to pypi.org (the JSON API, to find the file a pinned hash
belongs to when the lockfile does not give its URL) and files.pythonhosted.org
(the file itself), over https, with redirects elsewhere refused. Nothing is
read until its sha256 matches the lockfile.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from packaging.tags import Tag, sys_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from buckthorn.findings import Finding, Result, Severity
from buckthorn.scan import ARTIFACT_SUFFIXES, MAX_TOTAL_BYTES, scan_artifact

MAX_DOWNLOAD_BYTES = MAX_TOTAL_BYTES
MAX_INDEX_BYTES = 16 * 1024 * 1024
_ALLOWED_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})
_PYPI_REGISTRY = "https://pypi.org/simple"
# Artifact file names are used as the last part of a cache path, so they must be plain.
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

Fetch = Callable[[str, int], bytes]


class FetchError(Exception):
    pass


@dataclass
class PinnedFile:
    sha256: str
    filename: str | None = None
    url: str | None = None


@dataclass
class Pin:
    name: str
    version: str
    files: list[PinnedFile] = field(default_factory=list)
    problem: str | None = None  # why this pin cannot be checked; reported as not_verified
    skip: bool = False  # the project itself or a local workspace member, not a dependency

    @property
    def label(self) -> str:
        return f"{self.name}=={self.version}" if self.version else self.name


def parse(path: Path) -> list[Pin]:
    """Pins from a requirements file, uv.lock or poetry.lock. ValueError for anything else."""
    text = path.read_text(encoding="utf-8")
    if path.name in ("uv.lock", "poetry.lock"):
        try:
            data = tomllib.loads(text)
        except RecursionError:
            raise ValueError("TOML nested too deeply to parse") from None
        return _parse_uv(data) if path.name == "uv.lock" else _parse_poetry(data)
    if path.suffix in (".txt", ".in") or path.name.startswith("requirements"):
        return _parse_requirements(text)
    raise ValueError(f"{path.name}: not a requirements file, uv.lock, poetry.lock or MCP config")


def _parse_requirements(text: str) -> list[Pin]:
    pins = []
    for raw in re.sub(r"\\\r?\n", " ", text).splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            pins.append(Pin(line, "", problem="includes another file, which was not read"))
        elif line.startswith(("-e", "--editable")):
            pins.append(Pin(line, "", problem="editable install, not checked"))
        elif line.startswith("-"):
            continue  # --index-url and other options
        else:
            hashes = re.findall(r"--hash[=\s]+sha256:([0-9A-Fa-f]+)", line)
            spec = re.split(r"\s--hash", line)[0].split(";")[0].strip()
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*(\S+)", spec)
            if not match:
                pins.append(Pin(spec, "", problem="not pinned with ==, so not checked"))
            elif not hashes:
                problem = "no --hash, so the artifact to check is unknown"
                pins.append(Pin(match[1], match[3], problem=problem))
            else:
                pins.append(Pin(match[1], match[3], [PinnedFile(h.lower()) for h in hashes]))
    return pins


def _parse_uv(data: dict) -> list[Pin]:
    pins = []
    for package in data.get("package", []):
        pin = Pin(str(package.get("name", "")), str(package.get("version", "")))
        source = package.get("source", {})
        if source.keys() & {"editable", "virtual", "directory"}:
            pin.skip = True
        elif source.get("registry", "").rstrip("/") != _PYPI_REGISTRY:
            pin.problem = f"source {source} is not on PyPI, not checked"
        else:
            entries = ([package["sdist"]] if "sdist" in package else []) + package.get("wheels", [])
            for entry in entries:
                url = str(entry.get("url", ""))
                filename = urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[-1])
                pin.files.append(PinnedFile(_sha256_of(entry.get("hash")), filename, url))
        pins.append(pin)
    return pins


def _parse_poetry(data: dict) -> list[Pin]:
    pins = []
    for package in data.get("package", []):
        pin = Pin(str(package.get("name", "")), str(package.get("version", "")))
        source = package.get("source")
        if source:
            pin.problem = (
                f"source {source.get('type')} {source.get('url')} is not PyPI, not checked"
            )
        for entry in package.get("files", []):
            pin.files.append(PinnedFile(_sha256_of(entry.get("hash")), str(entry.get("file", ""))))
        pins.append(pin)
    return pins


def _sha256_of(value: object) -> str:
    """The hex digest from "sha256:<hex>", or "" for anything else (then not checked)."""
    algorithm, _, digest = str(value or "").partition(":")
    return digest.lower() if algorithm == "sha256" else ""


def check(
    path: Path,
    fetch: Fetch | None = None,
    cache_dir: Path | None = None,
    progress: Callable[[str], None] | None = None,
    all_files: bool = False,
) -> list[Result]:
    """One Result per pinned artifact, plus one per pin that cannot be checked.

    By default only the file this machine would install is checked for each pin:
    lockfiles list every platform's wheels. all_files checks every pinned file.
    progress, if given, is called with each artifact's file name before it is fetched.
    """
    fetch = fetch or fetch_url
    pins = parse(path)
    results: list[Result] = []
    with tempfile.TemporaryDirectory(prefix="buckthorn-") as tmp:
        cache = cache_dir or Path(tmp)
        for pin in pins:
            if pin.skip:
                continue
            if pin.problem:
                results.append(_gap(pin.label, "", pin.problem))
                continue
            results.extend(_check_pin(pin, fetch, cache, progress or (lambda _: None), all_files))
    return results


def _check_pin(
    pin: Pin, fetch: Fetch, cache: Path, progress: Callable[[str], None], all_files: bool
) -> list[Result]:
    results = []
    usable: list[tuple[str, str, str]] = []  # (filename, sha256, url)
    index: dict[str, tuple[str, str]] | None = None  # sha256 -> (filename, url), fetched once
    for pinned in pin.files:
        sha, filename, url = pinned.sha256, pinned.filename, pinned.url
        if not _SHA256.match(sha):
            results.append(_gap(filename or pin.label, "", "no sha256 pinned for this file"))
            continue
        if url is None:
            if index is None:
                try:
                    index = _release_files(pin, fetch)
                except FetchError as exc:
                    index = {}
                    results.append(_gap(pin.label, "", f"could not read the PyPI index: {exc}"))
            if sha not in index:
                if index:
                    message = f"pinned hash is not a file of {pin.label} on PyPI"
                    results.append(_gap(filename or pin.label, sha, message))
                continue
            index_filename, url = index[sha]
            filename = filename or index_filename
        filename = filename or ""
        if not (_SAFE_FILENAME.match(filename) and filename.lower().endswith(ARTIFACT_SUFFIXES)):
            results.append(_gap(filename or pin.label, sha, "not a plain wheel or sdist file name"))
            continue
        if not allowed_url(url):
            results.append(_gap(filename, sha, f"{url} is not on PyPI's file host, not fetched"))
            continue
        usable.append((filename, sha, url))
    chosen = usable if all_files else _installable_here(usable)
    if usable and not chosen:
        message = "no file of this pin installs on this machine, so none was checked (--all-files)"
        results.append(
            Result(pin.label, "", [Finding("BKT-LOCK-003", message, Severity.INFO, pin.label)])
        )
    for filename, sha, url in chosen:
        progress(filename)
        results.append(_fetch_and_scan(filename, sha, url, fetch, cache))
    return results


@functools.cache
def _tag_ranks() -> dict[Tag, int]:
    """This interpreter's wheel tags, best first: the same for every pin in a run."""
    return {tag: n for n, tag in enumerate(sys_tags())}


def _installable_here(files: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """The file pip would pick on this machine: the best compatible wheel, else the sdist."""
    rank = _tag_ranks()
    best: tuple[int, tuple[str, str, str]] | None = None
    for entry in files:
        if not entry[0].lower().endswith(".whl"):
            continue
        try:
            tags = parse_wheel_filename(entry[0])[3]
        except InvalidWheelFilename:
            continue
        score = min((rank[t] for t in tags if t in rank), default=None)
        if score is not None and (best is None or score < best[0]):
            best = (score, entry)
    if best:
        return [best[1]]
    sdists = [e for e in files if not e[0].lower().endswith(".whl")]
    return sdists[:1]


def scan_release(
    name: str, version: str, fetch: Fetch | None = None, cache_dir: Path | None = None
) -> Result:
    """Fetch and scan the file of name==version this machine would install.

    FetchError when the release cannot be read from PyPI or has no such file.
    """
    fetch = fetch or fetch_url
    usable = [
        (filename, sha, url)
        for sha, (filename, url) in _release_files(Pin(name, version), fetch).items()
        if _SHA256.match(sha)
        and _SAFE_FILENAME.match(filename)
        and filename.lower().endswith(ARTIFACT_SUFFIXES)
        and allowed_url(url)
    ]
    chosen = _installable_here(usable)
    if not chosen:
        raise FetchError(f"no file of {name}=={version} installs on this machine")
    filename, sha, url = chosen[0]
    with tempfile.TemporaryDirectory(prefix="buckthorn-") as tmp:
        return _fetch_and_scan(filename, sha, url, fetch, cache_dir or Path(tmp))


def _release_files(pin: Pin, fetch: Fetch) -> dict[str, tuple[str, str]]:
    name = urllib.parse.quote(pin.name, safe="")
    version = urllib.parse.quote(pin.version, safe="")
    raw = fetch(f"https://pypi.org/pypi/{name}/{version}/json", MAX_INDEX_BYTES)
    try:
        entries = json.loads(raw)["urls"]
        return {
            str(e["digests"]["sha256"]).lower(): (str(e["filename"]), str(e["url"]))
            for e in entries
        }
    except (ValueError, KeyError, TypeError) as exc:
        raise FetchError(f"unexpected index response: {exc}") from exc


def _fetch_and_scan(filename: str, sha: str, url: str, fetch: Fetch, cache: Path) -> Result:
    # The cache is keyed by the pinned hash and re-checked on every read, so a
    # tampered entry is fetched again rather than trusted.
    target = cache / sha / filename
    cached = target.is_file() and not target.is_symlink()
    if not (cached and hashlib.sha256(target.read_bytes()).hexdigest() == sha):
        try:
            data = fetch(url, MAX_DOWNLOAD_BYTES)
        except FetchError as exc:
            return _gap(filename, sha, f"could not fetch: {exc}")
        actual = hashlib.sha256(data).hexdigest()
        if actual != sha:
            message = f"downloaded file's sha256 is {actual}, the lockfile pins {sha}"
            return Result(filename, actual, [Finding("BKT-LOCK-001", message, Severity.HIGH, url)])
        target.parent.mkdir(parents=True, exist_ok=True)
        # Write beside it and rename over it: a link planted at target is replaced,
        # never written through.
        partial = target.with_name(f".{filename}.partial")
        partial.unlink(missing_ok=True)
        partial.write_bytes(data)
        os.replace(partial, target)
    return Result(filename, sha, scan_artifact(target))


def _gap(path: str, sha: str, message: str) -> Result:
    return Result(path, sha, [Finding("BKT-LOCK-002", message, Severity.INFO, path)])


def allowed_url(url: str | None) -> bool:
    if not url:
        return False
    parts = urllib.parse.urlparse(url)
    return (
        parts.scheme == "https"
        and parts.hostname in _ALLOWED_HOSTS
        and parts.port in (None, 443)
        and not parts.username
        and not parts.password
    )


class _PyPIOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not allowed_url(newurl):
            raise FetchError(f"redirect to {newurl} refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url: str, max_bytes: int) -> bytes:
    """GET an https URL on PyPI, up to max_bytes. FetchError for anything else."""
    if not allowed_url(url):
        raise FetchError(f"{url} is not on PyPI")
    opener = urllib.request.build_opener(_PyPIOnlyRedirects)
    # S310: https and the host were checked above, and redirects are checked too.
    request = urllib.request.Request(url, headers={"User-Agent": "buckthorn"})  # noqa: S310
    try:
        with opener.open(request, timeout=60) as response:  # noqa: S310
            data = response.read(max_bytes + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise FetchError(str(exc)) from exc
    if len(data) > max_bytes:
        raise FetchError(f"larger than {max_bytes} bytes")
    return data
