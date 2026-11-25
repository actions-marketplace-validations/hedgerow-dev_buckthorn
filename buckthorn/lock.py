"""Check every artifact a lockfile pins: fetch it, check its hash, scan it.

Network goes only to pypi.org (the JSON API, to find the file a pinned hash
belongs to when the lockfile does not give its URL), files.pythonhosted.org
(the file itself), for package-lock.json registry.npmjs.org, and for
packages.lock.json and packages.config api.nuget.org, over https, with
redirects elsewhere refused. Nothing is read until its hash matches the
lockfile, except from packages.config, which pins no hash.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import io
import json
import os
import platform
import re
import struct
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from packaging.tags import Tag, sys_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from buckthorn import nuget
from buckthorn.findings import Finding, Result, Severity
from buckthorn.scan import ARTIFACT_SUFFIXES, MAX_TOTAL_BYTES, scan_artifact

MAX_DOWNLOAD_BYTES = MAX_TOTAL_BYTES
MAX_INDEX_BYTES = 16 * 1024 * 1024
_ALLOWED_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})
_NPM_HOSTS = frozenset({"registry.npmjs.org"})
NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
_NUGET_HOSTS = frozenset({"api.nuget.org"})
NUGET_LOCKFILES = ("packages.lock.json", "packages.config")
_NUGET_FLAT = "https://api.nuget.org/v3-flatcontainer"
_NUGET_ID = re.compile(r"^[A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*$")
_NUGET_VERSION = re.compile(r"^(\d+(?:\.\d+){0,3})(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
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
    raise ValueError(
        f"{path.name}: not a requirements file, uv.lock, poetry.lock, package-lock.json, "
        "packages.lock.json, packages.config or MCP config"
    )


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
    if path.name in NPM_LOCKFILES:
        return _check_npm(path, fetch, cache_dir, progress or (lambda _: None), all_files)
    if path.name in NUGET_LOCKFILES:
        return _check_nuget(path, fetch, cache_dir, progress or (lambda _: None))
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


def _fetch_and_scan(
    filename: str,
    sha: str,
    url: str,
    fetch: Fetch,
    cache: Path,
    algorithm: str = "sha256",
    label: str | None = None,
) -> Result:
    """sha is the pinned hex digest in algorithm ("nuget" is NuGet's content hash).
    The Result is named label (else filename) and carries the file's sha256,
    whatever the lockfile pinned."""
    label = label or filename
    # The cache is keyed by the pinned hash and re-checked on every read, so a
    # tampered entry is fetched again rather than trusted.
    target = cache / sha / filename
    cached = target.is_file() and not target.is_symlink()
    if not (cached and _digest(algorithm, target.read_bytes()) == sha):
        try:
            data = fetch(url, MAX_DOWNLOAD_BYTES)
        except FetchError as exc:
            return _gap(label, sha if algorithm == "sha256" else "", f"could not fetch: {exc}")
        actual = _digest(algorithm, data)
        if not actual:
            message = "not a package NuGet would read, so its content hash is unknown"
            return _gap(label, hashlib.sha256(data).hexdigest(), message)
        if actual != sha:
            kind = "NuGet content hash" if algorithm == "nuget" else algorithm
            message = f"downloaded file's {kind} is {actual}, the lockfile pins {sha}"
            finding = Finding("BKT-LOCK-001", message, Severity.HIGH, url)
            return Result(label, hashlib.sha256(data).hexdigest(), [finding])
        _store(target, data)
    data_sha256 = sha if algorithm == "sha256" else hashlib.sha256(target.read_bytes()).hexdigest()
    return Result(label, data_sha256, scan_artifact(target))


def _store(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    # Write beside it and rename over it: a link planted at target is replaced,
    # never written through.
    partial = target.with_name(f".{target.name}.partial")
    partial.unlink(missing_ok=True)
    partial.write_bytes(data)
    os.replace(partial, target)


def _digest(algorithm: str, data: bytes) -> str:
    """Hex digest; for "nuget", NuGet's content hash, or "" if NuGet would refuse the file."""
    if algorithm != "nuget":
        return hashlib.new(algorithm, data).hexdigest()
    try:
        return nuget_content_hash(data)
    except ValueError:
        return ""


def _check_npm(
    path: Path,
    fetch: Fetch,
    cache_dir: Path | None,
    progress: Callable[[str], None],
    all_files: bool,
) -> list[Result]:
    """package-lock.json or npm-shrinkwrap.json, lockfileVersion 2 or 3.

    Each registry tarball is fetched from registry.npmjs.org and checked against
    its sha512 integrity before it is read. A package npm would not install on
    this machine (its os or cpu field) is skipped unless all_files.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except RecursionError:
        raise ValueError("JSON nested too deeply to parse") from None
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        message = "no 'packages' map (lockfileVersion 1?): run npm install to update it"
        return [_gap(path.name, "", message)]
    results: list[Result] = []
    seen: set[str] = set()
    fetched_at: dict[str, Path] = {}  # lock key -> its hash-checked tarball in the cache
    off_platform: set[str] = set()  # lock keys npm skips here, and so their nested ones
    here = _npm_platform()
    with tempfile.TemporaryDirectory(prefix="buckthorn-") as tmp:
        cache = cache_dir or Path(tmp)
        # Sorted, so a package comes before the ones nested under it.
        for key, entry in sorted(packages.items()):
            if not key or not isinstance(entry, dict) or entry.get("link"):
                continue  # the project, or a workspace link
            if "node_modules/" not in key:
                continue  # a workspace folder: its files are in the repository, not fetched
            parents = [key[:i] for i in range(len(key)) if key.startswith("/node_modules/", i)]
            if any(p in off_platform for p in parents):
                continue  # nested in a package npm does not install here
            bundle_shape = not entry.get("resolved") and not entry.get("integrity")
            if bundle_shape and _bundled_in(key, parents, fetched_at):
                continue  # shipped inside a parent tarball that was read
            name = str(entry.get("name") or key.rsplit("node_modules/", 1)[-1])
            version = str(entry.get("version", ""))
            url, sha512 = entry.get("resolved"), _sha512_of(entry.get("integrity"))
            if url is None and sha512:  # npm's omit-lockfile-registry-resolved
                base = name.rsplit("/", 1)[-1]
                url = f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz"
            # The allowlist matches by name and version, so both come from the
            # tarball fetched, and an entry that claims another is not trusted.
            fetched = _npm_tarball(url)
            problem = (
                f"source {url} is not on registry.npmjs.org, not checked"
                if not allowed_url(url, _NPM_HOSTS)
                else "no sha512 integrity, so the tarball cannot be checked"
                if not sha512
                else "not a plain npm registry tarball URL"
                if fetched is None
                else f"resolved URL is {fetched[0]}@{fetched[1]}, not {name}@{version}"
                if fetched[:2] != (name, version)
                else None
            )
            if problem or fetched is None:
                results.append(_gap(f"{name}=={version}", "", problem or ""))
                continue
            filename = fetched[2]
            label = f"{name}-{version}.tgz"
            fits = all(
                _npm_allows(entry.get(field) or [], value)
                for field, value in zip(("os", "cpu"), here, strict=True)
            )
            if not (fits or all_files):
                off_platform.add(key)
                message = "npm does not install this package on this machine (os, cpu), not checked"
                info = Finding("BKT-LOCK-003", message + " (--all-files)", Severity.INFO, label)
                results.append(Result(label, "", [info]))
                continue
            # Same integrity, same bytes: scanned once. Only a scanned copy counts.
            if sha512 not in seen:
                progress(label)
                result = _fetch_and_scan(filename, sha512, str(url), fetch, cache, "sha512", label)
                results.append(result)
                seen.add(sha512)
            target = cache / sha512 / filename
            if target.is_file():
                fetched_at[key] = target
    return results


def _bundled_in(key: str, parents: list[str], fetched_at: dict[str, Path]) -> bool:
    """Whether the nearest parent read so far ships this package in its own tarball.

    npm works bundling out from the parent's tarball, so a lockfile flag is not
    trusted: the package.json must be in the hash-checked tarball itself.
    """
    parent = next((p for p in reversed(parents) if p in fetched_at), None)
    if parent is None:
        return False
    return key[len(parent) + 1 :] + "/package.json" in _tar_paths(fetched_at[parent])


@functools.lru_cache(maxsize=64)
def _tar_paths(path: Path) -> frozenset[str]:
    """Member paths of a tarball below its top folder; empty if it cannot be listed."""
    try:
        with tarfile.open(path, "r:gz") as tf:
            return frozenset(n.split("/", 1)[-1] for n in tf.getnames())
    except (tarfile.TarError, OSError, EOFError):
        return frozenset()


_NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.IGNORECASE)


def _npm_tarball(url: object) -> tuple[str, str, str] | None:
    """(name, version, file name) from a registry URL /<name>/-/<base>-<version>.tgz."""
    path = urllib.parse.unquote(urllib.parse.urlparse(str(url)).path)
    name, sep, filename = path.lstrip("/").partition("/-/")
    base = name.rsplit("/", 1)[-1]
    if not (sep and _NPM_NAME.match(name) and _SAFE_FILENAME.match(filename)):
        return None
    if not (filename.startswith(f"{base}-") and filename.endswith(".tgz")):
        return None
    version = filename[len(base) + 1 : -len(".tgz")]
    return (name, version, filename) if version else None


def _sha512_of(value: object) -> str:
    """Hex sha512 from an npm integrity string ("sha512-<base64>", maybe among others)."""
    for part in str(value or "").split():
        algorithm, _, digest = part.partition("-")
        if algorithm == "sha512":
            return _sha512_hex(digest)
    return ""


def _sha512_hex(value: object) -> str:
    """Hex from a base64 sha512 digest; "" if it is not one."""
    try:
        raw = base64.b64decode(str(value or ""), validate=True)
    except (binascii.Error, ValueError):
        return ""
    return raw.hex() if len(raw) == 64 else ""


def _npm_platform() -> tuple[str | None, str | None]:
    """This machine as npm names it (process.platform, process.arch); None if unknown."""
    os_name = next(
        (
            n
            for n in ("linux", "darwin", "win32", "freebsd", "openbsd")
            if sys.platform.startswith(n)
        ),
        None,
    )
    machine = platform.machine().lower()
    cpu = {
        "x86_64": "x64",
        "amd64": "x64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "i386": "ia32",
        "i686": "ia32",
        "x86": "ia32",
        "armv7l": "arm",
    }.get(machine)
    return os_name, cpu


def _npm_allows(values: object, here: str | None) -> bool:
    """npm's os and cpu fields: a "!x" entry excludes x; any plain entry must include here.
    Unknown here or an odd field counts as allowed, so more is checked, not less."""
    if here is None or not isinstance(values, list):
        return True
    names = [str(v) for v in values]
    if f"!{here}" in names:
        return False
    wanted = [v for v in names if not v.startswith("!")]
    return not wanted or here in wanted


NuGetPin = tuple[str, str, str | None]  # (id, version, hex content hash or None if not pinned)


def _check_nuget(
    path: Path, fetch: Fetch, cache_dir: Path | None, progress: Callable[[str], None]
) -> list[Result]:
    """packages.lock.json or packages.config. Each package is fetched from nuget.org.

    A lockfile entry is checked against its contentHash before it is read. Neither
    file says which feed a package came from, so nuget.org is assumed. A
    packages.config entry pins no hash: what nuget.org serves now is scanned.
    """
    data = path.read_bytes()
    if path.name == "packages.lock.json":
        pins, results = _nuget_lock_pins(data)
    else:
        pins, results = _packages_config_pins(data)
    seen: set[tuple[str, str, str | None]] = set()  # ids and versions in any case
    with tempfile.TemporaryDirectory(prefix="buckthorn-") as tmp:
        cache = cache_dir or Path(tmp)
        for package_id, version, sha512 in pins:
            key = (package_id.lower(), (_nuget_version(version) or version).lower(), sha512)
            if key in seen:
                continue  # the same package in another target framework
            seen.add(key)
            normalized = _nuget_version(version)
            # fullmatch: $ in a pattern also matches before a final newline.
            if not (_NUGET_ID.fullmatch(package_id) and len(package_id) <= 100 and normalized):
                label = f"{package_id[:100]} {version[:64]}"
                results.append(_gap(label, "", "not a plain NuGet id and exact version"))
                continue
            label = f"{package_id}.{normalized}.nupkg"
            if sha512 == "":
                message = "no sha512 contentHash, so the package cannot be checked"
                results.append(_gap(label, "", message))
                continue
            filename = label.lower()
            url = f"{_NUGET_FLAT}/{package_id.lower()}/{normalized.lower()}/{filename}"
            progress(label)
            if sha512 is not None:
                results.append(_fetch_and_scan(filename, sha512, url, fetch, cache, "nuget", label))
                continue
            try:
                body = fetch(url, MAX_DOWNLOAD_BYTES)
            except FetchError as exc:
                results.append(_gap(label, "", f"could not fetch: {exc}"))
                continue
            sha256 = hashlib.sha256(body).hexdigest()
            target = cache / sha256 / filename
            _store(target, body)
            message = "packages.config pins no hash: this is what nuget.org serves now"
            note = Finding("BKT-LOCK-004", message, Severity.INFO, url)
            results.append(Result(label, sha256, [*scan_artifact(target), note]))
    return results


def _nuget_lock_pins(data: bytes) -> tuple[list[NuGetPin], list[Result]]:
    """Every package of every target in a packages.lock.json, version 1, 2 or 3.
    Local project references (type Project) are left out: they are not fetched."""
    try:
        lockfile = json.loads(data)
    except RecursionError:
        raise ValueError("JSON nested too deeply to parse") from None
    version = lockfile.get("version") if isinstance(lockfile, dict) else None
    targets: object = None
    if type(version) is int and version in (1, 2):
        targets = lockfile.get("dependencies")
    elif type(version) is int and version == 3:
        targets = {
            k: v.get("dependencies") if isinstance(v, dict) else v
            for k, v in lockfile.items()
            if k != "version"
        }
    if not isinstance(targets, dict):
        message = f"not a packages.lock.json of version 1, 2 or 3 (version {version!r})"
        return [], [_gap("packages.lock.json", "", message)]
    pins: list[NuGetPin] = []
    results: list[Result] = []
    for target, packages in targets.items():
        if not isinstance(packages, dict):
            results.append(_gap(f"packages.lock.json {target}", "", "target is not a map"))
            continue
        for package_id, entry in packages.items():
            if not isinstance(entry, dict):
                results.append(_gap(str(package_id)[:100], "", "lockfile entry is not a map"))
            elif entry.get("type") != "Project":
                resolved = entry.get("resolved")
                version_text = resolved if isinstance(resolved, str) else ""
                pins.append((package_id, version_text, _sha512_hex(entry.get("contentHash"))))
    return pins, results


def _packages_config_pins(data: bytes) -> tuple[list[NuGetPin], list[Result]]:
    """Every <package id version> in a packages.config. It pins no hashes."""
    root, problem = nuget._xml(data, "packages.config")
    if root is not None and root.tag != "packages":
        root, problem = None, "packages.config has no <packages> root"
    if root is None:
        return [], [_gap("packages.config", "", problem)]
    pins: list[NuGetPin] = [
        (element.get("id", ""), element.get("version", ""), None)
        for element in root
        if element.tag == "package"
    ]
    return pins, []


def _nuget_version(version: str) -> str | None:
    """The version as NuGet names the file: build metadata dropped, three numbers
    without leading zeros, a fourth only if it is not 0. None if not exact."""
    match = _NUGET_VERSION.fullmatch(version) if len(version) <= 64 else None
    if not match:
        return None
    numbers = [str(int(n)) for n in match[1].split(".")]
    numbers += ["0"] * (3 - len(numbers))
    if len(numbers) == 4 and numbers[3] == "0":
        numbers.pop()
    return ".".join(numbers) + (match[2] or "")


_SIGNATURE_NAME = b".signature.p7s"
_CENTRAL_HEADER = struct.Struct("<IHHHHHHIIIHHHHHII")  # 46 bytes, as the zip spec lays it out
_END_RECORD = struct.Struct("<IHHHHIIH")  # 22 bytes


def nuget_content_hash(data: bytes) -> str:
    """NuGet's contentHash of a .nupkg, as hex: the sha512 of the file, or for a
    signed package the sha512 of the zip as it was before the signature was
    added. Ported from NuGet.Client's SignedPackageArchiveUtility.GetPackageContentHash.
    ValueError for a file NuGet would refuse.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            signed = _SIGNATURE_NAME.decode() in zf.namelist()
    # NotImplementedError: zipfile on some corrupt headers.
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError) as exc:
        raise ValueError(f"not a zip: {exc}") from exc
    if not signed:
        return hashlib.sha512(data).hexdigest()
    # The end of central directory record: the last signature in the final 64 KB.
    found = data.rfind(b"PK\x05\x06", max(0, len(data) - 22 - 0xFFFF), len(data) - 18)
    if found < 0:
        raise ValueError("no end of central directory record")
    _, _, _, on_disk, total, cd_size, cd_offset, _ = _END_RECORD.unpack_from(data, found)
    if 0xFFFF in (on_disk, total) or 0xFFFFFFFF in (cd_size, cd_offset):
        raise ValueError("a zip64 package, which NuGet does not sign")
    # Each central directory record: [position, local header offset, record size, entry size].
    records: list[list[int]] = []
    signature = -1
    position = cd_offset
    while data[position : position + 4] == b"PK\x01\x02":
        if position + 46 > len(data):
            raise ValueError("central directory runs past the end of the file")
        fields = _CENTRAL_HEADER.unpack_from(data, position)
        flags, name_len, extra_len, comment_len, local = fields[3], *fields[10:13], fields[16]
        name = data[position + 46 : position + 46 + name_len]
        if name == _SIGNATURE_NAME and not flags & 0x800:
            if signature >= 0:
                raise ValueError("more than one package signature file")
            signature = len(records)
        size = 46 + name_len + extra_len + comment_len
        records.append([position, local, size, 0])
        position += size
    if not records or signature < 0:
        raise ValueError("no package signature file in the central directory")
    start_of_entries = min(min(r[1] for r in records), len(data))
    end_of_entries = min(r[0] for r in records)
    by_offset = sorted(records, key=lambda r: r[1])
    for current, following in zip(by_offset, by_offset[1:] + [None], strict=True):
        current[3] = (following[1] if following else end_of_entries) - current[1]
    end_of_directory = records[-1][0] + records[-1][2]
    signature_record = records[signature]
    kept = [r for r in by_offset if r is not signature_record]

    digest = hashlib.sha512(data[:start_of_entries])
    for _, local, _, entry_size in kept:
        digest.update(data[local : local + entry_size])
    # Where each entry moves to once the signature entry is gone.
    shift: dict[int, int] = {}
    previous_end = 0
    for record in kept:
        shift[id(record)] = previous_end - record[1]
        previous_end = record[1] + record[3] + shift[id(record)]
    for record in sorted(kept, key=lambda r: r[0]):
        start, size = record[0], record[2]
        digest.update(data[start : start + 42])
        local = struct.unpack_from("<I", data, start + 42)[0]
        digest.update(struct.pack("<I", (local + shift[id(record)]) & 0xFFFFFFFF))
        digest.update(data[start + 46 : start + size])
    end = end_of_directory
    if data[end : end + 4] != b"PK\x05\x06" or end + 22 > len(data):
        raise ValueError("central directory is not followed by its end record")
    on_disk, total, cd_size, cd_offset = struct.unpack_from("<HHII", data, end + 8)
    digest.update(data[end : end + 8])
    digest.update(struct.pack("<HH", (on_disk - 1) & 0xFFFF, (total - 1) & 0xFFFF))
    digest.update(struct.pack("<I", (cd_size - signature_record[2]) & 0xFFFFFFFF))
    digest.update(struct.pack("<I", (cd_offset - signature_record[3]) & 0xFFFFFFFF))
    digest.update(data[end + 20 :])
    return digest.hexdigest()


def _gap(path: str, sha: str, message: str) -> Result:
    return Result(path, sha, [Finding("BKT-LOCK-002", message, Severity.INFO, path)])


def allowed_url(url: str | None, hosts: frozenset[str] = _ALLOWED_HOSTS) -> bool:
    if not url:
        return False
    parts = urllib.parse.urlparse(url)
    return (
        parts.scheme == "https"
        and parts.hostname in hosts
        and parts.port in (None, 443)
        and not parts.username
        and not parts.password
    )


class _PyPIOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not allowed_url(newurl, _ALLOWED_HOSTS | _NPM_HOSTS | _NUGET_HOSTS):
            raise FetchError(f"redirect to {newurl} refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url: str, max_bytes: int) -> bytes:
    """GET an https URL on PyPI, the npm registry or nuget.org, up to max_bytes.
    FetchError otherwise."""
    if not allowed_url(url, _ALLOWED_HOSTS | _NPM_HOSTS | _NUGET_HOSTS):
        raise FetchError(f"{url} is not on PyPI, the npm registry or nuget.org")
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
