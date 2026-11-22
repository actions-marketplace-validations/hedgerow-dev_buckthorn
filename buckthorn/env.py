"""Scan an installed environment in place: a virtualenv, or a site-packages folder.

Each installed distribution's RECORD is the inventory. Every file in it is
hashed against RECORD, so a file changed after install is caught, and then
read by the same rules as a wheel. Files at the top of site-packages that no
RECORD lists are reported too, since that is where a dropped .pth would sit.
Files are read in place and never imported; links are never followed.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import posixpath
from email.parser import HeaderParser
from pathlib import Path

from buckthorn import scan
from buckthorn.findings import Finding, Result, Severity

_HEAD_BYTES = 64 * 1024  # enough of a native library for the executable checks
_RECORD_HASHES = frozenset({"sha256", "sha384", "sha512"})
UNOWNED = "site-packages (not owned by any package)"


def find_site_packages(root: Path) -> list[Path]:
    """The site-packages folders of a venv, or root itself if it is one. ValueError if neither."""
    found = sorted(root.glob("lib/python*/site-packages")) + sorted(root.glob("Lib/site-packages"))
    if found:
        return found
    if any(root.glob("*.dist-info")):
        return [root]
    raise ValueError(f"{root}: not a virtualenv or a site-packages folder")


def scan_env(root: Path) -> list[Result]:
    results: list[Result] = []
    for site in find_site_packages(root):
        owned: set[str] = set()
        for dist_info in sorted(p for p in site.iterdir() if p.name.endswith(".dist-info")):
            if dist_info.is_dir() and not dist_info.is_symlink():
                result, files = _scan_distribution(site, dist_info)
                results.append(result)
                owned |= files
        unowned = _scan_unowned(site, owned)
        if unowned.findings:
            results.append(unowned)
    return results


def _scan_distribution(site: Path, dist_info: Path) -> tuple[Result, set[str]]:
    """A distribution's Result, and the paths (relative to site-packages) its RECORD claims."""
    label = _label(dist_info)
    record = dist_info / "RECORD"
    if not record.is_file():
        message = "installed without a RECORD, so its files are unknown"
        return Result(label, "", [Finding("BKT-SKIP-005", message, Severity.INFO, label)]), set()
    try:
        rows = list(csv.reader(record.read_text(encoding="utf-8", errors="replace").splitlines()))
    except csv.Error as exc:  # a field past csv's limit
        message = f"RECORD could not be read ({exc}), so its files are unknown"
        return Result(label, "", [Finding("BKT-SKIP-005", message, Severity.INFO, label)]), set()
    owned = set()
    for row in rows:
        relative = posixpath.normpath(row[0]) if row else ".."
        if not relative.startswith(("..", "/")):  # bin/ scripts and the like are outside
            owned.add(relative)
    site_real = site.resolve()
    members: list[tuple[str, bytes]] = []
    findings: list[Finding] = []
    # Noted, but the files RECORD lists are still read: a wheel can ship its own
    # direct_url.json, so the marker alone is no reason to trust a distribution.
    if _is_editable(dist_info):
        message = "editable install: the project's own code outside this environment is not read"
        findings.append(Finding("BKT-ENV-002", message, Severity.INFO, label))
    for row in rows:
        relative = posixpath.normpath(row[0]) if row else ".."
        if relative not in owned:
            continue
        path = site / relative
        if not path.exists() and not path.is_symlink():
            continue  # removed since install, or a .pyc never written
        if path.is_symlink() or not path.resolve().is_relative_to(site_real):
            message = f"{relative} is a link and was not followed"
            findings.append(Finding("BKT-SKIP-004", message, Severity.INFO, relative))
            continue
        if not path.is_file():
            continue
        algorithm, _, expected = (row[1] if len(row) > 1 else "").partition("=")
        whole = relative.endswith((".py", ".pth")) or relative.startswith(f"{dist_info.name}/")
        try:
            data, digest = _read(
                path, algorithm, scan.MAX_MEMBER_BYTES + 1 if whole else _HEAD_BYTES
            )
        except OSError as exc:
            message = f"could not read: {exc}"
            findings.append(Finding("BKT-SKIP-001", message, Severity.INFO, relative))
            continue
        if algorithm in _RECORD_HASHES and digest != expected:
            message = "file has changed since it was installed (does not match RECORD)"
            findings.append(Finding("BKT-REC-001", message, Severity.HIGH, relative))
        if whole and len(data) > scan.MAX_MEMBER_BYTES:
            message = f"{relative} is over {scan.MAX_MEMBER_BYTES} bytes, not read"
            findings.append(Finding("BKT-SKIP-002", message, Severity.INFO, relative))
            continue
        members.append((relative, data))
    findings.extend(scan.check_members(members, _is_pure(dist_info)))
    return Result(label, "", findings), owned


def _read(path: Path, algorithm: str, keep: int) -> tuple[bytes, str]:
    """The first `keep` bytes, and the RECORD-style digest of the whole file, streamed."""
    digest = hashlib.new(algorithm if algorithm in _RECORD_HASHES else "sha256")
    kept = bytearray()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
            if len(kept) < keep:
                kept += chunk[: keep - len(kept)]
    return bytes(kept), base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode()


def _scan_unowned(site: Path, owned: set[str]) -> Result:
    """Top-level files and folders no RECORD lists. Files are read; folders are only named."""
    owned_top = {path.split("/")[0] for path in owned}
    findings: list[Finding] = []
    members: list[tuple[str, bytes]] = []
    for entry in sorted(site.iterdir()):
        name = entry.name
        if name in owned_top or name == "__pycache__":
            continue
        if entry.is_symlink():
            message = f"{name} is a link and was not followed"
            findings.append(Finding("BKT-SKIP-004", message, Severity.INFO, name))
            continue
        if entry.is_dir():
            message = "folder not owned by any installed package (not read)"
            findings.append(Finding("BKT-ENV-001", message, Severity.INFO, name))
            continue
        if not entry.is_file():  # a FIFO or device: opening it could block
            message = f"{name} is not a regular file, not read"
            findings.append(Finding("BKT-SKIP-001", message, Severity.INFO, name))
            continue
        try:
            data, _ = _read(entry, "sha256", scan.MAX_MEMBER_BYTES + 1)
        except OSError as exc:
            findings.append(Finding("BKT-SKIP-001", f"could not read: {exc}", Severity.INFO, name))
            continue
        if len(data) > scan.MAX_MEMBER_BYTES:
            message = f"{name} is over {scan.MAX_MEMBER_BYTES} bytes, not read"
            findings.append(Finding("BKT-SKIP-002", message, Severity.INFO, name))
            continue
        # The virtualenv tool seeds this pair into every venv. Expected only while the
        # .pth is exactly its one line; _virtualenv.py is still read by the rules.
        if name == "_virtualenv.pth" and data.strip() == b"import _virtualenv":
            continue
        if name != "_virtualenv.py":
            message = "file not owned by any installed package"
            findings.append(Finding("BKT-ENV-001", message, Severity.INFO, name))
        members.append((name, data))
    findings.extend(scan.check_members(members, pure=False))
    return Result(UNOWNED, "", findings)


def _label(dist_info: Path) -> str:
    try:
        text = (dist_info / "METADATA").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return dist_info.name
    headers = HeaderParser().parsestr(text)
    name, version = headers.get("Name"), headers.get("Version")
    return f"{name}=={version}" if name and version else dist_info.name


def _is_editable(dist_info: Path) -> bool:
    try:
        data = json.loads((dist_info / "direct_url.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool(isinstance(data, dict) and data.get("dir_info", {}).get("editable"))


def _is_pure(dist_info: Path) -> bool:
    try:
        text = (dist_info / "WHEEL").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    tags = HeaderParser().parsestr(text).get_all("Tag") or []
    return bool(tags) and all(tag.strip().endswith("-none-any") for tag in tags)
