"""VS Code extensions (.vsix, from the Marketplace or Open VSX, which Cursor
and Windsurf use): the JavaScript the editor runs on its own.

VS Code unpacks extension/ and runs no install script. It loads the main
(or, in a browser, the browser) entry when the extension activates and calls
its activate and deactivate exports, and it runs scripts["vscode:uninstall"]
with node when the extension is removed. Those files, and the local files
they load, are read with the npm reader (npm._Package). Read from members
already in memory (see scan.read_archive), never run.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

from buckthorn import npm
from buckthorn.findings import Finding, Severity

_TOP = "extension"
_MANIFEST = f"{_TOP}/package.json"
_CALLED = ("activate", "deactivate")
_NAMES_ACTIVATE = re.compile(rb"\bactivate\b")
# Characters no editor draws: variation selectors, tag characters and zero-width
# marks. GlassWorm hid its payload in thousands of them; an emoji or a joined
# emoji sequence uses one or two at a time.
_INVISIBLE_RUN = re.compile(
    "[\ufe00-\ufe0f\U000e0100-\U000e01ef\U000e0000-\U000e007f\u200b-\u200d\u2060-\u2064]{16,}"
)


def scan_vsix(members: list[tuple[str, bytes]], read: list[Finding]) -> list[Finding]:
    """Findings for a .vsix; read holds the coverage findings from reading it."""
    # Paths as unzipped: extension/./a and extension\\a are extension/a.
    files = {}
    for name, data in members:
        top, sep, rest = posixpath.normpath(name.replace("\\", "/")).partition("/")
        if top == _TOP and sep:
            files[rest] = data
    findings = list(read)
    manifest, problem = (
        npm._load(files["package.json"]) if "package.json" in files else (None, "no package.json")
    )
    if manifest is None:
        message = "extension/package.json is missing or unreadable, so what runs is unknown"
        return findings + [
            Finding("BKT-SKIP-003", problem, Severity.INFO, _MANIFEST),
            Finding("BKT-VSX-META-001", message, Severity.MEDIUM, _MANIFEST),
        ]
    findings += _dependencies(manifest)
    package = npm._Package(files, dict.fromkeys(files, _TOP), manifest)
    _uninstall(package, manifest)
    how = "called by VS Code when the extension activates"
    roots: dict[str, tuple[bool, dict[str, str]]] = {}
    for field in ("main", "browser"):
        entry = manifest.get(field)
        if isinstance(entry, str) and entry.strip():
            path = package._file(package._local("", entry))
            if path is None:
                package.note(f"the {field} entry is not in the extension: not read", "package.json")
            elif path.endswith(".node"):
                package.note(f"the {field} entry is a native addon: not read", path)
            elif not path.endswith(".json"):
                roots[path] = (False, dict.fromkeys(_CALLED, how))
    package._read(roots, "ACTIVATE", set(package.read))
    for path in roots:
        _, analysis = package.read.get(path, ("", None))
        # An entry that names activate but gives no function for it the reader
        # can find: what activation runs is not read. One that never names it
        # has none, and VS Code only loads it.
        if analysis and "activate" in analysis.unfound and _NAMES_ACTIVATE.search(files[path]):
            package.note("activate() is not found in the entry, so what it runs is not read", path)
    for path in package.read:
        text = files[path].decode("utf-8", "replace")
        if match := _INVISIBLE_RUN.search(text):
            line = text.count("\n", 0, match.start()) + 1
            message = f"holds {len(match.group(0))} characters in a row no editor shows"
            where = {"lines": [line]}
            findings.append(
                Finding("BKT-VSX-HIDE-001", message, Severity.HIGH, package.at(path), where)
            )
    return findings + package.findings()


def _dependencies(manifest: dict[str, Any]) -> list[Finding]:
    """BKT-VSX-DEPS-001: the extensions VS Code installs along with this one."""
    names = []
    for field in ("extensionDependencies", "extensionPack"):
        value = manifest.get(field)
        if isinstance(value, list):
            names += [str(n)[:100] for n in value]
    if not names:
        return []
    message = f"installs other extensions too, not read here: {', '.join(names[:20])}"
    return [Finding("BKT-VSX-DEPS-001", message, Severity.INFO, _MANIFEST)]


def _uninstall(package: npm._Package, manifest: dict[str, Any]) -> None:
    """BKT-VSX-SCRIPT-001 for a vscode:uninstall script, and its code read
    whole. No other script runs on a user's machine: vscode:prepublish runs
    when the publisher packs the extension."""
    scripts = manifest.get("scripts")
    command = scripts.get("vscode:uninstall") if isinstance(scripts, dict) else None
    if not isinstance(command, str) or not command.strip():
        return
    message = "vscode:uninstall script runs when the extension is removed"
    package.found.append(Finding("BKT-VSX-SCRIPT-001", message, Severity.MEDIUM, _MANIFEST))
    roots: dict[str, tuple[bool, dict[str, str]]] = {}
    for kind, value, _ in package._runs({}, command, set()):
        if kind == "file":
            roots[value] = (True, {})
        else:  # VS Code forks node on a file; inline code does not run
            package.note(f"vscode:uninstall script runs {value}, which is not read", "package.json")
    package._read(roots, "UNINSTALL", set())
