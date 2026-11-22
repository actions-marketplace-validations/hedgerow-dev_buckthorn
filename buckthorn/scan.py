"""Read a package archive in memory and run the rules over it.

Nothing is extracted to disk, installed, imported or run. Member names are
only ever used as dictionary keys, never joined onto a path.
"""

from __future__ import annotations

import ast
import base64
import configparser
import csv
import hashlib
import itertools
import lzma
import os
import posixpath
import re
import struct
import tarfile
import tomllib
import zipfile
import zlib
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from email.parser import HeaderParser
from functools import partial
from keyword import iskeyword
from pathlib import Path
from typing import IO

from buckthorn import npm
from buckthorn.code import (
    _LEGACY_COMMANDS,
    Hit,
    Unit,
    analyse,
    call_units,
    command_code,
    import_calls,
    imported_functions,
    imported_modules,
    may_import_any,
    not_run_by_pip,
    reaches_setup_py,
)
from buckthorn.findings import Finding, Severity

MAX_MEMBERS = 50_000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SOURCE_BYTES = 5 * 1024 * 1024  # one Python file parsed with ast
# Source re-read following calls between modules, as a multiple of all of it.
# Real packages stay well under it.
_FOLLOW_BUDGET = 10
# Code that runs only when called (functions nothing runs at import, tests,
# scripts) is read too, and flagged only for a payload-shaped combination
# (BKT-CALL-*). Off unless BUCKTHORN_CALL_TIME=1.
CALL_TIME = os.environ.get("BUCKTHORN_CALL_TIME") == "1"


def _is_python(name: str, data: bytes) -> bool:
    """A .py file, or a script whose #! line runs Python (setup(scripts=...), .data/scripts)."""
    return name.endswith(".py") or (data[:2] == b"#!" and b"python" in data.split(b"\n", 1)[0])


_ZIP_SUFFIXES = (".whl", ".zip")
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")
ARTIFACT_SUFFIXES = _ZIP_SUFFIXES + _TAR_SUFFIXES


def read_archive(path: Path) -> tuple[list[tuple[str, bytes]], list[Finding]]:
    """Return (member name, bytes) pairs plus any coverage-gap findings.

    A list, not a dict: an archive can hold the same name twice, and every
    copy has to be checked.

    On a limit hit, the members read so far are returned with a BKT-SKIP-002,
    so rules still run on them but the verdict can never be clean.
    """
    name = path.name.lower()
    try:
        if name.endswith(_ZIP_SUFFIXES):
            with zipfile.ZipFile(path) as zf:
                files = [i for i in zf.infolist() if not i.is_dir()]
                # On Windows zipfile turns \ into / in .filename; pip on Linux keeps it.
                # orig_filename is the raw name, cut at a NUL as .filename is.
                named = ((i.orig_filename.split("\0")[0], partial(zf.open, i)) for i in files)
                return _read_members(path, named)
        if name.endswith(_TAR_SUFFIXES):
            with tarfile.open(path, "r:*") as tf:
                return _read_members(path, _tar_entries(tf))
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        EOFError,
        zlib.error,
        lzma.LZMAError,
        NotImplementedError,
        RuntimeError,
        OSError,
    ) as exc:
        message = f"could not open archive: {exc}"
        return [], [Finding("BKT-SKIP-001", message, Severity.INFO, str(path))]
    message = "not a wheel or sdist file name"
    return [], [Finding("BKT-SKIP-001", message, Severity.INFO, str(path))]


# Opens one archive member; None for a link, which is never followed.
Opener = Callable[[], "IO[bytes] | None"]


def _tar_entries(tf: tarfile.TarFile) -> Iterator[tuple[str, Opener | None]]:
    # Lazily, and every header counts against the member cap: a small compressed
    # tar can hold millions of directory entries.
    for info in tf:
        if info.isfile():
            yield info.name, partial(tf.extractfile, info)
        elif info.issym() or info.islnk():
            yield info.name, lambda: None
        else:
            yield info.name, None  # a directory or device: counted, not read


def _read_members(
    path: Path, entries: Iterable[tuple[str, Opener | None]]
) -> tuple[list[tuple[str, bytes]], list[Finding]]:
    members: list[tuple[str, bytes]] = []
    findings: list[Finding] = []
    total = 0
    for count, (name, open_member) in enumerate(entries, 1):
        if count > MAX_MEMBERS:
            return members, findings + [_limit(path, f"more than {MAX_MEMBERS} members")]
        if open_member is None:
            continue
        fh = open_member()
        if fh is None:
            # A link. Never followed; whatever it points at was not read.
            message = f"{name} is a link and was not followed"
            findings.append(Finding("BKT-SKIP-004", message, Severity.INFO, name))
            continue
        with fh:
            data = fh.read(MAX_MEMBER_BYTES + 1)
        if len(data) > MAX_MEMBER_BYTES:
            return members, findings + [_limit(path, f"{name} is over {MAX_MEMBER_BYTES} bytes")]
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            return members, findings + [_limit(path, f"archive is over {MAX_TOTAL_BYTES} bytes")]
        members.append((name, data))
    return members, findings


def _limit(path: Path, detail: str) -> Finding:
    return Finding("BKT-SKIP-002", f"archive limit hit: {detail}", Severity.INFO, str(path))


def scan_wheel(path: Path) -> list[Finding]:
    members, findings = read_archive(path)
    if not findings:  # integrity needs every member; a cut-short read is already not_verified
        findings.extend(_check_integrity(path.name, members))
    version = split_artifact_name(path.name)[1]
    findings.extend(check_members(members, _is_pure_wheel(path.name), version))
    return findings


def check_members(members: list[tuple[str, bytes]], pure: bool, version: str = "") -> list[Finding]:
    """The per-file rules, for wheel members or files installed in site-packages.

    Names are wheel member names, which for installed files are their paths
    relative to site-packages. version, when known, is left out of line hashes.
    """
    names = {name for name, _ in members}
    modules, quiet = _modules_and_quiet_tests(members)
    called, findings = _calls_between(modules, quiet)
    for name, data in members:
        findings.extend(_check_scripts(name, data))
        findings.extend(_check_binary(name, data, pure))
        installed = _site_packages_path(name)
        if installed is None:
            if CALL_TIME and _is_python(name, data):
                findings.extend(_call_findings(name, data, whole_file=True))
            continue
        if "/" not in installed and installed.endswith(".pth"):
            findings.extend(_check_pth(name, data))
        if installed.split("/")[0].split(".")[0] in _STARTUP_MODULES:
            message = f"ships {installed}, which Python imports at every start"
            findings.append(Finding("BKT-START-001", message, Severity.HIGH, name))
        if installed.endswith(".py"):
            entry = called.get(name, {})
            found = _code_findings("IMPORT", name, data, True, entry=entry, version=version)
            findings.extend(found[0])
            if CALL_TIME:
                findings.extend(_call_findings(name, data, entry, whole_file=name in quiet))
        elif installed.endswith(".pyc"):
            findings.extend(_check_pyc(name, data, names))
    # What test files do at import is info: `import pkg` never runs them.
    _quieten(findings, quiet)
    return findings


def _quieten(findings: list[Finding], quiet: Collection[str]) -> None:
    """Import findings in quiet files become info: nothing that runs imports them."""
    for finding in findings:
        if finding.file_path in quiet and finding.rule_id.startswith("BKT-IMPORT-"):
            finding.severity = Severity.INFO
            installed = _site_packages_path(finding.file_path) or finding.file_path
            if _vendored(installed):
                finding.message += (
                    " (in a folder no import statement can name, and nothing imports it)"
                )
            else:
                finding.message += " (in a test file nothing outside the tests imports)"


_TEST_FOLDERS = frozenset({"test", "tests", "_tests", "testing"})


def _is_test_file(installed: str) -> bool:
    top, *rest = installed.split("/")
    if not rest:
        return False  # a top-level module is what the user imports, whatever its name
    *folders, file = rest
    return (
        top in {"test", "tests", "_tests"}  # a top-level testing/ can be a real package
        or any(folder in _TEST_FOLDERS for folder in folders)
        or file == "conftest.py"
        or file.startswith("test_")
        or file.endswith("_test.py")
    )


def _vendored(path: str) -> bool:
    """Whether a file (its path from the package root) sits under a folder below
    the top-level name that no import statement can name: not an identifier, or
    a keyword (node_modules/npm/node_modules/node-gyp/...). Only importlib or a
    path can load what is under it. A top-level name or a module's own file
    name is how a distribution names its own code (malicious uploads often use
    dify-api/__init__.py), so those still count."""
    return any(not part.isidentifier() or iskeyword(part) for part in path.split("/")[1:-1])


def _modules_and_quiet_tests(
    members: list[tuple[str, bytes]],
) -> tuple[dict[str, list[tuple[str, bytes]]], set[str]]:
    """The .py files installed to site-packages by dotted module name, and the
    files among them that nothing that runs imports: test files, and modules
    no import statement can name (see _quiet_files).
    """
    modules: dict[str, list[tuple[str, bytes]]] = {}  # dotted name -> files with it
    tests = set()
    entry_points = set()  # a pytest11 plugin, say, runs in every project's tests
    for name, data in members:
        if name.endswith(".dist-info/entry_points.txt"):
            text = data.decode("utf-8", "replace")
            entry_points.update(re.findall(r"=\s*([\w.]+)", text))
        installed = _site_packages_path(name)
        if installed and installed.endswith(".py"):
            dotted = installed[: -len(".py")].replace("/", ".").removesuffix(".__init__")
            modules.setdefault(dotted, []).append((name, data))
            if _is_test_file(installed) or _vendored(installed):
                tests.add(dotted)
    if not tests or any("\\" in name for name, _ in members):
        return modules, set()  # pip on Windows reads a backslash as a folder separator
    # importing an entry point's module runs its parent packages too
    reached = {t for t in tests for e in entry_points if e == t or e.startswith(t + ".")}
    return modules, _quiet_files(modules, tests, reached)


def _quiet_files(
    modules: dict[str, list[tuple[str, bytes]]], quiet: set[str], reached: set[str]
) -> set[str]:
    """Files of the modules in quiet that nothing that runs imports.

    One runs when a module that does run imports it, directly, relatively,
    through other quiet modules or by name (importlib, a path). reached: those
    already known to run. Nothing is quiet when a module cannot be read.
    """
    reached = set(reached)
    todo = [m for m in modules if m not in quiet] + list(reached)
    seen: set[str] = set()  # every name the modules that run import, for may_import_any
    while todo:
        module = todo.pop()
        imported = set()
        for name, data in modules[module]:
            if len(data) > MAX_SOURCE_BYTES:
                return set()  # a module we cannot read may import any of them
            try:
                imported |= imported_modules(data, _package_of(module, name))
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                return set()
        seen |= imported
        if may_import_any(seen):
            return set()  # imports by a computed name, so it may run any of them
        found = _named(quiet - reached, imported)
        reached |= found
        todo.extend(found)
    return {name for m in quiet - reached for name, _ in modules[m]}


def _named(modules: Collection[str], imported: Collection[str]) -> set[str]:
    """The modules that imported names name, in full or by their last part."""
    return {m for m in modules if m in imported or m.rpartition(".")[2] in imported}


def _package_of(module: str, name: str) -> str:
    """The package a file's relative imports resolve against: its own if it is one."""
    return module if posixpath.basename(name) == "__init__.py" else module.rpartition(".")[0]


def _calls_between(
    modules: dict[str, list[tuple[str, bytes]]],
    quiet: Collection[str] = (),
    seed: Mapping[str, Mapping[str, str]] = {},
) -> tuple[dict[str, dict[str, str]], list[Finding]]:
    """Functions each file defines that another file of the same artifact calls
    at import, each with the file whose module-level code starts the calls:
    {file: {function: "called at import by pkg/__init__.py"}}. Seed adds
    functions called from outside (install code), followed the same way.

    Followed to a fixed point, since a function reached this way may call
    another module's function in turn, re-reading a file each time it gains
    functions. Files that cannot be parsed call nothing here (they are
    reported as not parsed), and nor do quiet ones or __main__.py, which only
    `python -m` runs, like an `if __name__ == "__main__":` block.

    Also returns a BKT-SKIP-003 if following would re-read too much (a
    package built to make the scan slow): what was found so far is kept.
    """
    called = {name: dict(functions) for name, functions in seed.items()}
    budget = _FOLLOW_BUDGET * sum(len(data) for files in modules.values() for _, data in files)
    todo = dict.fromkeys(modules)  # an ordered set: a module waits once
    while todo:
        module, _ = todo.popitem()
        for name, data in modules[module]:
            script = posixpath.basename(name) == "__main__.py"
            if name in quiet or script or len(data) > MAX_SOURCE_BYTES:
                continue
            budget -= len(data)
            if budget < 0:
                message = "too many calls between modules to follow them all"
                return called, [Finding("BKT-SKIP-003", message, Severity.INFO, name)]
            package, how = _package_of(module, name), f"called at import by {name}"
            try:
                calls = import_calls(data, package, called.get(name, {}), how)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
            for target, functions in calls.items():
                for target_name, _ in modules.get(target, []):
                    known = called.setdefault(target_name, {})
                    new = {f: h for f, h in functions.items() if f not in known}
                    if new:
                        known.update(new)
                        todo[target] = None
    return called, []


def _check_pyc(name: str, data: bytes, names: set[str]) -> list[Finding]:
    """BKT-HIDE-003 for bytecode with no source; BKT-HIDE-004 for a pyc that ignores its source."""
    if "/__pycache__/" not in f"/{name}":
        if name[:-1] not in names:
            message = "bytecode with no source: the module cannot be read"
            return [Finding("BKT-HIDE-003", message, Severity.MEDIUM, name)]
        return []
    # PEP 552: flags word after the magic. Hash-based (bit 0) with check_source
    # (bit 1) off means Python runs this file without comparing it to the .py.
    flags = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
    if flags & 0b01 and not flags & 0b10:
        message = "unchecked hash-based .pyc: Python runs it instead of the source beside it"
        return [Finding("BKT-HIDE-004", message, Severity.HIGH, name)]
    return []


# Words in an executed .pth line that mean it reaches into the interpreter
# itself: swapping modules or builtins, or installing an import hook (the
# ShadowPickle "overwritten module" shape).
_INTERPRETER_HOOKS = ("sys.modules", "builtins", "meta_path", "path_hooks")

# Modules the site module imports at start-up if they are anywhere on sys.path.
_STARTUP_MODULES = frozenset({"sitecustomize", "usercustomize"})


def _site_packages_path(name: str) -> str | None:
    """Where a wheel member lands relative to site-packages, or None if elsewhere."""
    # Installers resolve ./ and ../, so judge where the file lands, not how it is spelled.
    parts = posixpath.normpath(name).split("/")
    # pkg-1.0.data/purelib/... and .../platlib/... install to site-packages. The
    # data scheme installs under sys.prefix, so data/lib/pythonX.Y/site-packages/...
    # (or data/Lib/site-packages/... on Windows) lands there too in a venv.
    if parts[0].endswith(".data"):
        if len(parts) >= 3 and parts[1] in ("purelib", "platlib"):
            return "/".join(parts[2:])
        rest = parts[2:] if len(parts) >= 3 and parts[1] == "data" else []
        if (
            len(rest) > 3
            and rest[0] == "lib"
            and rest[1].startswith("python")
            and rest[2] == "site-packages"
        ):
            return "/".join(rest[3:])
        if len(rest) > 2 and rest[0] == "Lib" and rest[1] == "site-packages":
            return "/".join(rest[2:])
        return None
    return "/".join(parts)


def _check_pth(name: str, data: bytes) -> list[Finding]:
    # Mirrors site.addpackage: only lines starting "import " or "import\t" run.
    findings = []
    for lineno, line in enumerate(data.decode("utf-8-sig", errors="replace").splitlines(), 1):
        if not line.startswith(("import ", "import\t")):
            continue
        hooks = [word for word in _INTERPRETER_HOOKS if word in line]
        if hooks:
            findings.append(
                Finding(
                    "BKT-PTH-002",
                    f".pth line runs at every Python start and touches {', '.join(hooks)}",
                    Severity.HIGH,
                    name,
                    {"line": lineno},
                )
            )
        else:
            findings.append(
                Finding(
                    "BKT-PTH-001",
                    ".pth line runs code at every Python start",
                    Severity.MEDIUM,
                    name,
                    {"line": lineno},
                )
            )
    return findings


# Commands a console script must not quietly take over. Version suffixes and
# .exe are stripped before comparing, so python3.12 and pip.exe count.
_SHADOWED_COMMANDS = frozenset({"python", "pip", "git", "ssh"})


def _check_scripts(name: str, data: bytes) -> list[Finding]:
    """BKT-SCRIPT-001 for entry points and .data/scripts files named like a common command."""
    parts = posixpath.normpath(name).split("/")
    commands: list[str] = []
    if len(parts) == 3 and parts[0].endswith(".data") and parts[1] == "scripts":
        commands.append(parts[2])
    elif len(parts) == 2 and parts[0].endswith(".dist-info") and parts[1] == "entry_points.txt":
        parser = configparser.ConfigParser(delimiters=("=",), interpolation=None)
        parser.optionxform = str  # type: ignore[assignment,method-assign]
        try:
            parser.read_string(data.decode("utf-8", errors="replace"))
        except configparser.Error as exc:
            message = f"could not parse entry points: {exc}"
            return [Finding("BKT-SKIP-003", message, Severity.INFO, name)]
        for section in ("console_scripts", "gui_scripts"):
            if parser.has_section(section):
                commands.extend(parser.options(section))
    else:
        return []
    # A distribution may install its own command: pip ships pip and pip3.
    dist = parts[0].split("-")[0].lower().replace("_", "-")
    findings = []
    for command in commands:
        base = re.sub(r"[0-9.]+$", "", command.lower().removesuffix(".exe"))
        if base in _SHADOWED_COMMANDS and base != dist:
            message = f"installs a command named {command!r}, shadowing {base}"
            findings.append(Finding("BKT-SCRIPT-001", message, Severity.HIGH, name))
    return findings


_NATIVE_NAME = re.compile(r"\.(so|pyd|dll|dylib)(\.[0-9]+)*$", re.IGNORECASE)

# Suffixes that say "source, text or image". An executable named like this is
# hiding. Bundled tools with no suffix (an ffmpeg binary) are left alone.
_DATA_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".pth",
        ".txt",
        ".md",
        ".rst",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".cfg",
        ".ini",
        ".csv",
        ".html",
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".svg",
    }
)


def _is_pure_wheel(filename: str) -> bool:
    """True for a wheel tagged abi "none", platform "any" (name-ver[-build]-py-abi-plat.whl)."""
    tags = filename.removesuffix(".whl").split("-")
    return len(tags) >= 5 and tags[-2] == "none" and tags[-1] == "any"


def _executable_kind(data: bytes) -> str | None:
    """ELF, Mach-O or PE when the header says so; checks the start of the file only."""
    head = data[:4]
    if head == b"\x7fELF":
        return "ELF"
    if head in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    # A universal binary shares 0xCAFEBABE with Java class files; there the next
    # word is the class version (45 or more), here the architecture count.
    if head in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and len(data) >= 8:
        (count,) = struct.unpack_from(">I", data, 4)
        if 0 < count < 20:
            return "Mach-O"
    if data[:2] == b"MZ" and len(data) >= 0x40:
        (offset,) = struct.unpack_from("<I", data, 0x3C)
        if data[offset : offset + 4] == b"PE\x00\x00":
            return "PE"
    return None


def _check_binary(name: str, data: bytes, pure: bool, where: str = "") -> list[Finding]:
    """pure: native code is not expected here, where says why (a pure wheel, an sdist)."""
    where = where or "a wheel tagged pure Python"
    kind = _executable_kind(data)
    if kind and posixpath.splitext(name)[1].lower() in _DATA_SUFFIXES:
        message = f"{kind} executable named like a data or source file"
        return [Finding("BKT-BIN-002", message, Severity.HIGH, name)]
    if pure and _NATIVE_NAME.search(name):
        message = f"native library in {where}"
        return [Finding("BKT-BIN-001", message, Severity.MEDIUM, name)]
    if pure and kind:
        # Shown, not flagged: pip and setuptools ship Windows launchers this way.
        message = f"{kind} executable in {where}"
        return [Finding("BKT-BIN-003", message, Severity.INFO, name)]
    return []


_RECORD_HASHES = frozenset({"sha256", "sha384", "sha512"})  # the wheel spec bars md5 and sha1


def _normalise_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _check_metadata(
    metadata_name: str, files: dict[str, bytes], dist: str, version: str
) -> list[Finding]:
    """BKT-META-001 when METADATA or PKG-INFO is missing or names another package or version."""
    if metadata_name not in files:
        return [Finding("BKT-META-001", "no metadata file", Severity.MEDIUM, metadata_name)]
    headers = HeaderParser().parsestr(files[metadata_name].decode("utf-8", errors="replace"))
    name, meta_version = headers.get("Name", ""), headers.get("Version", "")
    if _normalise_name(name) != _normalise_name(dist) or meta_version != version:
        message = f"metadata says {name} {meta_version}, file name says {dist} {version}"
        return [Finding("BKT-META-001", message, Severity.MEDIUM, metadata_name)]
    return []


def _check_integrity(filename: str, members: list[tuple[str, bytes]]) -> list[Finding]:
    """BKT-META-001 for metadata that disagrees with the file name, BKT-REC-* for RECORD."""
    tags = filename.removesuffix(".whl").split("-")
    dist, version = (tags[0], tags[1]) if len(tags) >= 5 else ("", "")
    dist_infos = sorted(
        {n.split("/")[0] for n, _ in members if n.split("/")[0].endswith(".dist-info")}
    )
    if len(dist_infos) != 1:
        message = f"expected one .dist-info folder, found {len(dist_infos)}"
        return [Finding("BKT-META-001", message, Severity.MEDIUM, filename)]
    dist_info = dist_infos[0]
    files = dict(members)  # for metadata files, the last copy is the one an installer keeps
    findings = []

    findings.extend(_check_metadata(f"{dist_info}/METADATA", files, dist, version))

    record_name = f"{dist_info}/RECORD"
    if record_name not in files:
        findings.append(Finding("BKT-REC-002", "wheel has no RECORD", Severity.MEDIUM, record_name))
        return findings
    record: dict[str, str] = {}
    try:
        for row in csv.reader(files[record_name].decode("utf-8", errors="replace").splitlines()):
            if len(row) >= 2:
                record[row[0]] = row[1]
    except csv.Error as exc:  # a field past csv's limit: pip cannot read it either
        message = f"RECORD could not be read: {exc}"
        findings.append(Finding("BKT-REC-002", message, Severity.MEDIUM, record_name))
        return findings
    unsigned = {record_name, f"{dist_info}/RECORD.jws", f"{dist_info}/RECORD.p7s"}
    for name, data in members:
        if name in unsigned:
            continue
        algorithm, _, expected = record.get(name, "").partition("=")
        if algorithm not in _RECORD_HASHES:
            message = "file is not covered by a sha256 or stronger hash in RECORD"
            findings.append(Finding("BKT-REC-002", message, Severity.MEDIUM, name))
            continue
        digest = hashlib.new(algorithm, data).digest()
        if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != expected:
            message = "file does not match its RECORD hash"
            findings.append(Finding("BKT-REC-001", message, Severity.HIGH, name))
    return findings


def scan_artifact(path: Path) -> list[Finding]:
    """A wheel by its name; a tar is an npm tarball or an sdist by what it holds."""
    if path.name.lower().endswith(".whl"):
        return scan_wheel(path)
    members, findings = read_archive(path)
    name = path.name.lower()
    shape = npm.shape(members, name.endswith(".tgz")) if name.endswith(_TAR_SUFFIXES) else "sdist"
    if shape == "sdist":
        return scan_sdist(path, (members, findings))
    # Members past a limit, or past where tarfile stops and npm reads on, are unseen.
    cut_short = any(f.rule_id == "BKT-SKIP-002" for f in findings) or _npm_reads_on(path)
    if shape == "npm" and not cut_short:
        return npm.scan_npm(_sdist_stem(path.name), members, findings)
    # Read it both ways, so neither reading hides what the other finds.
    message = (
        "holds an npm package.json, but npm and pip would read it differently (Python "
        "build files beside it, members npm would drop or merge, or a cut-short read, "
        "including entries past the tar's end that npm reads): read both ways"
    )
    gap = Finding("BKT-SKIP-001", message, Severity.INFO, str(path))
    stem = _sdist_stem(path.name)
    return scan_sdist(path, (members, findings)) + npm.scan_npm(stem, members, []) + [gap]


def _npm_reads_on(path: Path) -> bool:
    """True when a tar has entries past a zero block or a bad header. tarfile
    (and so pip) stops there without an error; npm's tar reader skips them and
    reads on, so npm installs entries this scan never saw."""
    try:
        with tarfile.open(path, "r:*") as tf:
            seen = sum(1 for _ in itertools.islice(tf, MAX_MEMBERS + 1))
        with tarfile.open(path, "r:*", ignore_zeros=True) as tf:
            return next(itertools.islice(tf, seen, None), None) is not None
    except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError):
        return True  # cannot tell: treat as unseen


def split_artifact_name(filename: str) -> tuple[str, str]:
    """(distribution, version) from a wheel or sdist file name, as written in it."""
    if filename.lower().endswith(".whl"):
        tags = filename[:-4].split("-")
        return (tags[0], tags[1]) if len(tags) >= 5 else ("", "")
    stem = _sdist_stem(filename)
    # An npm version can hold a dash (1.3.0-beta.1), so split before the last
    # semver that fits: a package named lodash-4.17.21 is not lodash.
    npm_split = re.fullmatch(r"(.+)-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)", stem)
    if filename.lower().endswith(".tgz") and npm_split:
        return npm_split[1], npm_split[2]
    dist, _, version = stem.rpartition("-")
    return dist, version


def _sdist_stem(filename: str) -> str:
    for suffix in _TAR_SUFFIXES + (".zip",):
        if filename.lower().endswith(suffix):
            return filename[: -len(suffix)]
    return filename


_BUILD_FILES = frozenset({"setup.py", "setup.cfg", "pyproject.toml"})


def scan_sdist(
    path: Path, read: tuple[list[tuple[str, bytes]], list[Finding]] | None = None
) -> list[Finding]:
    """Install-time code in an sdist, and PKG-INFO.

    setup.py and an in-tree build backend are read whole. Other modules beside
    them (which setup.py or the backend may import) are read top-level only, and
    so are local modules they import, plus the functions they call from them.
    The modules of the sdist's packages are read as import-time code. read is
    read_archive's result, when the caller already has it.
    """
    members, findings = read if read is not None else read_archive(path)
    complete = not findings
    # Names as an unpacker sees them: ./ and ../ resolved, a leading / dropped
    # (tarfile's data filter, which pip uses), \ a folder separator as pip splits
    # the top folder there, and one top folder stripped only when every file sits
    # in it (pip's rule). Last copy wins.
    files: dict[str, bytes] = {}
    raw: dict[str, str] = {}
    for name, data in members:
        unpacked = posixpath.normpath(name.replace("\\", "/").lstrip("/"))
        if "\\" in name:
            # A folder separator on Windows, part of a file name elsewhere: where
            # pip puts the file, and so which setup.py runs, depends on the system.
            message = f"{name}: a backslash in a member name unpacks differently by system"
            findings.append(Finding("BKT-SKIP-001", message, Severity.INFO, unpacked))
        elif raw.setdefault(unpacked, name) != name:
            message = f"{name} and {raw[unpacked]} unpack to the same file"
            findings.append(Finding("BKT-SKIP-001", message, Severity.INFO, unpacked))
        files[unpacked] = data
    tops = {name.split("/")[0] for name in files}
    top = tops.pop() if len(tops) == 1 and all("/" in name for name in files) else ""

    def at(relative: str) -> str:
        return posixpath.normpath(f"{top}/{relative}" if top else relative)

    # On a case-insensitive disk (macOS, Windows) Setup.py is setup.py, and pip runs
    # it. Windows also drops a trailing dot or space, and writes setup.py::$DATA
    # as setup.py.
    for name in files:
        rest = name[len(top) + 1 :] if top else name
        if rest.split(":")[0].rstrip(". ").lower() in _BUILD_FILES and rest not in _BUILD_FILES:
            message = f"{rest} is a build file on macOS or Windows, and is not read as one"
            findings.append(Finding("BKT-SKIP-001", message, Severity.INFO, name))

    dist, version = split_artifact_name(path.name)
    if complete:
        findings.extend(_check_metadata(at("PKG-INFO"), files, dist, version))
    whole = [at("setup.py")] if at("setup.py") in files else []
    folders = {at(".")}
    if at("pyproject.toml") in files:
        backend_findings, modules, backend_folders = _check_build_backend(at, files)
        findings.extend(backend_findings)
        whole.extend(m for m in modules if m not in whole)
        folders |= backend_folders
    # exec(open('pkg/_version.py').read()) runs that file at install too: read its
    # top level, as for a module. Paths are only looked up in the archive, so ../
    # can only miss.
    queue = [(name, False) for name in whole]
    setup, setup_at, setup_found = at("setup.py"), len(findings), []
    for name, top_level_only in queue:  # grows as exec'd files are found
        found, exec_files = _code_findings(
            "INSTALL",
            name,
            files[name],
            top_level_only,
            follow=lambda p: at(p) in files,
            version=version,
        )
        if name == setup:  # placed once the other install code is known
            setup_found = found
        else:
            findings.extend(found)
        if CALL_TIME and top_level_only:  # a file setup.py execs: its functions too
            findings.extend(_call_findings(name, files[name]))
        for path in exec_files:
            if at(path) not in {queued for queued, _ in queue}:
                queue.append((at(path), True))
    whole = [name for name, _ in queue]
    under, names = _declared(files, at, top)
    # Local modules the install code imports run at install: their top level, and
    # the functions it calls from them (from main import main; main()). Looked up
    # in the package roots too, as setup.py often puts src/ on sys.path first.
    entry: dict[str, dict[str, str]] = {}
    for name in whole:
        if len(files[name]) > MAX_SOURCE_BYTES:
            continue  # already reported as not parsed
        try:
            imported = imported_functions(files[name])
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue  # already reported as not parsed
        for module, functions in imported.items():
            path = module.replace(".", "/")
            for candidate in under.get(f"{path}.py", []) + under.get(f"{path}/__init__.py", []):
                if candidate not in whole:
                    entry.setdefault(candidate, {}).update(functions)
    beside = {
        name
        for name in files
        if name.endswith(".py") and posixpath.dirname(name) in folders and name not in whole
    }
    # Package modules are installed, so they run at import as a wheel's do,
    # with the functions they call in each other.
    modules: dict[str, list[tuple[str, bytes]]] = {}
    for name, dotted in _package_modules(files, under, names):
        modules.setdefault(dotted, []).append((name, files[name]))
    package_modules = sorted({name for files_ in modules.values() for name, _ in files_})
    # A module no import statement can name (node_modules/node-gyp/...) runs only
    # when code that runs names it by a string: as for a wheel, its import
    # findings are notes until then. Install code counts as code that runs.
    unnamed = {
        module
        for module, found in modules.items()
        for name, _ in found
        if _vendored(
            module.replace(".", "/")
            + ("/__init__.py" if posixpath.basename(name) == "__init__.py" else ".py")
        )
    }
    install_names: set[str] = set()
    for name in [*whole, *sorted(beside)] if unnamed else ():
        try:
            if len(files[name]) > MAX_SOURCE_BYTES:
                raise ValueError("too large to parse")
            install_names |= imported_modules(files[name], "")
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            unnamed = set()  # install code we cannot read may name any of them
            break
    if may_import_any(install_names):
        unnamed = set()  # install code that imports by a computed name may run any of them
    quiet = _quiet_files(modules, unnamed, _named(unnamed, install_names)) if unnamed else set()
    called, gaps = _calls_between(modules, quiet, seed=entry)
    findings.extend(gaps)
    for name, functions in called.items():
        if "called at install" in functions.values():
            entry.setdefault(name, {})  # reached from install code, so it runs at install
    for name in sorted(beside | entry.keys()):
        # A package module setup.py imports is read as install code, so the
        # functions other package modules call in it are read here too.
        how = called.get(name, {}) | entry.get(name, {})
        found = _code_findings("INSTALL", name, files[name], True, entry=how, version=version)
        findings.extend(found[0])
        if CALL_TIME:
            findings.extend(_call_findings(name, files[name], how))
    read = set(whole) | beside | entry.keys()
    if setup in files:
        # Code in setup.py pip never runs (a publish command) is a note, not install code.
        config = [at("setup.cfg"), at("pyproject.toml")]
        config += [name for name in files if name.endswith(".egg-info/entry_points.txt")]
        if skipped := _not_run_by_pip(files, setup, config):
            setup_found = _code_findings(
                "INSTALL",
                setup,
                files[setup],
                False,
                lambda p: at(p) in files,
                skipped=skipped,
                version=version,
            )[0]
        findings[setup_at:setup_at] = setup_found
    for name in package_modules:
        if name not in read:
            how = called.get(name, {})
            found = _code_findings("IMPORT", name, files[name], True, entry=how, version=version)
            _quieten(found[0], quiet)
            findings.extend(found[0])
            if CALL_TIME:
                findings.extend(_call_findings(name, files[name], called.get(name, {})))
    if CALL_TIME:  # tests, docs, examples and scripts: all of it runs only when called
        done = read.union(package_modules)
        for name in sorted(files):
            if name not in done and _is_python(name, files[name]):
                findings.extend(_call_findings(name, files[name], whole_file=True))
    # setup.py, a build backend or their config can put any file the sdist ships
    # at the top of site-packages (data_files, a copy in an install command, a
    # folder mapped to the wheel root), so every .pth is read as installed. Test
    # folders are left out unless the install code or config mentions ".pth".
    install = read | {at("setup.cfg"), at("pyproject.toml")}
    mentioned = any(b".pth" in files[name] for name in install if name in files)
    for name in sorted(files):
        folders = name.split("/")[1 if top else 0 : -1]
        if name.endswith(".pth") and (mentioned or not any(map(_is_test_folder, folders))):
            findings.extend(_check_pth(name, files[name]))
        # An sdist ships source, so a binary is not built from anything read here.
        if not any(map(_is_test_folder, folders)):
            # An empty file holds no code: meson's test cases ship empty lib*.so stand-ins.
            where = "an sdist, which ships source"
            findings.extend(_check_binary(name, files[name], bool(files[name]), where))
    # Install code can also write the .pth line itself: read its strings as .pth text.
    for name in sorted(read) if mentioned else ():
        if len(files[name]) > MAX_SOURCE_BYTES:
            continue  # already reported as not parsed
        try:
            tree = ast.parse(files[name])
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue  # already reported as not parsed
        # Code a process call runs with -c is not written to a file (poetry-core's
        # wheel builder: check_output([executable, "-c", "import sysconfig ..."])).
        commands = command_code(tree)
        for node in ast.walk(tree):
            if node in commands:
                continue
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for finding in _check_pth(name, node.value.encode("utf-8", "surrogatepass")):
                    finding.metadata["line"] += node.lineno - 1
                    findings.append(finding)
    return findings


# Root-level folders a build usually leaves out (find_packages(exclude=...)),
# used when the sdist does not say what it installs.
_NOT_INSTALLED = frozenset(
    {"doc", "docs", "example", "examples", "scripts", "devscripts", "dev", "tools", "build"}
    | {"bench", "benchmarks", "ci"}
)


def _is_test_folder(name: str) -> bool:
    return name.lower() in ("test", "testing") or name.lower().startswith("tests")


def _declared(
    files: dict[str, bytes], at: Callable[[str], str], top: str
) -> tuple[dict[str, list[str]], set[str]]:
    """The sdist's .py files by their path under each package root, and the
    top-level names it says it installs.

    Package roots are the sdist's root, src/ and any literal
    `package_dir={"": ...}` in setup.py. Names come from an egg-info
    top_level.txt and from literal `packages=` in setup.py (their first part),
    and a literal `py_modules=` names a file ("tool.py"). These are the
    uploader's word, so they only add code to read, never hide any. A file
    under two roots is listed under both paths.
    """
    roots, names = ["", "src"], set()
    prefix = f"{top}/" if top else ""
    for name in files:
        rel = name[len(prefix) :] if name.startswith(prefix) else ""
        if rel.count("/") <= 2 and rel.endswith(".egg-info/top_level.txt"):
            text = files[name].decode("utf-8", errors="replace")
            names |= {line.strip() for line in text.splitlines()}
    setup = files.get(at("setup.py"), b"")
    try:
        tree = ast.parse(setup) if len(setup) <= MAX_SOURCE_BYTES else None
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        tree = None  # already reported as not parsed
    for node in ast.walk(tree) if tree else ():
        for keyword in node.keywords if isinstance(node, ast.Call) else ():
            if keyword.arg not in ("package_dir", "packages", "py_modules"):
                continue
            try:
                value = ast.literal_eval(keyword.value)
            except (ValueError, TypeError, SyntaxError, RecursionError, MemoryError):
                continue  # not a literal: named at run time
            if keyword.arg == "package_dir" and isinstance(value, dict):
                roots += [v for k, v in value.items() if k == "" and isinstance(v, str)]
            elif isinstance(value, (list, tuple)):
                # "pkg.sub", "./pkg" and distutils' "pkg/sub" all name pkg
                paths = [
                    posixpath.normpath(v).replace(".", "/") for v in value if isinstance(v, str)
                ]
                if keyword.arg == "packages":
                    names |= {path.strip("/").split("/")[0] for path in paths}
                else:
                    names |= {f"{path.strip('/')}.py" for path in paths}
    # Index each file under every root it sits in: one pass over its folders, so
    # however many roots setup.py names, the cost stays per file.
    bases = {at(root) for root in roots}
    under: dict[str, list[str]] = {}
    for name in files:
        if name.endswith(".py"):
            parts = name.split("/")
            for i in range(len(parts)):
                if ("/".join(parts[:i]) or ".") in bases:
                    under.setdefault("/".join(parts[i:]), []).append(name)
    names.discard("")
    return under, names


def _package_modules(
    files: dict[str, bytes], under: dict[str, list[str]], names: set[str]
) -> list[tuple[str, str]]:
    """The .py files in an sdist's importable packages, each with its dotted name.

    A file under a package root counts when every folder from the root down to
    it has an __init__.py, or when its top-level name is declared installed
    (see _declared), which also brings in namespace packages, loose modules and
    root-level dev folders. Test folders inside a package are always left out,
    and root-level test and dev folders unless declared.
    """
    modules = []
    for rel, found in sorted(under.items()):
        parts = rel.split("/")
        folders = parts[:-1]
        if any(_is_test_folder(f) for f in folders[1:]):
            continue
        # a declared folder (or top-level module), or a declared module file
        declared = parts[0] in names or rel in names or rel.removesuffix(".py") in names
        if not declared and (
            not folders or _is_test_folder(folders[0]) or folders[0] in _NOT_INSTALLED
        ):
            continue
        dotted = rel.removesuffix(".py").removesuffix("/__init__").replace("/", ".")
        for name in found:
            base = name[: len(name) - len(rel)]
            if declared or all(
                f"{base}{'/'.join(folders[: i + 1])}/__init__.py" in files
                for i in range(len(folders))
            ):
                modules.append((name, dotted))
    return modules


def _check_build_backend(
    at: Callable[[str], str], files: dict[str, bytes]
) -> tuple[list[Finding], list[str], set[str]]:
    """BKT-INSTALL-009 for build requirements, BKT-INSTALL-007 for a backend in the sdist.

    Also returns the backend's module files and the backend-path folders, for
    the caller to read as install-time code.
    """
    name = at("pyproject.toml")
    try:
        data = tomllib.loads(files[name].decode("utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        message = f"could not parse pyproject.toml: {exc}"
        return [Finding("BKT-SKIP-003", message, Severity.INFO, name)], [], set()
    build_system = data.get("build-system", {})
    if not isinstance(build_system, dict):
        message = "pyproject.toml build-system is not a table"
        return [Finding("BKT-SKIP-003", message, Severity.INFO, name)], [], set()
    findings = []
    # pip installs these and runs them at install. They are not read here, so
    # name them: a gap would fail nearly every sdist.
    requires = build_system.get("requires")
    names = [r for r in requires if isinstance(r, str)] if isinstance(requires, list) else []
    if names:
        more = f", and {len(names) - 10} more" if len(names) > 10 else ""
        listed = ", ".join(names[:10]) + more
        message = f"build requirements run at install and are not read here: {listed}"
        findings.append(Finding("BKT-INSTALL-009", message, Severity.INFO, name))
    backend_path = build_system.get("backend-path")
    if not isinstance(backend_path, list) or not backend_path:
        return findings, [], set()
    # Info: common (pyyaml, pillow, setuptools). The backend's own code is read
    # by the caller, and what it does is what gets flagged.
    message = "build backend is shipped in the sdist (backend-path), so its code runs at install"
    findings.append(Finding("BKT-INSTALL-007", message, Severity.INFO, name))
    module = str(build_system.get("build-backend", "")).split(":")[0].replace(".", "/")
    folders = {at(folder) for folder in backend_path if isinstance(folder, str)}
    modules = [
        candidate
        for folder in sorted(folders)
        for candidate in (f"{folder}/{module}.py", f"{folder}/{module}/__init__.py")
        if module and posixpath.normpath(candidate) in files
    ]
    return findings, [posixpath.normpath(m) for m in modules], folders


# Kind of code hit -> rule id and severity. {when} is INSTALL or IMPORT: it says
# when the code runs, so BKT-INSTALL-001 is network access in setup.py. Hidden
# code is reported the same way wherever it is.
_CODE_RULES = {
    "network": ("BKT-{when}-001", Severity.HIGH),
    "process": ("BKT-{when}-002", Severity.MEDIUM),
    "exec": ("BKT-{when}-003", Severity.MEDIUM),
    "secrets": ("BKT-{when}-004", Severity.HIGH),
    "persistence": ("BKT-{when}-005", Severity.HIGH),
    "environ": ("BKT-{when}-006", Severity.INFO),
    "hidden": ("BKT-HIDE-001", Severity.HIGH),
    "encoded": ("BKT-HIDE-002", Severity.LOW),
    "discord": ("BKT-EXFIL-001", Severity.MEDIUM),
    "telegram": ("BKT-EXFIL-002", Severity.MEDIUM),
}
_WHEN = {"INSTALL": "at install", "IMPORT": "at import"}


def _code_findings(
    when: str,
    name: str,
    source: bytes,
    top_level_only: bool,
    follow: Callable[[str], bool] = lambda path: False,
    entry: Mapping[str, str] = {},
    skipped: Sequence[tuple[int, int, str | None]] = (),
    version: str = "",
) -> tuple[list[Finding], list[str]]:
    """One finding per kind of hit per file, with every line it was seen on.

    exec(open('p').read()) of a file the caller can read (follow(p) is true)
    is returned for the caller to read in turn: the setup.py version trick.
    Any other exec of a file is reported as exec, since its code is not here.
    Hits on lines skipped says pip never runs (see _skipped) are info notes.
    """
    if len(source) > MAX_SOURCE_BYTES:
        message = f"over {MAX_SOURCE_BYTES} bytes, not parsed"
        return [Finding("BKT-SKIP-003", message, Severity.INFO, name)], []
    try:
        hits = analyse(source, top_level_only, entry)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        message = f"could not parse as Python: {exc}"
        return [Finding("BKT-SKIP-003", message, Severity.INFO, name)], []
    by_kind: dict[str, list] = {}
    for hit in hits:
        by_kind.setdefault(hit.kind, []).append(hit)
    exec_files = []
    for hit in by_kind.pop("exec_file", []):
        if follow(hit.detail):
            exec_files.append(hit.detail)
        else:
            by_kind.setdefault("exec", []).append(Hit("exec", hit.line, f"execs {hit.detail}"))
    # Code pip never runs is a note. Hidden code and channels count wherever they are.
    notes: dict[str, list] = {}
    for kind in [k for k in by_kind if "{when}" in _CODE_RULES[k][0]]:
        for hit in list(by_kind[kind]):
            if why := _skipped(skipped, hit.line):
                by_kind[kind].remove(hit)
                notes.setdefault(kind, []).append(Hit(kind, hit.line, f"{hit.detail} ({why})"))
        if not by_kind[kind]:
            del by_kind[kind]
    findings = []
    text = source.decode("utf-8", "replace").splitlines()

    def where(lines: list[int]) -> dict[str, list]:
        # A hash of each line's text, so diff can tell one call from another of a
        # kind. A hash, not the text: a line can hold a token, and reports never do.
        code = [text[n - 1].strip() if 0 < n <= len(text) else "" for n in lines]
        if "." in version:  # a line naming the package's own version is the same line
            code = [c.replace(version, "") for c in code]
        return {"lines": lines, "line_hashes": [_line_hash(c) for c in code]}

    for kind, kind_hits in by_kind.items():
        rule, severity = _CODE_RULES[kind]
        details = "; ".join(sorted({h.detail for h in kind_hits}))
        message = f"runs {_WHEN[when]}: {details}" if "{when}" in rule else details
        lines = [h.line for h in kind_hits]
        findings.append(Finding(rule.format(when=when), message, severity, name, where(lines)))
    if "network" in by_kind and ("secrets" in by_kind or "environ" in by_kind):
        message = f"reads credentials or the whole environment and uses the network {_WHEN[when]}"
        parts = {h.line for k in ("network", "secrets", "environ") for h in by_kind.get(k, [])}
        findings.append(
            Finding(f"BKT-{when}-008", message, Severity.CRITICAL, name, where(sorted(parts)))
        )
    for kind, kind_hits in notes.items():
        details = "; ".join(sorted({h.detail for h in kind_hits}))
        message = f"runs only on request, not at install: {details}"
        lines = [h.line for h in kind_hits]
        rule = _CODE_RULES[kind][0].format(when=when)
        findings.append(Finding(rule, message, Severity.INFO, name, where(lines)))
    return findings, exec_files


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()[:16]


def _skipped(spans: Sequence[tuple[int, int, str | None]], line: int) -> str | None:
    """Why pip never runs a line: from the smallest span holding it (code that runs
    wins a tie), or None when it may run."""
    holding = [
        (last - first, why is not None, why) for first, last, why in spans if first <= line <= last
    ]
    return min(holding)[2] if holding else None


# pip's default for an sdist with no build-backend is setuptools' legacy one.
_SETUPTOOLS_BACKENDS = ("setuptools.build_meta:__legacy__", "setuptools.build_meta")


def _not_run_by_pip(
    files: Mapping[str, bytes], setup: str, config: Iterable[str]
) -> list[tuple[int, int, str | None]]:
    """not_run_by_pip for setup.py, or nothing when commands or setup.py's names
    can be reached from elsewhere: a build backend other than setuptools' own
    (it may run any command), config that names commands (aliases, a cmdclass,
    distutils.commands entry points), or any other file in the sdist that could
    run at install and reaches setup.py (see reaches_setup_py), or cannot be
    read (too large, bytecode, a native module). Any module can run at install:
    setup.py's imports run their packages' __init__ and what that imports."""
    pyproject = next((name for name in config if name.endswith("pyproject.toml")), "")
    if pyproject in files:
        try:
            toml = tomllib.loads(files[pyproject].decode("utf-8", "replace"))
        except (tomllib.TOMLDecodeError, RecursionError):
            return []
        build = toml.get("build-system", {})
        if not isinstance(build, dict) or "backend-path" in build:
            return []
        if build.get("build-backend", _SETUPTOOLS_BACKENDS[0]) not in _SETUPTOOLS_BACKENDS:
            return []
    for name in config:
        text = files.get(name, b"")
        if any(word in text for word in (b"cmdclass", b"distutils.commands")):
            return []
        if b"aliases" not in text:
            continue
        # An alias only matters named like a command pip runs (egg_info = publish).
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text.decode("utf-8", "replace"))
        except configparser.Error:
            return []
        aliases = parser["aliases"] if parser.has_section("aliases") else {}
        if not name.endswith("setup.cfg") or {a.lower() for a in aliases} & _LEGACY_COMMANDS:
            return []
    try:
        if len(files[setup]) > MAX_SOURCE_BYTES:
            return []
        spans = not_run_by_pip(files[setup], legacy=pyproject not in files)
        if all(why is None for _, _, why in spans):
            return spans  # nothing is skipped: no need to read the rest
        for name, data in files.items():
            lower = name.lower()
            if lower.endswith(_UNREADABLE_CODE) or _NATIVE_NAME.search(name):
                return []
            if lower.endswith((".py", ".pyw")) and name != setup:
                if len(data) > MAX_SOURCE_BYTES or reaches_setup_py(data):
                    return []
        return spans
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []


# Code an import can run that is not read here: bytecode, and archives zipimport
# loads once on sys.path.
_UNREADABLE_CODE = (".pyc", ".pyo", ".zip", ".egg", ".whl", ".pyz")


def _call_findings(
    name: str, source: bytes, entry: Mapping[str, str] = {}, whole_file: bool = False
) -> list[Finding]:
    """BKT-CALL-* for code that runs only when called (see call_units).

    A file too large or that will not parse adds nothing here: an installed
    module is already reported as not parsed, and a script or test file was
    never read before, nor runs on its own.
    """
    if len(source) > MAX_SOURCE_BYTES:
        return []
    try:
        units = call_units(source, entry, whole_file)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    return _combinations(name, units)


# What a unit of call-time code must combine to be flagged: one kind of hit from
# each group. Alone, each kind is everyday code in a library.
_CALL_RULES = [
    (
        "BKT-CALL-001",
        Severity.HIGH,
        "fetches code and runs it",
        [{"network", "fetch_run"}, {"exec", "hidden", "runs_written", "fetch_run"}],
    ),
    (
        "BKT-CALL-002",
        Severity.HIGH,
        "decodes data and runs it",
        [{"decode"}, {"exec", "hidden", "runs_written"}],
    ),
    (
        "BKT-CALL-003",
        Severity.HIGH,
        "uses a start-up location and the network",
        [{"persistence", "names_persistence"}, {"network"}],
    ),
    (
        "BKT-CALL-004",
        Severity.HIGH,
        "connects out and hands its streams to a process (a reverse shell)",
        [{"redirect"}, {"network"}, {"process"}],
    ),
    (
        "BKT-CALL-005",
        Severity.HIGH,
        "reads credentials and uses the network",
        [{"secrets"}, {"network"}],
    ),
]


def _combinations(name: str, units: list[Unit]) -> list[Finding]:
    """One finding per rule per file, naming the units and the lines involved."""
    findings = []
    for rule, severity, meaning, groups in _CALL_RULES:
        wanted = set().union(*groups)
        matched = [u for u in units if all(g & {h.kind for h in u.hits} for g in groups)]
        if not matched:
            continue
        where = ", ".join(f"{u.name}()" for u in matched[:5]) + (
            ", ..." if len(matched) > 5 else ""
        )
        details = "; ".join(sorted({h.detail for u in matched for h in u.hits if h.kind in wanted}))
        lines = sorted({h.line for u in matched for h in u.hits if h.kind in wanted})
        message = f"when called, {meaning} in {where}: {details}"
        findings.append(Finding(rule, message, severity, name, {"lines": lines}))
    return findings
