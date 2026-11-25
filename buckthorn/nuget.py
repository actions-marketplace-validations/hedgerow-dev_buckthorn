"""NuGet packages (.nupkg): what the .nuspec names, and the code that runs on
its own: the PowerShell scripts Visual Studio runs from tools/, the MSBuild
files NuGet imports into every build (and the package files they import), and
analyzers, which run inside the compiler.

Read from members already in memory (see scan.read_archive). Nothing is run.
XML with a DOCTYPE is refused before it is parsed, so no entity is expanded or
fetched. Compiled code is not read: an analyzer or a task assembly runs on its
own at build, so each is a BKT-SKIP-003; lib/ runs only when the app calls it,
like an npm bin file, and is not read.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import xml.etree.ElementTree as ET  # noqa: S405 - a DOCTYPE is refused before parsing (_xml)
from collections.abc import Container
from urllib.parse import unquote

from buckthorn.code import FETCHING_COMMAND, channels_in
from buckthorn.findings import Finding, Severity

MAX_XML_BYTES = 5 * 1024 * 1024  # the same cap as one Python file
# Scripts Visual Studio runs from tools/ (or tools/<framework>/): init.ps1 when
# the solution opens, install.ps1 and uninstall.ps1 when a packages.config
# project adds or removes the package.
_SCRIPTS = {
    "init.ps1": "when the solution opens",
    "install.ps1": "when the package is installed (packages.config projects)",
    "uninstall.ps1": "when the package is removed (packages.config projects)",
}
# PowerShell that runs code it builds or ships, beside fetching: keeps an
# install.ps1 or uninstall.ps1 medium.
_PS_RUNS = re.compile(
    r"\b(?:iex|invoke-expression|frombase64string|start-process|add-type)\b"
    r"|\s-(?:e|en|enc|encodedcommand)\s",
    re.IGNORECASE,
)
# Folders whose <id>.props and <id>.targets NuGet imports into every build, at
# the top or in a <framework>/ folder. Lower case: NuGet matches in any case.
# buildCrossTargeting is buildMultiTargeting's old name, still read.
_BUILD_FOLDERS = ("build", "buildtransitive", "buildmultitargeting", "buildcrosstargeting")
# .NET and PowerShell calls that use the network, beside FETCHING_COMMAND.
_NETWORK = re.compile(
    r"\b(?:WebClient|HttpClient|WebRequest|HttpWebRequest|TcpClient|UdpClient"
    r"|DownloadString|DownloadFile|DownloadData)\b",
    re.IGNORECASE,
)
# A path under one of these (and not climbing out with ..) is MSBuild's or the
# SDK's own, not the package's.
_MSBUILD_OWN = re.compile(
    r"\s*\$\((?:MSBuildToolsPath|MSBuildBinPath|MSBuildExtensionsPath(?:32|64)?"
    r"|MSBuildFrameworkToolsPath(?:32|64)?|MSBuildSDKsPath)\)",
    re.IGNORECASE,
)
# The project being built, which the MSBuild task may build again: not package code.
_USER_PROJECT = re.compile(r"\s*\$\(MSBuildProject(?:FullPath|File)\)\s*", re.IGNORECASE)
_THIS_FOLDER = re.compile(r"\$\(MSBuildThisFileDirectory\)", re.IGNORECASE)
# An MSBuild project SDK package (<Project Sdk="Pkg/1.0">): MSBuild imports these.
_SDK_FILES = ("sdk/sdk.props", "sdk/sdk.targets")
# Properties Microsoft.Common.targets runs with Exec.
_BUILD_EVENTS = frozenset({"prebuildevent", "postbuildevent"})
# Properties the SDK and common targets take as a program or task assembly to
# run (CscToolPath, CscToolExe, MicrosoftNETBuildTasksAssembly, DotnetHostPath).
_TOOL_PROPERTY = re.compile(
    r"(?:toolpath|toolexe|toolfullpath|tasksassembly|taskassembly)$|^dotnethostpath$"
)
# MSBuild files a property or item can point the build at (.csproj, .proj, ...).
_MSBUILD_FILES = ("proj", ".props", ".targets", ".tasks")
# MSBuild's own folder properties. A package that sets one can point a path
# that looks like MSBuild's at itself.
_OWN_FOLDERS = re.compile(
    r"msbuild(?:toolspath|binpath|extensionspath(?:32|64)?|frameworktoolspath(?:32|64)?|sdkspath)"
)
# Properties that make the build import a file (CustomAfterMicrosoftCommonTargets,
# RoslynTargetsPath): judged by value when written out, a gap when a task sets them.
_IMPORT_PROPERTY = re.compile(r"^custom(?:before|after)|(?:targets|props)(?:path|file)?$")
# C++ build steps whose <Command> MSBuild runs.
_CPP_STEPS = frozenset(
    {"prebuildevent", "prelinkevent", "postbuildevent", "custombuildstep", "custombuild"}
)
# Files a later build, restore or shell runs, when a build writes them.
_RUNS_LATER = re.compile(
    r"(?:proj|\.props|\.targets|\.tasks|\.rsp|\.ps1|\.psm1|\.cmd|\.bat|\.sh"
    r"|(?:^|[/\\])global\.json|(?:^|[/\\])nuget\.config)\s*$",
    re.IGNORECASE,
)
# SDKs the .NET SDK ships. Any other MSBuild may fetch from NuGet and import.
_INBOX_SDK = re.compile(r"\s*Microsoft\.NET\.Sdk(?:\.[A-Za-z]+)*\s*(?:/|$)", re.IGNORECASE)
_CHANNEL_RULES = {"discord": "BKT-EXFIL-001", "telegram": "BKT-EXFIL-002"}

# Member names by key: unescaped as NuGet unpacks them (%2F is /), \ as /, in
# lower case. Each key holds every copy: a zip can hold a name twice.
Files = dict[str, list[tuple[str, bytes]]]


def scan_nuget(stem: str, members: list[tuple[str, bytes]], read: list[Finding]) -> list[Finding]:
    """Findings for a .nupkg. stem is its file name without .nupkg; read holds
    the coverage findings from reading the archive."""
    files: Files = {}
    for name, data in members:
        files.setdefault(_key(name), []).append((name, data))
    findings = list(read)
    # NuGet reads the one .nuspec at the top of the package, and refuses more.
    copies = [
        c for key, cs in files.items() if "/" not in key and key.endswith(".nuspec") for c in cs
    ]
    path = copies[0][0] if len(copies) == 1 else ".nuspec"
    root, problem = _xml(copies[0][1], path) if len(copies) == 1 else (None, "")
    ids, versions = _metadata(root)
    if root is None or not ids or not versions:
        if not problem:
            problem = (
                "no .nuspec at the top of the package"
                if not copies
                else "more than one .nuspec at the top of the package"
                if len(copies) > 1
                else ".nuspec has no id or version"
            )
        message = ".nuspec cannot be read, so what the package is and runs is unknown"
        return findings + [
            Finding("BKT-SKIP-003", problem, Severity.INFO, path),
            Finding("BKT-NUGET-META-001", message, Severity.MEDIUM, path),
        ]
    if len(ids) > 1 or len(versions) > 1:
        # Tools disagree on which one counts: each id's MSBuild files are read.
        shown = ", ".join(v[:100] for v in ids + versions)
        message = f".nuspec names more than one id or version ({shown})"
        findings.append(Finding("BKT-NUGET-META-001", message, Severity.MEDIUM, path))
    else:
        findings += _check_name(stem, ids[0], versions[0], path)
    findings += _channels(_strings(root), path)
    findings += _check_scripts(files)
    findings += _check_msbuild(files, [i.lower() for i in ids])
    findings += _check_analyzers(files)
    return findings


def _key(name: str) -> str:
    return _clean(unquote(name).replace("\\", "/"))


def _clean(path: str) -> str:
    """A /-separated path as Windows names the file: trailing dots and spaces
    dropped from each name, name::$DATA as name. Normalized, in lower case."""
    parts = []
    for part in path.split("/"):
        if part.lower().endswith("::$data"):
            part = part[: -len("::$data")]
        parts.append(part if part in (".", "..") else part.rstrip(" ."))
    return posixpath.normpath("/".join(parts)).lstrip("/").lower()


def _local(tag: str) -> str:
    """An element or attribute name without its namespace, in lower case."""
    return tag.rpartition("}")[2].lower()


def _xml(data: bytes, path: str) -> tuple[ET.Element | None, str]:
    """The parsed file, or None and why not."""
    name = posixpath.basename(path)
    if len(data) > MAX_XML_BYTES:
        return None, f"{name} is over {MAX_XML_BYTES} bytes, not parsed"
    try:
        text = _decode(data)
    except (ValueError, LookupError):  # UnicodeError too: encoding="undefined"
        return None, f"{name} is not text in the encoding it names, not parsed"
    if re.search(r"<!DOCTYPE", text, re.IGNORECASE):
        return None, f"{name} has a DOCTYPE, which can define entities: not parsed"
    try:
        return ET.fromstring(text), ""  # noqa: S314 - no DOCTYPE, so no entities
    except ET.ParseError as exc:
        return None, f"could not parse {name}: {exc}"


def _decode(data: bytes) -> str:
    """XML as .NET reads it: by its byte order mark, else in the encoding its
    declaration names (utf-7 too), else UTF-8."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    declared = re.match(
        rb"\s*<\?xml[^>]*?encoding\s*=\s*[\"']([A-Za-z0-9._-]{1,40})[\"']", data[:1024]
    )
    return data.decode(declared[1].decode("ascii") if declared else "utf-8")


def _metadata(root: ET.Element | None) -> tuple[list[str], list[str]]:
    """Every id and version in package/metadata, each once (in any case), in
    any case of the element name: NuGet reads the first in its own case."""
    found: dict[str, dict[str, str]] = {"id": {}, "version": {}}
    if root is None or _local(root.tag) != "package":
        return [], []
    for metadata in root:
        if _local(metadata.tag) == "metadata":
            for item in metadata:
                value = (item.text or "").strip()
                if _local(item.tag) in found and value:
                    found[_local(item.tag)].setdefault(value.lower(), value)
    return list(found["id"].values()), list(found["version"].values())


def _check_name(stem: str, package_id: str, version: str, path: str) -> list[Finding]:
    """BKT-NUGET-META-001 when id and version do not give the file name. nuget
    pack writes the normalized version; nuget.org names files in lower case."""
    names = {f"{package_id}.{v}".lower() for v in (version, _normalized(version))}
    if stem.lower() in names:
        return []
    # Cut short: these come from the package, so they can be any size.
    message = f".nuspec says {package_id[:100]} {version[:100]}, file name says {stem}"
    return [Finding("BKT-NUGET-META-001", message, Severity.MEDIUM, path)]


def _normalized(version: str) -> str:
    """A NuGet version as NuGet writes it: no leading zeros, at least three
    parts, a fourth only when it is not 0, no build metadata."""
    release = version.partition("+")[0]
    numbers, dash, pre = release.partition("-")
    parts = numbers.split(".")
    if not 1 <= len(parts) <= 4 or not all(
        p.isascii() and p.isdigit() and len(p) < 20 for p in parts
    ):
        return release
    parts = [str(int(p)) for p in parts] + ["0"] * (3 - len(parts))
    if len(parts) == 4 and parts[3] == "0":
        parts = parts[:3]
    return ".".join(parts) + dash + pre


def _text(data: bytes) -> str:
    """A script as text: UTF-16 by its byte order mark, else UTF-8 (bytes that
    are not are replaced, so the rest is still read)."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    return data.decode("utf-8-sig", "replace")


def _fetches(text: str) -> str:
    """What in a command, script or inline code uses the network, or ""."""
    match = FETCHING_COMMAND.search(text) or _NETWORK.search(text)
    return match.group(0) if match else ""


def _channels(strings: list[str], path: str) -> list[Finding]:
    """BKT-EXFIL-001/002 for a messenger channel in any of the strings, once a kind."""
    found: dict[str, str] = {}
    for string in strings:
        for kind, detail in channels_in(string):
            found.setdefault(kind, detail)
    return [
        Finding(_CHANNEL_RULES[kind], detail, Severity.MEDIUM, path)
        for kind, detail in found.items()
    ]


def _strings(root: ET.Element, skip: Container[ET.Element] = ()) -> list[str]:
    """Every text and attribute value in an XML tree, but those of the
    elements in skip."""
    strings = []
    for element in root.iter():
        if element not in skip:
            strings += [element.text or "", element.tail or "", *element.attrib.values()]
    return [s for s in strings if s.strip()]


# Tasks whose text a build only shows: it never reaches a command.
_SHOWN = frozenset({"error", "warning", "message"})


def _check_scripts(files: Files) -> list[Finding]:
    """BKT-NUGET-SCRIPT-001 for each PowerShell script Visual Studio runs, and
    BKT-NUGET-INSTALL-001 for one that fetches. PowerShell is not parsed."""
    findings = []
    for key, copies in files.items():
        parts = key.split("/")
        if parts[0] != "tools" or len(parts) not in (2, 3) or parts[-1] not in _SCRIPTS:
            continue
        for path, data in copies:
            text = _text(data)
            message = f"Visual Studio runs {parts[-1]} {_SCRIPTS[parts[-1]]}"
            # install.ps1 and uninstall.ps1 run only in packages.config projects,
            # and in the top 1,000 packages were all routine setup: a note.
            # Medium again when it runs code it decodes, compiles or ships.
            runs = parts[-1] == "init.ps1" or _PS_RUNS.search(text)
            severity = Severity.MEDIUM if runs else Severity.INFO
            findings.append(Finding("BKT-NUGET-SCRIPT-001", message, severity, path))
            if fetched := _fetches(text):
                message = f"{parts[-1]} fetches ({fetched})"
                findings.append(Finding("BKT-NUGET-INSTALL-001", message, Severity.HIGH, path))
            findings += _channels([text], path)
    return findings


def _check_msbuild(files: Files, ids: list[str]) -> list[Finding]:
    """The MSBuild files NuGet imports into every build (and MSBuild into a
    project that names the package as its SDK), and the package files they
    import, read for what they run."""
    names = {f"{i}{ext}" for i in ids for ext in (".props", ".targets")}
    todo = [
        key
        for key in files
        if key in _SDK_FILES
        or (
            (parts := key.split("/"))[0] in _BUILD_FOLDERS
            and len(parts) in (2, 3)
            and parts[-1] in names
        )
    ]
    seen = set(todo)
    findings = []
    while todo:
        key = todo.pop()
        for path, data in files[key]:
            root, problem = _xml(data, path)
            if root is None:
                findings.append(Finding("BKT-SKIP-003", problem, Severity.INFO, path))
                continue
            found, imports = _msbuild(files, key, path, root)
            findings += found
            for target in imports:
                if target not in seen:
                    seen.add(target)
                    todo.append(target)
    # Any other MSBuild project in the package: a property built from other
    # properties can still point the build at it, but such a property in the
    # files read above is already a gap. A note: .NET workload manifests ship
    # these by the dozen (eval/nuget-noise).
    for key in files.keys() - seen:
        for path, data in files[key]:
            root, _ = _xml(data, path)
            if root is None or _local(root.tag) != "project":
                continue
            found, _ = _msbuild(files, key, path, root)
            findings += [f for f in found if f.rule_id.startswith("BKT-EXFIL")]
            if any(not f.rule_id.startswith("BKT-EXFIL") for f in found):
                message = (
                    "an MSBuild file no import names runs or loads code; a property "
                    "can still point a build at it"
                )
                findings.append(Finding("BKT-NUGET-BUILD-004", message, Severity.INFO, path))
    return findings


def _msbuild(
    files: Files, key: str, path: str, root: ET.Element
) -> tuple[list[Finding], list[str]]:
    """Findings for one MSBuild file, and the package files it imports. Every
    Exec, task and import counts, whatever its Condition and whether or not a
    build reaches its target."""
    strings = _strings(root)
    findings = _channels(strings, path)
    imports: list[str] = []
    folder = posixpath.dirname(key)
    parents = {child: parent for parent in root.iter() for child in parent}
    # An Error, Warning or Message task in a target; a property or item of
    # that name can still reach a command.
    shown_tasks = {
        e
        for e in root.iter()
        if _group(e, parents) == "target" and _local(e.tag).rpartition(".")[2] in _SHOWN
    }
    reach_commands = _strings(root, shown_tasks)

    def run(what: str, command: str) -> None:
        """BUILD-001 for a command; BUILD-002 when it, or (built from
        properties or items) anything in the file but shown text, fetches."""
        shown = " ".join(command.split())[:100]
        message = f"{what} at build ({shown})"
        findings.append(Finding("BKT-NUGET-BUILD-001", message, Severity.MEDIUM, path))
        fetched = _fetches(command)
        if not fetched and re.search(r"[$@%]\(", command):
            fetched = next((f for f in map(_fetches, reach_commands) if f), "")
        if fetched:
            message = f"{what} at build that fetches ({fetched})"
            findings.append(Finding("BKT-NUGET-BUILD-002", message, Severity.HIGH, path))

    def not_read(message: str) -> None:
        findings.append(Finding("BKT-SKIP-003", message, Severity.INFO, path))

    def prop(name: str, value: str | None) -> None:
        """A property set to a value, or (None) by a task at build."""
        name = name.strip().lower()
        if value is None:
            sensitive = name in _BUILD_EVENTS or _TOOL_PROPERTY.search(name)
            if sensitive or _OWN_FOLDERS.fullmatch(name) or _IMPORT_PROPERTY.search(name):
                not_read(f"sets {name[:100]} from a task at build: not judged")
            return
        value = value.strip()
        if not value:
            return
        if name in _BUILD_EVENTS:
            run(f"runs {name}, a command", value)
        elif _TOOL_PROPERTY.search(name):
            not_read(f"points the build at a program ({name[:100]}): compiled, not read")
        elif _OWN_FOLDERS.fullmatch(name):
            not_read(f"sets MSBuild's own {name}, so paths under it can be the package's")
        elif _THIS_FOLDER.search(value):
            imports.extend(_named(files, folder, value))

    def item(name: str, include: str | None) -> None:
        """An item added with an Include, or (None) by a task at build."""
        if name.strip().lower() == "analyzer" and (include is None or include.strip()):
            shown = (include or "from a task").strip()[:100]
            not_read(f"adds an analyzer ({shown}): compiled code the compiler runs, not read")
        elif include and _THIS_FOLDER.search(include):
            imports.extend(_named(files, folder, include))

    def pairs(value: str) -> None:
        """Properties the MSBuild task or a ProjectReference sets: A=1;B=2."""
        for pair in value.split(";"):
            name, eq, set_to = pair.partition("=")
            if eq:
                prop(name, set_to)

    # Property values in this file, for writes built from properties.
    values = [
        "".join(e.itertext()) for e in root.iter() if _group(e, parents) == "propertygroup"
    ] + [
        value
        for e in root.iter()
        if _group(e, parents) == "itemgroup"
        for name, value in e.attrib.items()
        if _local(name) == "include"
    ]
    top = {_local(name): value for name, value in root.attrib.items()}
    sdks = [top.get("sdk", "")] if _local(root.tag) == "project" else []

    for element in root.iter():
        # A task can be named in full: Microsoft.Build.Tasks.Exec is Exec.
        tag = _local(element.tag).rpartition(".")[2]
        group = _group(element, parents)
        projects: list[str] = []  # files an Import or the MSBuild task names
        # MSBuild decodes %XX escapes in a value before using it.
        attrs = {_local(name): unquote(value) for name, value in element.attrib.items()}
        for attr in ("toolpath", "toolexe"):
            if attrs.get(attr, "").strip():
                not_read(f"runs a program the build names ({attrs[attr].strip()[:100]}): not read")
        for attr in ("properties", "additionalproperties"):
            if attr in attrs:
                pairs(attrs[attr])
        if group == "propertygroup":
            prop(tag, unquote("".join(element.itertext())))
        elif group == "itemgroup":
            item(tag, attrs.get("include", ""))
        elif group in ("projectreference", "msbuild") and tag in (
            "properties",
            "additionalproperties",
        ):
            pairs(unquote("".join(element.itertext())))
        elif tag == "command" and group in _CPP_STEPS:
            run(f"runs a {group} command", unquote("".join(element.itertext())))
        elif tag == "output":
            task = parents[element]
            task_name = _local(task.tag).rpartition(".")[2]
            task_attrs = {_local(n): unquote(v) for n, v in task.attrib.items()}
            if "propertyname" in attrs:
                set_to = task_attrs.get("value", "") if task_name == "createproperty" else None
                prop(attrs["propertyname"], set_to)
            if "itemname" in attrs:
                added = task_attrs.get("include", "") if task_name == "createitem" else None
                item(attrs["itemname"], added)
        elif tag == "exec":
            run("runs a command", attrs.get("command", ""))
        elif tag in ("writelinestofile", "copy", "move"):
            named = [attrs.get(a, "") for a in ("file", "sourcefiles", "destinationfiles")]
            written = [n for value in named for n in value.split(";")]
            built = any(re.search(r"[$@%]\(", n) for n in written)
            if (
                any(_RUNS_LATER.search(n) for n in written)
                or (built and any(_RUNS_LATER.search(v.strip()) for v in values))
                or "<project" in attrs.get("lines", "").lower()
            ):
                shown = " ".join(" ".join(named).split())[:100]
                message = f"writes a file a later build or shell runs, at build ({shown})"
                findings.append(Finding("BKT-NUGET-BUILD-001", message, Severity.MEDIUM, path))
        elif tag == "downloadfile":
            url = " ".join(attrs.get("sourceurl", "").split())[:100]
            message = f"downloads a file at build ({url})"
            findings.append(Finding("BKT-NUGET-BUILD-002", message, Severity.HIGH, path))
        elif tag == "xsltransformation" and attrs.get(
            "usetrustedsettings", ""
        ).strip().lower() not in ("", "false"):
            message = (
                "runs XSLT with scripts allowed at build (XslTransformation UseTrustedSettings)"
            )
            findings.append(Finding("BKT-NUGET-BUILD-003", message, Severity.MEDIUM, path))
        elif tag == "usingtask":
            findings += _using_task(files, folder, element, attrs, path)
        elif tag == "sdk":
            sdks.append(attrs.get("name", ""))
        elif tag == "import":
            project = attrs.get("project", "")
            if "sdk" in attrs:
                sdks.append(attrs["sdk"])
                # The SDK's own file, unless its path leaves the SDK's folder.
                if not (_THIS_FOLDER.search(project) or _leaves(project)):
                    continue
            projects = project.split(";")
        elif tag == "msbuild":  # the MSBuild task builds other projects
            projects = [
                p for p in attrs.get("projects", "").split(";") if not _USER_PROJECT.fullmatch(p)
            ]
        for project in projects:
            targets, problem = _resolve(files, folder, project)
            if problem:
                not_read(problem)
            imports += targets
    for sdk in (s for value in sdks for s in value.split(";") if s.strip()):
        if not _INBOX_SDK.match(sdk):
            shown = sdk.strip()[:100]
            not_read(f"uses the {shown} SDK, which MSBuild can fetch from NuGet: not read")
    return findings, imports


def _group(element: ET.Element, parents: dict[ET.Element, ET.Element]) -> str:
    """The name of an element's parent, in lower case, or "" at the top."""
    return _local(parents[element].tag) if element in parents else ""


def _named(files: Files, folder: str, value: str) -> list[str]:
    """The package MSBuild files a property or item value names: a file, each
    MSBuild file in a folder, or none. What is not found is not an import."""
    found = []
    for part in value.split(";"):
        targets, _ = _resolve(files, folder, part)
        found += [t for t in targets if t.endswith(_MSBUILD_FILES)]
    return found


def _leaves(path: str) -> bool:
    """A path that climbs out of the folder it is joined onto, or is rooted."""
    path = path.strip().replace("\\", "/")
    return ".." in path or path.startswith("/") or bool(re.match(r"[A-Za-z]:", path))


def _using_task(
    files: Files, folder: str, element: ET.Element, attrs: dict[str, str], path: str
) -> list[Finding]:
    """A task made from inline code (a <Task> body, as for RoslynCodeTaskFactory,
    or a package file its <Code Source> names), or loaded from an assembly that
    is not MSBuild's own."""
    findings = []
    body = [child for child in element if _local(child.tag) == "task"]
    code = "".join(text for child in body for text in child.itertext())
    sources = [
        unquote(value)
        for child in body
        for item in child.iter()
        if _local(item.tag) == "code"
        for name, value in item.attrib.items()
        if _local(name) == "source"
    ]
    for source in sources:
        targets, problem = _resolve(files, folder, source)
        if problem:
            findings.append(Finding("BKT-SKIP-003", problem, Severity.INFO, path))
        code += "".join(_text(data) for key in targets for _, data in files[key])
    if code.strip() or sources:
        factory = attrs.get("taskfactory", "")[:100]
        message = f"builds a task from inline code at build ({factory})"
        findings.append(Finding("BKT-NUGET-BUILD-003", message, Severity.MEDIUM, path))
        if fetched := _fetches(code):
            message = f"inline task code fetches ({fetched})"
            findings.append(Finding("BKT-NUGET-BUILD-002", message, Severity.HIGH, path))
    assembly = attrs.get("assemblyfile")
    if assembly is not None and not _msbuild_own(assembly):
        message = f"loads a task assembly at build ({assembly.strip()[:100]}): compiled, not read"
        findings.append(Finding("BKT-SKIP-003", message, Severity.INFO, path))
    return findings


def _msbuild_own(path: str) -> bool:
    """A path under one of MSBuild's own folders, the rest written out plainly:
    no properties, items, lists or climbing out."""
    match = _MSBUILD_OWN.match(path)
    if match is None:
        return False
    return not re.search(r"[$@%]\(|;|\.\.", path[match.end() :])


def _resolve(files: Files, folder: str, project: str) -> tuple[list[str], str]:
    """The package files an Import or a Code Source names (a wildcard may name
    several), or why it cannot be followed. A relative path is from the
    importing file's folder."""
    if not project.strip() or _msbuild_own(project):
        return [], ""
    shown = project.strip()[:100]
    here = f"{folder}/" if folder else ""
    joined = _THIS_FOLDER.sub(lambda _: here, project.strip())
    if re.search(r"[$@%]\(", joined):
        return [], f"names a file built from properties ({shown}), which is not read"
    joined = joined.replace("\\", "/")
    if joined.startswith("/") or re.match(r"[A-Za-z]:", joined):
        return [], f"names a file outside the package ({shown}), which is not read"
    if not _THIS_FOLDER.search(project):
        joined = here + joined
    path = _clean(joined)
    if path == ".." or path.startswith("../"):
        return [], f"names a file outside the package ({shown}), which is not read"
    if any(c in path for c in "*?"):
        return [key for key in files if fnmatch.fnmatchcase(key, path)], ""
    if path in files:
        return [path], ""
    if inside := [k for k in files if k.startswith(f"{path}/") and k.endswith(_MSBUILD_FILES)]:
        return inside, ""  # a folder: the MSBuild files in it
    return [], f"names a package file that is not in the package ({shown}), which is not read"


def _check_analyzers(files: Files) -> list[Finding]:
    """A BKT-SKIP-003 for each analyzer or source generator: compiled code the
    compiler loads and runs at every build."""
    message = "an analyzer: compiled code the compiler runs at every build, not read"
    return [
        Finding("BKT-SKIP-003", message, Severity.INFO, path)
        for key, copies in files.items()
        if key.startswith("analyzers/") and key.endswith(".dll")
        for path, _ in copies
    ]
