"""npm tarballs: what package.json makes run on its own, and the JavaScript
that runs on its own: what install scripts run, and what `require` or
`import` of the package runs.

Read from members already in memory (see scan.read_archive). JavaScript is
tokenized (js.py), never run. Each file that runs on its own and cannot be
read is a BKT-SKIP-003; files that do not run on their own (bin commands,
files nothing loads) are not read and do not block a clean verdict.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from typing import Any

from buckthorn import js
from buckthorn.code import FETCHING_COMMAND, channels_in
from buckthorn.findings import Finding, Severity

MAX_MANIFEST_BYTES = 5 * 1024 * 1024  # the same cap as one Python file
# Files that make an archive a Python sdist to pip. `npm pack` never writes them
# at the top of package/, and a real sdist's top folder is name-version, never
# a bare package/.
_PYTHON_BUILD_FILES = ("PKG-INFO", "setup.py", "setup.cfg", "pyproject.toml")

# Scripts npm runs when it installs a tarball. prepare is not one: npm runs it
# for a git dependency or a local install, never for a registry tarball.
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
# A native build and nothing else: node-gyp, or a prebuilt binary for it. Flags
# only (a flag may take one plain word: -r napi), so no URL, path or shell
# syntax; `||` between them is the usual fallback.
_BUILD_TOOLS = frozenset(
    {"node-gyp", "node-gyp-build", "node-gyp-build-optional-packages", "prebuild-install"}
)
_BUILD_COMMAND = re.compile(
    r"(?:node-gyp rebuild|node-gyp-build(?:-optional-packages)?|prebuild-install)"
    r"(?: -[\w.=-]+(?: \w+)?)*"  # one way to split each option, so no exponential backtracking
)
# Tools that build a binding.gyp when they run (prebuild-install and node-pre-gyp
# fall back to it).
_NATIVE_BUILDERS = re.compile(r"\b(?:node-gyp|node-gyp-build|prebuild-install|node-pre-gyp)\b")
# Commands a bin must not quietly take over, unless the package is that tool.
_SHADOWED_COMMANDS = frozenset({"node", "npm", "npx", "git", "ssh", "sh"})
_OWN_COMMANDS = {"npm": {"npm", "npx"}}  # npm ships npx too
# How Node runs each kind of JavaScript file: as an ES module, as a script, or
# (a .js file, or one with another extension, by the nearest package.json
# "type" and, since Node 22, by its syntax) either way.
_JS_MODULE = {".mjs": True, ".cjs": False, ".js": None}
# JavaScript read from one package, in all. The most in the top 1,000
# packages on 2026-11-12 was 12.6 MB (webpack), counting every file.
MAX_JS_BYTES = 32 * 1024 * 1024


def shape(members: list[tuple[str, bytes]], tgz: bool) -> str:
    """npm, sdist or ambiguous, by content. tgz: the file name ends .tgz.

    npm unpacks a tarball by stripping the first folder of every member,
    whatever its name; `npm pack` calls it package/. So a tar is npm when one
    top folder holds everything and a package.json. It is ambiguous, for the
    caller to read both ways, when npm would drop or merge members (more than
    one top folder, a file at the top, an absolute name), or when Python build
    files sit beside the package.json and the top folder is package/ or the
    name ends .tgz: pip would read it as an sdist, npm as a package. A Python
    sdist that ships a package.json (a JupyterLab extension) has a
    name-version top folder and a .tar.gz name.
    """
    names = {posixpath.normpath(name) for name, _ in members}
    if not any(posixpath.basename(n) == "package.json" and _depth(n) == 1 for n in names):
        return "sdist"
    tops = {name.split("/")[0] for name in names}
    if len(tops) != 1 or "" in tops or any("/" not in name for name in names):
        return "ambiguous"
    top = tops.pop()
    lower = {name.lower() for name in names}  # Setup.py is setup.py on a case-insensitive disk
    if any(f"{top}/{name}".lower() in lower for name in _PYTHON_BUILD_FILES):
        return "ambiguous" if top == "package" or tgz else "sdist"
    return "npm"


def _depth(name: str) -> int:
    return name.lstrip("/").count("/")


def scan_npm(stem: str, members: list[tuple[str, bytes]], read: list[Finding]) -> list[Finding]:
    """Findings for a tar holding an npm package.json (see shape). stem is its
    file name without the suffix; read holds the coverage findings from
    reading the archive."""
    # Paths as npm unpacks them: first folder stripped, a file with none dropped,
    # last copy wins.
    files, tops = {}, {}
    for name, data in members:
        top, sep, rest = posixpath.normpath(name).lstrip("/").partition("/")
        if sep:
            files[rest], tops[rest] = data, top
    path = f"{tops['package.json']}/package.json"
    findings = list(read)
    manifest, problem = _load(files["package.json"])
    if manifest is None:
        message = "package.json cannot be read, so what it runs and names is unknown"
        return findings + [
            Finding("BKT-SKIP-003", problem, Severity.INFO, path),
            Finding("BKT-NPM-META-001", message, Severity.MEDIUM, path),
        ]
    name = manifest.get("name")
    name = name if isinstance(name, str) else ""
    bins, found = _bin_commands(manifest, name, files)
    commands = [command for command, _ in bins]
    # sh runs a command file with no #! line as a shell script, and a JSON
    # string can hold $(...): package.json as a command is code, not read as such.
    if any(posixpath.normpath(target) == "package.json" for _, target in bins):
        message = "package.json is installed as a command, so it can run as a shell script"
        findings.append(Finding("BKT-SKIP-003", message, Severity.INFO, path))
    found += _check_name(stem, manifest.get("name"), manifest.get("version"))
    found += _check_scripts(manifest, files, commands)
    found += _check_bin(commands, name)
    found += _check_channels(manifest)
    for finding in found:  # every check reads package.json
        finding.file_path = path
    package = _Package(files, tops, manifest)
    package.install()
    package.load()
    return findings + found + package.findings()


def _load(data: bytes) -> tuple[dict[str, Any] | None, str]:
    if len(data) > MAX_MANIFEST_BYTES:
        return None, f"package.json is over {MAX_MANIFEST_BYTES} bytes, not parsed"
    try:
        manifest = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return None, f"could not parse package.json: {type(exc).__name__}"
    if not isinstance(manifest, dict):
        return None, "package.json is not a JSON object"
    return manifest, ""


def _check_name(stem: str, name: Any, version: Any) -> list[Finding]:
    """BKT-NPM-META-001 when name and version do not give the file name.

    The registry names @scope/pkg's tarball pkg-1.0.0.tgz; `npm pack` names it
    scope-pkg-1.0.0.tgz. npm cleans a leading v or = off the version.
    """
    if isinstance(name, str) and isinstance(version, str):
        version = version.strip().lstrip("=v")
        scope, _, base = name.rpartition("/")
        names = {base, f"{scope.lstrip('@')}-{base}"} if scope else {name}
        if stem in {f"{n}-{version}" for n in names}:
            return []
    # Cut short: these come from the package, so they can be any size.
    message = f"package.json says {str(name)[:100]} {str(version)[:100]}, file name says {stem}"
    return [Finding("BKT-NPM-META-001", message, Severity.MEDIUM, "package.json")]


def _check_scripts(
    manifest: dict[str, Any], files: dict[str, bytes], commands: list[str]
) -> list[Finding]:
    """BKT-NPM-SCRIPT-001 for scripts that run at install, BKT-NPM-INSTALL-001
    for those that fetch. Fields of the wrong type are not read: BKT-SKIP-003."""
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        return [Finding("BKT-SKIP-003", "scripts is not an object", Severity.INFO, "package.json")]
    # A build tool the package ships itself (bundled, or its own bin of that
    # name) is the package's code, not a known build.
    own_tools = bool(set(commands) & _BUILD_TOOLS) or any(
        name.startswith("node_modules/") for name in files
    )
    findings = []
    for script in (*_INSTALL_SCRIPTS, "prepare"):
        command = scripts.get(script)
        if command is None:
            continue
        if not isinstance(command, str):
            message = f"scripts.{script} is not a string"
            findings.append(Finding("BKT-SKIP-003", message, Severity.INFO, "package.json"))
            continue
        if not command.strip():
            continue  # npm runs nothing for an empty script
        where = {"script": script}
        if script == "prepare":
            message = "prepare script runs for a git dependency or a local install, not from here"
            findings.append(
                Finding("BKT-NPM-SCRIPT-001", message, Severity.INFO, "package.json", where)
            )
            continue
        build = not own_tools and all(
            _BUILD_COMMAND.fullmatch(" ".join(part.split())) for part in command.split("||")
        )
        message = f"{script} script runs at install" + (" (a native build)" if build else "")
        severity = Severity.INFO if build else Severity.MEDIUM
        findings.append(Finding("BKT-NPM-SCRIPT-001", message, severity, "package.json", where))
        if match := FETCHING_COMMAND.search(command):
            message = f"{script} script runs a command that fetches ({match.group(0)})"
            findings.append(
                Finding("BKT-NPM-INSTALL-001", message, Severity.HIGH, "package.json", where)
            )
        if "binding.gyp" in files and _NATIVE_BUILDERS.search(command):
            findings.append(_native_build(where))
    # npm adds `node-gyp rebuild` as the install script for a binding.gyp.
    if "binding.gyp" in files and not (scripts.get("install") or scripts.get("preinstall")):
        if manifest.get("gypfile") is not False:
            message = "binding.gyp with no install script: npm runs node-gyp rebuild at install"
            findings.append(Finding("BKT-NPM-SCRIPT-001", message, Severity.INFO, "package.json"))
            findings.append(_native_build({}))
    return findings


def _native_build(where: dict[str, str]) -> Finding:
    """A build from binding.gyp runs at install: gyp can run commands
    (`<!(cmd)`), and what it compiles runs native. Neither is read."""
    message = "a native build runs at install: binding.gyp and the code it compiles are not read"
    return Finding("BKT-SKIP-003", message, Severity.INFO, "package.json", dict(where))


def _bin_commands(
    manifest: dict[str, Any], name: str, files: dict[str, bytes]
) -> tuple[list[tuple[str, str]], list[Finding]]:
    """(command, file it runs) for each command the package installs. Commands
    are lower case, as npm names them: the base name only, so ../sh and lib\\sh
    install as sh. Or a BKT-SKIP-003."""
    bin_ = manifest.get("bin")
    directories = manifest.get("directories", {})
    if isinstance(bin_, str):
        bins = [(name.rpartition("/")[2], bin_)]  # named after the package
    elif isinstance(bin_, dict):
        bins = [
            (command, target if isinstance(target, str) else "") for command, target in bin_.items()
        ]
    elif bin_ is None and isinstance(directories, dict) and "bin" in directories:
        # Every file under directories.bin is a command named after the file.
        folder = directories["bin"]
        if not isinstance(folder, str):
            message = "directories.bin is not a string"
            return [], [Finding("BKT-SKIP-003", message, Severity.INFO, "package.json")]
        folder = posixpath.normpath(folder) if folder else ""  # npm skips an empty one
        prefix = "" if folder == "." else f"{folder}/"
        bins = [(f, f) for f in files if f.startswith(prefix)] if folder else []
    elif bin_ is None:
        return [], []
    else:
        message = "bin is not a string or object"
        return [], [Finding("BKT-SKIP-003", message, Severity.INFO, "package.json")]
    return [(posixpath.basename(re.sub(r"[\\:]", "/", c)).lower(), t) for c, t in bins], []


def _check_bin(commands: list[str], name: str) -> list[Finding]:
    """BKT-NPM-BIN-001 for a command named like a common tool, unless the package is it."""
    findings = []
    for command in commands:
        if command in _SHADOWED_COMMANDS and command not in _OWN_COMMANDS.get(name, {name}):
            message = f"installs a command named {command}, shadowing it"
            findings.append(Finding("BKT-NPM-BIN-001", message, Severity.HIGH, "package.json"))
    return findings


def _check_channels(manifest: dict[str, Any]) -> list[Finding]:
    """BKT-EXFIL-001/002 for a messenger channel in any key or string value."""
    rules = {"discord": "BKT-EXFIL-001", "telegram": "BKT-EXFIL-002"}
    found: dict[str, str] = {}
    todo: list[Any] = [manifest]
    while todo:  # a loop, not recursion: JSON can nest as deep as the parser allows
        value = todo.pop()
        if isinstance(value, dict):
            todo += [*value, *value.values()]
        elif isinstance(value, list):
            todo += value
        elif isinstance(value, str):
            for kind, detail in channels_in(value):
                found.setdefault(kind, detail)
    return [
        Finding(rules[kind], detail, Severity.MEDIUM, "package.json")
        for kind, detail in found.items()
    ]


# Kind of code hit -> rule and severity, by when the code runs. The same
# meanings as the Python INSTALL and IMPORT rules (scan._CODE_RULES).
_CODE_RULES = {
    "INSTALL": {
        "network": ("BKT-NPM-INSTALL-001", Severity.HIGH),
        "process": ("BKT-NPM-INSTALL-002", Severity.MEDIUM),
        "exec": ("BKT-NPM-INSTALL-003", Severity.MEDIUM),
        "secrets": ("BKT-NPM-INSTALL-004", Severity.HIGH),
        "persistence": ("BKT-NPM-INSTALL-005", Severity.HIGH),
        "environ": ("BKT-NPM-INSTALL-006", Severity.INFO),
    },
    "IMPORT": {
        "network": ("BKT-NPM-IMPORT-001", Severity.HIGH),
        "process": ("BKT-NPM-IMPORT-002", Severity.MEDIUM),
        "exec": ("BKT-NPM-IMPORT-003", Severity.MEDIUM),
        "secrets": ("BKT-NPM-IMPORT-004", Severity.HIGH),
        "persistence": ("BKT-NPM-IMPORT-005", Severity.HIGH),
        "environ": ("BKT-NPM-IMPORT-006", Severity.INFO),
    },
}
_CRITICAL = {"INSTALL": "BKT-NPM-INSTALL-008", "IMPORT": "BKT-NPM-IMPORT-008"}
_ANYWHERE_RULES = {
    "hidden": ("BKT-NPM-HIDE-001", Severity.HIGH),
    "encoded": ("BKT-NPM-HIDE-002", Severity.LOW),
    "discord": ("BKT-EXFIL-001", Severity.MEDIUM),
    "telegram": ("BKT-EXFIL-002", Severity.MEDIUM),
}
# exports conditions no runtime loads code from.
_TYPE_CONDITIONS = frozenset({"types", "typings"})
# TypeScript and its declarations: Node does not strip types inside node_modules.
_TYPESCRIPT = (".ts", ".mts", ".cts")
# Conditions under which Node itself loads an exports target (None: no condition).
_RUNTIME_CONDITIONS = frozenset({None, "require", "import", "node", "default", "module-sync"})
_MAX_SCRIPT_DEPTH = 32  # npm run inside npm run, as deep as is followed
_WHEN = {"INSTALL": "at install", "IMPORT": "at load"}
# Shell words that end one command and start the next.
_OPERATORS = frozenset({"&&", "||", ";", "|", "&", "(", ")", ";;", "|&"})
_NODE_VALUE_OPTIONS = frozenset(
    {"-r", "--require", "--import", "--loader", "--experimental-loader", "-e", "--eval"}
    | {"-p", "--print", "-C", "--conditions", "--input-type", "--title", "--env-file"}
)
_NODE_PRELOADS = frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash"})
# Programs that run a file named on their command line.
_INTERPRETERS = _SHELLS | frozenset(
    {"python", "python3", "perl", "ruby", "php", "pwsh", "powershell", "bun", "deno"}
    | {"ts-node", "tsx"}
)
_JS_EXTENSIONS = (".js", ".cjs", ".mjs")


class _Package:
    """The files of one npm package, as npm unpacks them, read for the
    JavaScript that runs on its own. Paths are relative to the package
    folder; tops gives each one's top folder in the tarball, for findings."""

    def __init__(
        self, files: dict[str, bytes], tops: dict[str, str], manifest: dict[str, Any]
    ) -> None:
        self.files, self.tops, self.manifest = files, tops, manifest
        name = manifest.get("name")
        self.name = name if isinstance(name, str) else ""
        self._manifests: dict[str, dict[str, Any]] = {"package.json": manifest}
        self._tokens: dict[str, list[js.Token] | None] = {}
        self.tokenized = 0  # bytes of JavaScript tokenized, for MAX_JS_BYTES
        self.spent = 0  # bytes read, counting each re-read
        code = sum(len(d) for p, d in files.items() if p.endswith(_JS_EXTENSIONS))
        self.budget = 10 * max(code, 1 << 20)  # as for Python: ten times the source
        self.notes: list[Finding] = []  # coverage
        self.found: list[Finding] = []
        self.read: dict[str, tuple[str, js.Analysis]] = {}  # file -> (when, analysis)
        self.folders = set()
        # Files by their name in lower case: npm installs onto case-insensitive
        # disks too, where INDEX.JS is index.js and one replaces the other.
        self.cases: dict[str, list[str]] = {}
        for path in files:
            self.cases.setdefault(path.lower(), []).append(path)
            while path := posixpath.dirname(path):
                self.folders.add(path)

    def find(self, path: str) -> str | None:
        """The file a path names, in any case (the last one, which a
        case-insensitive disk keeps), or None."""
        found = self.cases.get(path.lower())
        return found[-1] if found else None

    def at(self, path: str) -> str:
        return f"{self.tops.get(path, self.tops['package.json'])}/{path}"

    def note(self, message: str, path: str) -> None:
        self.notes.append(Finding("BKT-SKIP-003", message, Severity.INFO, self.at(path)))

    # Install scripts.

    def install(self) -> None:
        """Read the JavaScript the install scripts run: each file whole, as
        setup.py is read, and the local files it loads at top level."""
        scripts = self.manifest.get("scripts")
        if not isinstance(scripts, dict):
            return
        roots: dict[str, tuple[bool, dict[str, str]]] = {}
        for script in _INSTALL_SCRIPTS:
            command = scripts.get(script)
            if not isinstance(command, str) or not command.strip():
                continue
            for kind, value, cwd in self._runs(scripts, command, {script}):
                if kind == "file":
                    roots[value] = (True, {})
                elif kind == "unread":
                    self.note(f"{script} script runs {value}, which is not read", "package.json")
                elif kind == "fetch":
                    message = f"{script} script runs a script that fetches ({value})"
                    where = {"script": script}
                    self.found.append(
                        Finding(
                            "BKT-NPM-INSTALL-001",
                            message,
                            Severity.HIGH,
                            self.at("package.json"),
                            where,
                        )
                    )
                else:
                    self._inline(script, value, cwd, roots)
        self._read(roots, "INSTALL", set())

    def _inline(
        self, script: str, code: str, cwd: str, roots: dict[str, tuple[bool, dict[str, str]]]
    ) -> None:
        """`node -e CODE`: read the code whole, and queue what it loads."""
        try:
            analysis = js.analyse(js.tokenize(code, False), True)
        except js.JSError as exc:
            message = f"{script} script's inline code does not tokenize ({exc.kind})"
            self.note(message, "package.json")
            return
        for finding in _code_findings("INSTALL", self.at("package.json"), analysis):
            finding.metadata["script"] = script
            finding.metadata.pop("lines", None)  # lines of the inline code, not of package.json
            self.found.append(finding)
        how = f"called at install by the {script} script"
        for spec, names in analysis.loads.items():
            for target in self.resolve(spec, cwd):
                whole, entry = roots.get(target, (False, {}))
                roots[target] = (whole, {**{n: how for n in names}, **entry})

    def _runs(
        self, scripts: dict[str, Any], command: str, seen: set[str], depth: int = 0
    ) -> list[tuple[str, str, str]]:
        """What a script command runs, as (kind, value, folder): ("file",
        path) for JavaScript run whole, ("code", source) for node -e, ("unread",
        what) for code that is not read, ("fetch", what) for a script it runs
        through npm run that fetches. seen: scripts already followed, each
        once."""
        if depth > _MAX_SCRIPT_DEPTH:
            return [("unread", "scripts that run each other too deep to follow", "")]
        # $(cmd) splits on its brackets; `cmd` is made to split the same way.
        try:
            lexer = shlex.shlex(command.replace("`", " ; "), posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            words = list(lexer)
        except ValueError:
            return [("unread", "a command line that does not parse", "")]
        runs: list[tuple[str, str, str]] = []
        cwd: str | None = ""
        argv: list[str] = []
        redirect = False
        for word in [*words, ";"]:
            if redirect:
                redirect = False
            elif word in _OPERATORS:
                if argv and cwd is not None:
                    cwd = self._command(argv, cwd, scripts, seen, runs, depth)
                argv = []
            elif word[0] in "<>":
                redirect = True
            else:
                argv.append(word)
        return runs

    def _command(
        self,
        argv: list[str],
        cwd: str,
        scripts: dict[str, Any],
        seen: set[str],
        runs: list[tuple[str, str, str]],
        depth: int,
    ) -> str | None:
        """Add what one simple command runs; returns the folder after it."""
        while argv and (re.fullmatch(r"\w+=.*", argv[0]) or argv[0] in ("env", "cross-env")):
            argv = argv[1:]
        if not argv:
            return cwd
        program, args = posixpath.basename(argv[0]), argv[1:]
        if program == "cd":
            folder = self._local(cwd, args[0]) if args else ""
            if folder is None:
                runs.append(("unread", "commands in a folder outside the package", cwd))
            return folder
        if program in ("node", "nodejs", "node.exe"):
            self._node(args, cwd, runs)
        elif program in ("npm", "yarn", "pnpm") and args:
            name = args[1] if args[0] in ("run", "run-script") and len(args) > 1 else args[0]
            names = [f"pre{name}", name, f"post{name}"] if program == "npm" else [name]
            for name in names:
                command = scripts.get(name)
                if isinstance(command, str) and name not in seen:
                    seen.add(name)  # once each, so scripts that fan out stay linear
                    if match := FETCHING_COMMAND.search(command):
                        runs.append(("fetch", match.group(0), cwd))
                    runs += self._runs(scripts, command, seen, depth + 1)
        elif program in ("node-gyp-build", "node-gyp-build-optional-packages"):
            # Unless building from source, it tests the package's own prebuilt
            # addon at install: require of package.json prebuild.test, else
            # loading build/Release or prebuilds/*.node.
            prebuild = self.manifest.get("prebuild")
            test = prebuild.get("test") if isinstance(prebuild, dict) else None
            if isinstance(test, str) and (found := self._file(self._local(cwd, test))):
                runs.append(("file", found, cwd))
            if any(p.endswith(".node") for p in self.files):
                runs.append(("unread", f"{program}, which loads a shipped native addon", cwd))
        elif program in _SHELLS and len(args) > 1 and args[0] == "-c":
            runs += self._runs(scripts, args[1], seen, depth + 1)
        elif program in _INTERPRETERS:
            named = [a for a in args if not a.startswith("-")]
            self._run_file(self._local(cwd, named[0]) if named else None, cwd, runs)
        elif "/" in argv[0] or argv[0].startswith("."):
            self._run_file(self._local(cwd, argv[0]), cwd, runs)
        return cwd

    def _node(self, args: list[str], cwd: str, runs: list[tuple[str, str, str]]) -> None:
        """node [options] [file]: the file, -e code and -r preloads."""
        i, code = 0, None
        while i < len(args) and args[i].startswith("-") and args[i] != "-":
            option, eq, value = args[i].partition("=")
            i += 1
            if option == "--":
                break
            if option in _NODE_VALUE_OPTIONS and not eq:
                value = args[i] if i < len(args) else ""
                i += 1
            if option in ("-e", "--eval", "-p", "--print"):
                code = value
            elif option in _NODE_PRELOADS:
                runs += [("file", target, cwd) for target in self.resolve(value, cwd)]
        if code is not None:
            runs.append(("code", code, cwd))
        elif i < len(args):
            target = self._file(self._local(cwd, args[i]))
            if target:
                runs.append(("file", target, cwd))

    def _run_file(self, path: str | None, cwd: str, runs: list[tuple[str, str, str]]) -> None:
        """A file run by name: JavaScript is read, anything else is not."""
        path = self.find(path) if path is not None else None
        if path is None:
            return
        first = self.files[path][:200].split(b"\n", 1)[0]
        if path.endswith(_JS_EXTENSIONS) or (first.startswith(b"#!") and b"node" in first):
            runs.append(("file", path, cwd))
        else:
            runs.append(("unread", self.at(path), cwd))

    # require and import.

    def load(self) -> None:
        """Read the code that runs when the package is loaded: the entry
        files' top level, and the local files it loads, following the
        functions called in them. Files read as install code are not read
        again."""
        roots: dict[str, tuple[bool, dict[str, str]]] = {}
        for path in self.entries():
            if path.endswith(".node"):
                self.note("an entry file is a native addon: not read", path)
            elif not path.endswith(".json") and path not in self.read:
                roots[path] = (False, {})
        self._read(roots, "IMPORT", set(self.read))

    def entries(self) -> list[str]:
        """Files `require` or `import` of the package loads: main, every
        exports target (under any condition but types, a * pattern matching
        each JavaScript file that fits), else index.js."""
        found = []
        exports = self.manifest.get("exports")
        for key, value in _table(exports, True).items():
            for condition, target in _leaves(value):
                if target.startswith("./"):
                    entry = key == "." and condition in _RUNTIME_CONDITIONS
                    found += self._exported(target, entry)
        main = self.manifest.get("main")
        if (isinstance(main, str) and main) or exports is None:
            if path := self._file(""):
                found.append(path)
        return sorted(set(found))

    def _exported(self, target: str, entry: bool) -> list[str]:
        """Files an exports target names: one path, or for a * pattern every
        JavaScript file that fits it. A path is JavaScript, extensionless or
        a .node addon; the package's own entry under a condition Node uses
        is read whatever its extension, since require runs it as JavaScript.
        TypeScript never runs from a package: Node does not strip its types
        inside node_modules."""
        if "*" not in target:
            path = self.find(self._local("", target) or "")
            if path is None or path.lower().endswith(_TYPESCRIPT):
                return []
            name = posixpath.basename(path).lower()
            if entry or name.endswith((*_JS_EXTENSIONS, ".node")) or "." not in name:
                return [path]
            return []
        return [p for p in self.files if p.endswith(_JS_EXTENSIONS) and _fits(p, target[2:])]

    # Where a name leads, as Node resolves it.

    def _local(self, folder: str, spec: str) -> str | None:
        """spec joined onto folder, inside the package; None when it leaves it."""
        if spec.startswith("/") or re.match(r"[A-Za-z]:", spec):
            return None
        path = posixpath.normpath(posixpath.join(folder, spec))
        if path == "..":
            return None
        return "" if path == "." else None if path.startswith("../") else path

    def _file(self, path: str | None, depth: int = 0) -> str | None:
        """The file require loads for a path: as is, with .js, .json or .node
        added, or a folder's package.json main or index file."""
        if path is None:
            return None
        if path:
            for candidate in (path, f"{path}.js", f"{path}.json", f"{path}.node"):
                if found := self.find(candidate):
                    return found
        folder = f"{path}/" if path else ""
        main = self.manifest_at(self.find(f"{folder}package.json") or "").get("main")
        # One package.json only: a folder main names gives its index file,
        # never its own package.json's main (Node's tryPackage).
        if isinstance(main, str) and main and not depth:
            if found := self._file(self._local(path, main), depth + 1):
                return found
        for index in ("index.js", "index.json", "index.node"):
            if found := self.find(f"{folder}{index}"):
                return found
        return None

    def manifest_at(self, path: str) -> dict[str, Any]:
        """A package.json in the package, parsed ({} if it is not one)."""
        if path not in self._manifests:
            data = self.files.get(path)
            loaded = _load(data)[0] if data is not None else None
            self._manifests[path] = loaded or {}
        return self._manifests[path]

    def resolve(self, spec: str, folder: str) -> list[str]:
        """Files of this package a load from folder may run: a path, an
        `imports` name (#x), the package's own name, or a package bundled
        under node_modules. Empty for a builtin or another package."""
        spec = js.unprefixed(spec)
        if spec in (".", "..") or spec.startswith(("./", "../", "/")):
            found = self._file(self._local(folder, spec))
            return [found] if found else []
        if js.is_builtin(spec) or not spec:
            return []
        if spec.startswith("#"):
            root = folder
            while root and f"{root}/package.json" not in self.files:
                root = posixpath.dirname(root)
            imports = self.manifest_at(f"{root}/package.json" if root else "package.json")
            found = []
            for target in _targets(imports.get("imports"), spec, False):
                if target.startswith("./"):
                    path = self._local(root, target)
                    found += [p] if path is not None and (p := self.find(path)) else []
                elif not target.startswith("#"):
                    found += self.resolve(target, root)
            return found
        parts = spec.split("/")
        size = 2 if spec.startswith("@") else 1
        name, sub = "/".join(parts[:size]), "/".join(parts[size:])
        if name == self.name and "exports" in self.manifest:
            return self._entry("", sub)
        while True:  # node_modules in this folder and each one above it
            root = posixpath.join(folder, "node_modules", name)
            if root in self.folders:
                return self._entry(root, sub)
            if not folder:
                return []
            folder = posixpath.dirname(folder)

    def _entry(self, root: str, sub: str) -> list[str]:
        """The files a package at root gives for a subpath ("" for the package)."""
        manifest = self.manifest_at(f"{root}/package.json" if root else "package.json")
        if "exports" in manifest:
            subpath = f"./{sub}" if sub else "."
            found = [self._local(root, t) for t in _targets(manifest["exports"], subpath, True)]
            return [p for f in found if f is not None and (p := self.find(f))]
        found = self._file(self._local(root, sub or "."))
        return [found] if found else []

    # Reading.

    def tokens(self, path: str) -> list[js.Token] | None:
        """A file's tokens, read the way Node runs it; None (with a coverage
        note) when it cannot be read."""
        if path in self._tokens:
            return self._tokens[path]
        data = self.files[path]
        self.tokenized += len(data)
        found = None
        if self.tokenized > MAX_JS_BYTES:
            self.note(f"JavaScript past {MAX_JS_BYTES} bytes in all is not read", path)
        else:
            try:
                found = self._tokenize(path, data)
            except js.JSError as exc:
                self.note(f"JavaScript does not tokenize ({exc.kind} at line {exc.line})", path)
        self._tokens[path] = found
        return found

    def _tokenize(self, path: str, data: bytes) -> list[js.Token]:
        """`<!--` and a `-->` at a line start are comments in a script and code
        in a module. A .js file is a module by the nearest package.json's
        "type"; with none, Node runs it as one if it has import or export."""
        module = _JS_MODULE.get(posixpath.splitext(path)[1].lower())
        if module is None:
            folder = posixpath.dirname(path)
            while True:
                manifest = self.manifest_at(f"{folder}/package.json" if folder else "package.json")
                if f"{folder}/package.json" in self.files or not folder:
                    kind = manifest.get("type")
                    module = True if kind == "module" else False if kind == "commonjs" else None
                    break
                folder = posixpath.dirname(folder)
        try:
            return js.tokenize(data, module)
        except js.JSError as exc:
            if exc.kind != "html-comment":
                raise
        script = js.tokenize(data, False)
        if _has_module_syntax(script):
            return js.tokenize(data, True)
        # Node has more ways to call a file a module than are checked here (a
        # top-level `const require`, an await in a block): if it also reads as
        # one, which reading runs is not known, so fail closed.
        try:
            js.tokenize(data, True)
        except js.JSError:
            return script
        message = "has HTML-like comments, which are code if Node runs it as a module: not all read"
        self.note(message, path)
        return script

    def _read(
        self, roots: dict[str, tuple[bool, dict[str, str]]], when: str, skip: set[str]
    ) -> None:
        """Read each root (whole, or its top level and the functions named in
        its entry) and the local files code that runs loads, following the
        functions it calls in them. skip: files already read."""
        state = dict(roots)
        todo = list(roots)
        while todo:
            path = todo.pop()
            if path in todo:
                continue  # queued again since: read it once, with all its names
            whole, entry = state[path]
            tokens = self.tokens(path)
            if tokens is None:
                continue
            self.spent += len(self.files[path])
            if self.spent > self.budget:
                self.note("modules call each other too much to follow every call", path)
                return
            analysis = js.analyse(tokens, whole, entry)
            self.read[path] = (when, analysis)
            how = f"called {_WHEN[when]} by {self.at(path)}"
            for spec, names in analysis.loads.items():
                targets = self.resolve(spec, posixpath.dirname(path))
                if not targets and spec.startswith((".", "/")):
                    # Made or fetched at install (a built addon), or not there at all.
                    message = "loads a local file the package does not ship, so it is not read"
                    self.note(message, path)
                for target in targets:
                    if target in skip or target.endswith(".json"):
                        continue
                    if target.endswith(".node"):
                        self.note("a native addon loaded by code that runs: not read", target)
                        skip.add(target)
                        continue
                    whole_, known = state.get(target, (False, {}))
                    added = {n: how for n in names if n not in known}
                    if target not in state or added:
                        state[target] = (whole_, {**known, **added})
                        todo.append(target)

    def findings(self) -> list[Finding]:
        found = list(self.found)
        for path, (when, analysis) in self.read.items():
            found += _code_findings(when, self.at(path), analysis)
            if analysis.crowded:
                self.note("a name is bound too many ways to follow every call", path)
            if analysis.dynamic:
                lines = ", ".join(str(n) for n in sorted(set(analysis.dynamic))[:10])
                message = f"loads a module named at run time (line {lines}), which is not read"
                self.note(message, path)
            if len(self.cases[path.lower()]) > 1:
                message = (
                    "files differ only in case: on a case-insensitive disk one replaces another"
                )
                self.note(message, path)
        seen = set()
        notes = []
        for note in self.notes:  # once each
            if (note.message, note.file_path) not in seen:
                seen.add((note.message, note.file_path))
                notes.append(note)
        return found + notes


def _code_findings(when: str, path: str, analysis: js.Analysis) -> list[Finding]:
    """One finding per kind of hit, with every line it was seen on."""
    by_kind: dict[str, list] = {}
    for hit in analysis.hits:
        by_kind.setdefault(hit.kind, []).append(hit)
    findings = []
    for kind, hits in by_kind.items():
        details = "; ".join(sorted({h.detail for h in hits}))
        lines = {"lines": [h.line for h in hits]}
        if kind == "native":
            message = f"{details}: native code, not read"
            findings.append(Finding("BKT-SKIP-003", message, Severity.INFO, path, lines))
            continue
        if kind in _ANYWHERE_RULES:  # wherever it is in the file, run or not
            rule, severity = _ANYWHERE_RULES[kind]
            findings.append(Finding(rule, details, severity, path, lines))
            continue
        rule, severity = _CODE_RULES[when][kind]
        message = f"runs {_WHEN[when]}: {details}"
        findings.append(Finding(rule, message, severity, path, lines))
    if "network" in by_kind and ("secrets" in by_kind or "environ" in by_kind):
        message = f"reads credentials or the whole environment and uses the network {_WHEN[when]}"
        findings.append(Finding(_CRITICAL[when], message, Severity.CRITICAL, path))
    return findings


def _has_module_syntax(tokens: list[js.Token]) -> bool:
    """What makes Node 22 run a .js with no "type" as a module: a top-level
    import or export statement, import.meta, or a top-level await."""
    for i, t in enumerate(tokens):
        if t.kind != "name" or t.value not in ("import", "export", "await"):
            continue
        if i and tokens[i - 1].kind == "punct" and tokens[i - 1].value in (".", "?."):
            continue
        after = tokens[i + 1] if i + 1 < len(tokens) else None
        dot = after is not None and after.kind == "punct" and after.value == "."
        if t.value == "import" and dot and i + 2 < len(tokens) and tokens[i + 2].value == "meta":
            return True
        if t.depth or after is None or (after.kind == "punct" and after.value in ("(", ".")):
            continue
        return True
    return False


def _fits(path: str, pattern: str) -> bool:
    """Whether path fits an exports target pattern, every * standing for the
    same text (as Node fills them). String work, no regex to backtrack."""
    parts = pattern.split("*")
    fixed, stars = sum(map(len, parts)), len(parts) - 1
    if len(path) <= fixed or (len(path) - fixed) % stars:
        return False
    size = (len(path) - fixed) // stars
    star = path[len(parts[0]) : len(parts[0]) + size]
    return star.join(parts) == path


def _table(table: Any, exports: bool) -> dict[str, Any]:
    """An exports (or imports) field as {subpath: targets}: a bare target or
    a conditions object is the package's own "."."""
    if exports and (
        isinstance(table, str | list)
        or (isinstance(table, dict) and not any(str(k).startswith(".") for k in table))
    ):
        table = {".": table}
    return table if isinstance(table, dict) else {}


def _targets(table: Any, key: str, exports: bool) -> list[str]:
    """The paths an `exports` (or `imports`) table gives for a key, under any
    condition but types, with a * pattern filled in. TypeScript is left out."""
    found = []
    for pattern, value in _table(table, exports).items():
        if pattern == key:
            found += [t for _, t in _leaves(value)]
        elif isinstance(pattern, str) and pattern.count("*") == 1:
            before, _, after = pattern.partition("*")
            if key.startswith(before) and key.endswith(after) and len(key) > len(pattern) - 1:
                star = key[len(before) : len(key) - len(after)]
                found += [t.replace("*", star) for _, t in _leaves(value)]
    return [t for t in found if not t.lower().endswith(_TYPESCRIPT)]


def _leaves(value: Any) -> list[tuple[str | None, str]]:
    """Every path in a conditions object or a list of fallbacks, with the
    condition it is under (None for none), types conditions left out."""
    found: list[tuple[str | None, str]] = []
    todo: list[tuple[str | None, Any]] = [(None, value)]
    while todo:  # a loop, not recursion: conditions nest as deep as JSON does
        condition, item = todo.pop()
        if isinstance(item, str):
            found.append((condition, item))
        elif isinstance(item, dict):
            todo += [(k, v) for k, v in item.items() if k not in _TYPE_CONDITIONS]
        elif isinstance(item, list):
            todo += [(condition, v) for v in item]
    return found
