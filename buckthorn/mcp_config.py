"""Check an agent's MCP config: every server it launches, and the PyPI packages behind it.

Reads the `mcpServers` table of Claude Code (`.mcp.json`, `~/.claude.json` and its
per-project tables), Claude Desktop, Cursor and Windsurf, and the `servers` table
of VS Code's `mcp.json` (comments and trailing commas allowed). Each server's
launch is classified; a `uvx`, `uv tool run`, `uv run --with` or `pipx run`
launch has its package, and every package that launcher would install with it,
fetched from PyPI, hash-checked and scanned by `lock.scan_release`, exactly as
`buckthorn check` does for a lockfile pin.

The dependency set is resolved from static metadata only: the `requires_dist`
PyPI publishes for a release, or the `Requires-Dist` headers in the wheel or
sdist when it does not. Nothing is installed, built, imported or executed.

Configs hold credentials in `env`, in arguments and in URLs. Nothing from a
server entry is ever put in a finding except its config key and a package name
that parsed as one. Option values, environment values, URLs and paths are not.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
import tempfile
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from email.parser import HeaderParser
from pathlib import Path

from packaging.markers import UndefinedComparison, UndefinedEnvironmentName, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from buckthorn import lock
from buckthorn.code import PIPE_TO_SHELL
from buckthorn.findings import Finding, Result, Severity
from buckthorn.scan import ARTIFACT_SUFFIXES, read_archive

# Launcher options that take a value (uvx, uv run, uv tool run, pipx run). An option
# in neither set stops the check: guessing could take its value for the package.
_VALUE_OPTIONS = frozenset(
    "--from --with -w --with-editable --with-requirements --with-executables-from --python -p "
    "--index --index-url -i --extra-index-url --default-index --find-links -f --directory "
    "--project --cache-dir --config-file --env-file --spec --pip-args --constraints -c "
    "--overrides --build-constraints -b --python-platform --index-strategy --keyring-provider "
    "--resolution --prerelease --exclude-newer --link-mode --refresh-package --reinstall-package "
    "--upgrade-package -P --no-build-package --no-binary-package --color --allow-insecure-host "
    "--group --extra --package --only-group --no-group --config-setting -C --backend".split()
)
_FLAG_OPTIONS = frozenset(
    "-q --quiet -v --verbose -n --no-cache --isolated --offline --refresh -U --upgrade "
    "--reinstall --no-config --native-tls --no-progress --no-python-downloads --managed-python "
    "--no-managed-python --no-project --frozen --locked --no-sync --all-extras --no-dev "
    "--compile-bytecode --no-build-isolation --no-build --no-binary --no-sources --no-env-file "
    "--active --no-editable --exact --system-site-packages --pre -m --module --script -s "
    "--preview --pypackages --fetch-missing-python --no-index".split()
)
# Options and environment variables that make the launcher install from somewhere
# other than PyPI, or pick other versions than the newest the spec allows.
_SOURCE_OPTIONS = frozenset(
    "--index --index-url -i --extra-index-url --default-index --find-links -f --no-index "
    "--with-editable --with-requirements --pip-args --constraints -c --overrides "
    "--config-file --prerelease --pre --resolution --exclude-newer --directory --project "
    "--env-file".split()
)
# Environment variables that can change what a launcher installs or which program and
# modules run: the search path, Python's, uv's, pip's and the dynamic loader's.
_RISKY_ENV = re.compile(r"PATH|PYTHON.*|UV_.*|PIP_.*|PIPX_.*|LD_.*|DYLD_.*|VIRTUAL_ENV|CONDA_.*")
_WITH_OPTIONS = ("--with", "-w", "--with-executables-from")
_REMOTE_TYPES = frozenset({"http", "sse", "ws", "streamable-http", "streamableHttp"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
_NPM = frozenset({"npx", "bunx", "pnpx", "npm", "pnpm", "yarn", "bun"})
_CONTAINERS = frozenset({"docker", "podman", "nerdctl"})
_PYTHON = re.compile(r"python[0-9.]*|py")
# Anything a shell would interpret: such a script is not split into a command here.
_SHELL_SYNTAX = re.compile(r"[;&|<>`$()\n\\*?\[\]{}~#!]")
_CMD_SYNTAX = re.compile(r'[&|<>^%()"\n]')
# A launcher named by a bare name or a plain absolute path. A relative path or one
# built from a variable (${workspaceFolder}/uvx) can be a file the repository ships.
_LAUNCHER_PATH = re.compile(r"[^\s\\/$%~]+|(/|[A-Za-z]:[\\/])[^\s$%~]*")
_GIT_COMMIT = re.compile(r"@[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_UVX_VERSION = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)@([A-Za-z0-9.!+_-]+)")
_LOCAL_SPEC = re.compile(r"[\\/]|^[.~]|\.(whl|zip|tar\.gz|tgz|tar\.bz2)$", re.IGNORECASE)
_COMMENTS = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', re.DOTALL)
_TRAILING_COMMAS = re.compile(r'("(?:\\.|[^"\\])*")|,(?=\s*[}\]])')

Entries = list[tuple[str, object]]


def servers(text: str) -> Entries | None:
    """(config key, server entry) for every server in an MCP config, or None when the
    text is not one. ValueError when it starts like JSON but will not parse."""
    text = text.removeprefix("\ufeff")  # a byte order mark, as Windows editors write
    if not text.lstrip().startswith("{"):
        return None
    try:
        try:
            data = json.loads(text)
        except ValueError:  # JSONC: VS Code's mcp.json allows comments and trailing commas
            text = _COMMENTS.sub(lambda m: m[1] or "", text)
            data = json.loads(_TRAILING_COMMAS.sub(lambda m: m[1] or "", text))
    except RecursionError as exc:
        raise ValueError("nested too deeply to read") from exc
    if not isinstance(data, dict):
        return None
    # ~/.claude.json keeps each project's servers under projects/<path>/mcpServers;
    # the path is added to their keys, since two projects can use one server name.
    projects = data.get("projects")
    tables = [("", data.get("mcpServers")), ("", data.get("servers"))] + [
        (f" ({path})", project.get("mcpServers"))
        for path, project in (projects.items() if isinstance(projects, dict) else [])
        if isinstance(project, dict)
    ]
    tables = [(where, table) for where, table in tables if isinstance(table, dict)]
    if not tables:
        return None
    return [(f"{key}{where}", entry) for where, table in tables for key, entry in table.items()]


def check(
    entries: Entries,
    fetch: lock.Fetch | None = None,
    cache_dir: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[Result]:
    """One Result per package a server installs from PyPI (named key/file), and one
    named by the key for whatever else there is to say about the server.

    For each uv, uvx or pipx launch, that is the server package and the full set
    those tools would install with it.
    """
    fetch = _remembering(fetch or lock.fetch_url)
    if cache_dir is not None:
        return _check_cached(entries, fetch, cache_dir, progress)
    with tempfile.TemporaryDirectory(prefix="buckthorn-") as tmp:
        return _check_cached(entries, fetch, Path(tmp), progress)


def _check_cached(
    entries: Entries,
    fetch: lock.Fetch,
    cache: Path,
    progress: Callable[[str], None] | None,
) -> list[Result]:
    results = []
    for key, entry in entries:
        if progress:
            progress(key)
        requirements, findings = _server(key, entry)
        if requirements:
            results.extend(_install_set(key, requirements, fetch, cache))
        if findings:
            results.append(Result(key, "", findings))
    return results


def _server(key: str, entry: object) -> tuple[list[Requirement], list[Finding]]:
    if not isinstance(entry, dict):
        return [], [_gap(key, "is not an object, so what it runs is not known")]
    requirements: list[Requirement] = []
    findings: list[Finding] = []
    helper = entry.get("headersHelper")  # Claude Code runs it in a shell to build headers
    if isinstance(helper, str) and helper:
        requirements, findings = _launch(key, ["sh", "-c", helper])
    command, args = entry.get("command"), entry.get("args") or []
    if command is not None:  # whatever the type says: a client may launch it anyway
        if not (isinstance(command, str) and isinstance(args, list)) or not all(
            isinstance(a, str) for a in args
        ):
            return requirements, findings + [_gap(key, "has a command or args that are not text")]
        more, said = _launch(key, [command, *args])
        requirements, findings = requirements + more, findings + said
        env = entry.get("env")
        risky = isinstance(env, dict) and any(_RISKY_ENV.fullmatch(str(n)) for n in env)
        if more and (risky or "envFile" in entry):
            message = (
                "sets PATH or a Python, uv or pip variable, or reads an env file, which can "
                "change what runs; not checked"
            )
            return [], findings + [_gap(key, message)]
    elif entry.get("type") in _REMOTE_TYPES or entry.get("url") or entry.get("serverUrl"):
        message = "a remote server: nothing is installed or run on this machine for it"
        findings.append(Finding("BKT-MCP-006", message, Severity.INFO, key))
    else:
        findings.append(_gap(key, "has no command or url"))
    return requirements, findings


def _launch(key: str, tokens: list[str], depth: int = 0) -> tuple[list[Requirement], list[Finding]]:
    """What a command line installs from PyPI, and what can be said about the rest."""
    if len(tokens) == 1 and re.search(r"\s", tokens[0]):  # "uvx pkg" as one word, or sh -c
        try:
            tokens = shlex.split(tokens[0])
        except ValueError:
            return [], [_gap(key, "has a command that cannot be split into words")]
    if not tokens or depth > 3:
        return [], [_gap(key, "has no command to run")]
    if not _LAUNCHER_PATH.fullmatch(tokens[0]) or ".." in tokens[0]:
        return [], [_gap(key, "runs a local program or script, which is not checked")]
    program = re.split(r"[\\/]", tokens[0])[-1].lower()
    program = re.sub(r"\.(exe|cmd|bat|ps1)$", "", program)
    args = tokens[1:]
    if program in _SHELLS or program in ("cmd", "powershell", "pwsh"):
        if PIPE_TO_SHELL.search(" ".join(args)):
            message = (
                "downloads code and runs it in a shell each time it starts, with no pin or hash"
            )
            return [], [Finding("BKT-MCP-004", message, Severity.HIGH, key)]
        if program == "cmd" and args[:1] and args[0].lower() in ("/c", "/k"):
            if not _CMD_SYNTAX.search(" ".join(args[1:])):
                return _launch(key, args[1:], depth + 1)
        if program in _SHELLS and args[:1] == ["-c"] and len(args) >= 2:
            if not _SHELL_SYNTAX.search(args[1]):
                return _launch(key, [args[1]], depth + 1)
        return [], [_gap(key, "runs a shell script, which is not checked")]
    if program == "env":
        while args and "=" in args[0]:
            if _RISKY_ENV.fullmatch(args[0].partition("=")[0]) or args[0].startswith("-"):
                return [], [_other_source(key)]
            args = args[1:]
        if args[:1] and args[0].startswith("-"):
            return [], [_unknown_option(key)]
        return _launch(key, args, depth + 1)
    if program == "uvx":
        return _tool(key, args)
    if program == "pipx" and args[:1] == ["run"]:
        return _tool(key, args[1:])
    if program == "uv":
        parsed = _options(args)
        if parsed is None:
            return [], [_unknown_option(key)]
        options, rest = parsed
        if rest[:2] == ["tool", "run"]:
            return _tool(key, rest[2:], options)
        if rest[:1] == ["run"]:
            return _uv_run(key, rest[1:], options)
        return [], [_gap(key, "runs uv in a way that is not checked")]
    if _PYTHON.fullmatch(program):
        if "-m" in args:
            message = (
                "runs a module from a Python environment already on this machine; "
                "check that environment with buckthorn env"
            )
            return [], [_gap(key, message)]
        return [], [_gap(key, "runs a local program or script, which is not checked")]
    if program in _NPM:
        return [], [_gap(key, "npm servers are not checked yet")]
    if program in _CONTAINERS:
        return [], [_gap(key, "runs a container; container images are not checked")]
    return [], [_gap(key, "runs a local program or script, which is not checked")]


def _tool(
    key: str, args: list[str], earlier: list[tuple[str, str]] | None = None
) -> tuple[list[Requirement], list[Finding]]:
    """uvx, uv tool run, pipx run: the package is --from (or --spec), else the command."""
    parsed = _options(args)
    if parsed is None:
        return [], [_unknown_option(key)]
    options, rest = parsed
    options = (earlier or []) + options
    if _changes_source(options):
        return [], [_other_source(key)]
    named = [value for name, value in options if name in ("--from", "--spec")]
    main = named[-1] if named else (rest[0] if rest else None)
    if main is None:
        return [], [_gap(key, "names no package to run")]
    return _requirements(key, [main] + [v for n, v in options if n in _WITH_OPTIONS])


def _uv_run(
    key: str, args: list[str], earlier: list[tuple[str, str]]
) -> tuple[list[Requirement], list[Finding]]:
    """uv run: the --with packages come from PyPI; the command may come from a local
    project or file instead."""
    parsed = _options(args)
    if parsed is None:
        return [], [_unknown_option(key)]
    options, rest = parsed
    options = earlier + options
    if _changes_source(options):
        return [], [_other_source(key)]
    withs = [value for name, value in options if name in _WITH_OPTIONS]
    requirements, findings = _requirements(key, withs)
    names = {name for name, _ in options}
    # Without --no-project, uv installs the project in the folder the agent starts it
    # in. The command is taken as checked only when it is named like a --with package:
    # anything else (bash, node, a script) is found on PATH or on disk.
    packages = {canonicalize_name(r.name) for r in requirements}
    if (
        "--no-project" not in names
        or "--script" in names
        or not rest
        or canonicalize_name(rest[0]) not in packages
    ):
        message = "runs code from a local project, file or program, which is not checked"
        findings.append(_gap(key, message))
    return requirements, findings


def _changes_source(options: list[tuple[str, str]]) -> bool:
    """An index, local files, a config or a resolution setting, or an interpreter path
    (uv runs it to ask its version)."""
    return any(
        name in _SOURCE_OPTIONS or (name in ("--python", "-p") and _LOCAL_SPEC.search(value))
        for name, value in options
    )


def _options(tokens: list[str]) -> tuple[list[tuple[str, str]], list[str]] | None:
    """(options, the rest) up to the first word that is not an option; None for an
    option this module does not know."""
    options = []
    i = 0
    while i < len(tokens) and tokens[i].startswith("-") and tokens[i] != "-":
        if tokens[i] == "--":
            return options, tokens[i + 1 :]
        name, eq, value = tokens[i].partition("=")
        if name in _VALUE_OPTIONS:
            if not eq:
                i += 1
                if i == len(tokens):
                    return None
                value = tokens[i]
            options.append((name, value))
        elif name in _FLAG_OPTIONS and not eq:
            options.append((name, ""))
        else:
            return None
        i += 1
    return options, tokens[i:]


def _requirements(key: str, specs: list[str]) -> tuple[list[Requirement], list[Finding]]:
    requirements, findings = [], []
    for spec in specs:
        text = spec.strip()
        if "git+" in text.lower():
            if not _GIT_COMMIT.search(text):
                message = (
                    "installs from a git repository with no commit pinned, so any push to it "
                    "changes what runs"
                )
                findings.append(Finding("BKT-MCP-003", message, Severity.MEDIUM, key))
            findings.append(_gap(key, "installs from a git repository, which is not checked"))
            continue
        if _LOCAL_SPEC.search(text):
            findings.append(_gap(key, "installs a local path or file, not a PyPI package"))
            continue
        match = _UVX_VERSION.fullmatch(text)  # uvx's pkg@1.0 and pkg@latest
        if match:
            text = match[1] if match[2] == "latest" else f"{match[1]}=={match[2]}"
        try:
            requirement = Requirement(text)
        except InvalidRequirement:
            requirement = None
        if requirement is None or requirement.url:
            message = "installs a URL, a local path or a variable, not a PyPI package; not checked"
            findings.append(_gap(key, message))
        else:
            requirements.append(requirement)
    return requirements, findings


# How many packages, and how many versions, one server's install set may try.
# Past this the closure is not checked: a real tool environment is far smaller,
# and an index that branches forever must not hang the check.
_MAX_PACKAGES = 400
_MAX_STEPS = 5000
_UNKNOWN = object()
_UNREADABLE = ("BKT-LOCK-001", "BKT-LOCK-002", "BKT-MCP-001")


def _install_set(
    key: str, requirements: list[Requirement], fetch: lock.Fetch, cache: Path
) -> list[Result]:
    """Scan the packages uvx or pipx would install for these requirements."""
    resolver = _Resolver(fetch, cache)
    try:
        solution = resolver.resolve(requirements)
    except _Unresolvable as exc:
        return [_scan(key, req, fetch, cache, unresolved=exc.reason) for req in requirements]
    except lock.FetchError as exc:
        return [_scan(key, req, fetch, cache, unresolved=str(exc)) for req in requirements]
    results = []
    for canon in solution.order:
        version = solution.chosen[canon]
        display = solution.names[canon]
        result = _cached_scan(solution.scans, key, canon, display, version, fetch, cache)
        # A package PyPI does not have is named by the server key, as other gaps are.
        if not any(f.rule_id == "BKT-MCP-001" for f in result.findings):
            result.path = f"{key}/{result.path}"
        results.append(
            _annotate(
                key,
                result,
                display,
                version,
                solution.constraints[canon],
                solution.roots.get(canon),
                [gap.reason for gap in solution.gaps if gap.package == canon],
            )
        )
    return results


def _cached_scan(
    scans: dict[tuple[str, str], Result],
    key: str,
    canon: str,
    display: str,
    version: str,
    fetch: lock.Fetch,
    cache: Path,
) -> Result:
    cached = scans.get((canon, version))
    if cached is not None:
        return Result(cached.path, cached.sha256, list(cached.findings))
    try:
        return lock.scan_release(display, version, fetch=fetch, cache_dir=cache)
    except lock.FetchError as exc:
        message = f"{display} could not be checked on PyPI: {exc}"
        return Result(key, "", [_gap(key, message)])


def _annotate(
    key: str,
    result: Result,
    display: str,
    version: str,
    requirements: list[Requirement],
    roots: list[Requirement] | None,
    reasons: list[str],
) -> Result:
    """Pin and coverage notes for one resolved package. Info, except a gap."""
    scanned = not any(f.rule_id in _UNREADABLE for f in result.findings)
    if scanned and roots is not None and _exact_pin(_combined(roots)) is None:
        message = (
            f"{display} is not pinned to a version, so the agent runs whatever is newest "
            f"each time it starts; {version} was checked"
        )
        result.findings.append(Finding("BKT-MCP-002", message, Severity.INFO, key))
    if scanned and roots is None and _exact_pin(_combined(requirements)) is None:
        shown = ", ".join(dict.fromkeys(_shown(req) for req in requirements))
        message = (
            f"{display} is not pinned to a version ({shown}), so the agent installs "
            f"whatever is newest that matches each time it starts; {version} was checked"
        )
        result.findings.append(Finding("BKT-MCP-007", message, Severity.INFO, key))
    unique = list(dict.fromkeys(reasons))
    if unique:
        detail = "; ".join(unique)
        message = f"the packages {display} depends on were not checked: {detail}"
        result.findings.append(Finding("BKT-MCP-005", message, Severity.INFO, key))
    return result


def _scan(
    key: str,
    requirement: Requirement,
    fetch: lock.Fetch,
    cache_dir: Path | None,
    unresolved: str | None = None,
) -> Result:
    """Scan one requirement at the version its own spec selects, with no dependencies.

    Used when the install set could not be resolved: the named package is still
    checked, and the gap says why the rest was not.
    """
    name = requirement.name
    specifiers = list(requirement.specifier)
    pinned = None
    if (
        len(specifiers) == 1
        and specifiers[0].operator in ("==", "===")
        and "*" not in str(specifiers[0].version)
    ):
        pinned = specifiers[0].version
    try:
        version = pinned or _newest(requirement, fetch)
        result = lock.scan_release(name, version, fetch=fetch, cache_dir=cache_dir)
    except lock.FetchError as exc:
        return Result(key, "", [_gap(key, f"{name} could not be checked on PyPI: {exc}")])
    result.path = f"{key}/{result.path}"
    if not pinned and not any(f.rule_id in _UNREADABLE for f in result.findings):
        message = (
            f"{name} is not pinned to a version, so the agent runs whatever is newest "
            f"each time it starts; {version} was checked"
        )
        result.findings.append(Finding("BKT-MCP-002", message, Severity.INFO, key))
    if unresolved and not any(f.rule_id == "BKT-MCP-001" for f in result.findings):
        message = f"the packages {name} depends on were not checked: {unresolved}"
        result.findings.append(Finding("BKT-MCP-005", message, Severity.INFO, key))
    return result


def _newest(requirement: Requirement, fetch: lock.Fetch) -> str:
    """The newest release on PyPI the spec allows: not yanked, not a pre-release
    unless only pre-releases match, as uv and pip choose."""
    raw = fetch(_index_url(requirement.name), lock.MAX_INDEX_BYTES)
    try:
        releases = json.loads(raw)["releases"]
        versions = {}
        for text, files in releases.items():
            if isinstance(files, list) and _installable(files):
                try:
                    versions[Version(text)] = text
                except InvalidVersion:
                    continue
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise lock.FetchError(f"unexpected index response: {exc}") from exc
    best = max(requirement.specifier.filter(versions), default=None)
    if best is None:
        raise lock.FetchError("no release on PyPI matches")
    return versions[best]


class _SkipVersion(Exception):
    """This version is not on PyPI or has no file here; try an older candidate."""


class _Unresolvable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _Gap:
    package: str  # canonical name of the package whose dependencies are incomplete
    version: str
    reason: str


@dataclass
class _Solution:
    order: list[str]
    chosen: dict[str, str]
    constraints: dict[str, list[Requirement]]
    roots: dict[str, list[Requirement]]
    names: dict[str, str]
    gaps: list[_Gap]
    scans: dict[tuple[str, str], Result]


class _Resolver:
    """Newest-first backtracking over static Requires-Dist.

    The same choices uv and pip make for a tool install on this machine: the
    newest file that installs here, markers evaluated for this interpreter,
    extras only when the requirement asks for them. A version whose metadata
    is not static is kept (it is what would be installed) and recorded as a
    gap, rather than replaced with an older release that happens to say more.
    """

    def __init__(self, fetch: lock.Fetch, cache: Path) -> None:
        self.fetch = fetch
        self.cache = cache
        self.projects: dict[str, dict] = {}
        self.dep_cache: dict[tuple[str, str], tuple[list[str] | None, str | None]] = {}
        self.scans: dict[tuple[str, str], Result] = {}
        self.constraints: dict[str, list[Requirement]] = {}
        self.order: list[str] = []
        self.names: dict[str, str] = {}
        self.chosen: dict[str, str] = {}
        self.expanded: dict[tuple[str, str], frozenset[str]] = {}
        self.gaps: list[_Gap] = []
        self.roots: dict[str, list[Requirement]] = {}
        self.stuck = ""
        self.steps = 0

    def resolve(self, roots: list[Requirement]) -> _Solution:
        for requirement in roots:
            canon = canonicalize_name(requirement.name)
            self.roots.setdefault(canon, []).append(requirement)
            self._note(requirement)
        if not self._search():
            who = self.stuck or "a dependency"
            raise _Unresolvable(
                f"no release of {who} satisfies the constraints, so the packages "
                "that would be installed were not checked"
            )
        return _Solution(
            order=list(self.order),
            chosen=dict(self.chosen),
            constraints={name: list(reqs) for name, reqs in self.constraints.items()},
            roots={name: list(reqs) for name, reqs in self.roots.items()},
            names=dict(self.names),
            gaps=list(self.gaps),
            scans=self.scans,
        )

    def _search(self) -> bool:
        self.steps += 1
        if self.steps > _MAX_STEPS or len(self.order) > _MAX_PACKAGES:
            raise _Unresolvable(
                "the dependency set is too large to resolve, so the packages "
                "that would be installed were not checked"
            )
        canon = next((name for name in self.order if not self._done(name)), None)
        if canon is None:
            return True
        if canon in self.chosen:
            return self._reexpand(canon)
        options = self._candidates(canon)
        if not options:
            self.stuck = self.names.get(canon, canon)
            return False
        readable = False
        for version in options:
            self.steps += 1
            if self.steps > _MAX_STEPS:
                raise _Unresolvable(
                    "the dependency set is too large to resolve, so the packages "
                    "that would be installed were not checked"
                )
            try:
                requires, reason = self._dependency_strings(self.names[canon], version)
            except _SkipVersion:
                continue
            readable = True
            saved = self._save()
            self.chosen[canon] = version
            if self._expand(canon, version, requires, reason) and self._search():
                return True
            self._restore(saved)
            # No static metadata: an older release is not what would be installed.
            if requires is None:
                break
        if not readable:
            self.stuck = self.names.get(canon, canon)
        return False

    def _reexpand(self, canon: str) -> bool:
        """A later requirement asked for more extras of a package already chosen."""
        version = self.chosen[canon]
        saved = self._save()
        try:
            requires, reason = self._dependency_strings(self.names[canon], version)
        except _SkipVersion:
            self._restore(saved)
            return False
        if self._expand(canon, version, requires, reason) and self._done(canon) and self._search():
            return True
        self._restore(saved)
        return False

    def _done(self, canon: str) -> bool:
        if canon not in self.chosen:
            return False
        return self.expanded.get((canon, self.chosen[canon])) == _extras(self.constraints[canon])

    def _expand(
        self, canon: str, version: str, requires: list[str] | None, reason: str | None
    ) -> bool:
        while True:
            extras = _extras(self.constraints[canon])
            if self.expanded.get((canon, version)) == extras:
                return True
            self.expanded[(canon, version)] = extras
            if requires is None:
                why = reason or "it publishes no static dependency metadata"
                self.gaps.append(_Gap(canon, version, why))
                return True
            if not self._apply(canon, version, requires, extras):
                return False

    def _apply(self, canon: str, version: str, requires: list[str], extras: frozenset[str]) -> bool:
        for text in requires:
            text = text.strip()
            if not text:
                continue
            try:
                requirement = Requirement(text)
            except InvalidRequirement:
                why = "a dependency requirement could not be parsed"
                self.gaps.append(_Gap(canon, version, why))
                continue
            applies = _marker_applies(requirement, extras)
            if applies is None:
                why = f"a marker on {requirement.name} could not be evaluated"
                self.gaps.append(_Gap(canon, version, why))
                continue
            if not applies:
                continue
            if requirement.url:
                why = f"{requirement.name} is a URL or a path, not a PyPI release"
                self.gaps.append(_Gap(canon, version, why))
                continue
            self._note(requirement)
            dep = canonicalize_name(requirement.name)
            if dep in self.chosen and self.chosen[dep] not in self._candidates(dep):
                return False
        return True

    def _note(self, requirement: Requirement) -> None:
        canon = canonicalize_name(requirement.name)
        self.names.setdefault(canon, requirement.name)
        have = self.constraints.setdefault(canon, [])
        if any(_same_requirement(earlier, requirement) for earlier in have):
            return
        have.append(requirement)
        if canon not in self.order:
            self.order.append(canon)

    def _candidates(self, canon: str) -> list[str]:
        """Versions the current constraints allow, newest first.

        An exact `==` or `===` pin is that version even when it is yanked: uv
        and pip still install a pin. Anything else skips yanked releases and
        releases this machine cannot install.
        """
        spec = _combined(self.constraints[canon])
        exact = _exact_pin(spec)
        if exact is not None:
            return [exact]
        releases = self._releases(self.names[canon])
        versions: dict[Version, str] = {}
        for text, files in releases.items():
            if not isinstance(text, str) or not isinstance(files, list) or not _installable(files):
                continue
            try:
                versions[Version(text)] = text
            except InvalidVersion:
                continue
        return [versions[item] for item in sorted(spec.filter(versions), reverse=True)]

    def _releases(self, name: str) -> dict:
        canon = canonicalize_name(name)
        if canon not in self.projects:
            raw = self.fetch(_index_url(name), lock.MAX_INDEX_BYTES)
            try:
                releases = json.loads(raw)["releases"]
            except (ValueError, KeyError, TypeError) as exc:
                raise lock.FetchError(f"unexpected index response: {exc}") from exc
            if not isinstance(releases, dict):
                raise lock.FetchError("unexpected index response")
            self.projects[canon] = releases
        return self.projects[canon]

    def _dependency_strings(self, name: str, version: str) -> tuple[list[str] | None, str | None]:
        """(Requires-Dist, None) or (None, why it is not known). _SkipVersion when
        this version itself cannot be used."""
        canon = canonicalize_name(name)
        key = (canon, version)
        if key in self.dep_cache:
            return self.dep_cache[key]
        try:
            document = self._version_document(name, version)
        except lock.FetchError as exc:
            raise _SkipVersion(str(exc)) from exc
        found = _requires_from_index(document)
        reason = None
        if found is _UNKNOWN:
            found, reason = self._requires_from_artifact(name, version)
        self.dep_cache[key] = (found, reason)
        return found, reason

    def _version_document(self, name: str, version: str) -> dict:
        raw = self.fetch(_index_url(name, version), lock.MAX_INDEX_BYTES)
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise lock.FetchError(f"unexpected index response: {exc}") from exc
        if not isinstance(document, dict):
            raise lock.FetchError("unexpected index response")
        return document

    def _requires_from_artifact(
        self, name: str, version: str
    ) -> tuple[list[str] | None, str | None]:
        try:
            result = lock.scan_release(name, version, fetch=self.fetch, cache_dir=self.cache)
        except lock.FetchError as exc:
            raise _SkipVersion(str(exc)) from exc
        self.scans[(canonicalize_name(name), version)] = result
        if any(f.rule_id in _UNREADABLE for f in result.findings) or not result.sha256:
            return None, "its files could not be read"
        path = self.cache / result.sha256 / result.path
        if not path.is_file():
            return None, "its files could not be read"
        return _read_static_requires(path)

    def _save(self) -> tuple:
        return (
            {name: list(reqs) for name, reqs in self.constraints.items()},
            list(self.order),
            list(self.gaps),
            dict(self.expanded),
            dict(self.chosen),
        )

    def _restore(self, saved: tuple) -> None:
        constraints, order, gaps, expanded, chosen = saved
        self.constraints = constraints
        self.order = order
        self.gaps = gaps
        self.expanded = expanded
        self.chosen = chosen


def _remembering(fetch: lock.Fetch) -> lock.Fetch:
    """Reuse PyPI's JSON responses within one check. Artifact bytes stay on the
    file cache: holding every wheel in memory as well would double the read."""
    seen: dict[tuple[str, int], bytes] = {}

    def wrapped(url: str, max_bytes: int) -> bytes:
        if urllib.parse.urlparse(url).hostname != "pypi.org":
            return fetch(url, max_bytes)
        key = (url, max_bytes)
        if key not in seen:
            seen[key] = fetch(url, max_bytes)
        return seen[key]

    return wrapped


def _index_url(name: str, version: str | None = None) -> str:
    base = "https://pypi.org/pypi/" + urllib.parse.quote(name, safe="")
    if version is None:
        return base + "/json"
    return base + "/" + urllib.parse.quote(version, safe="") + "/json"


def _installable(files: list) -> bool:
    """True when some non-yanked file of this release installs on this machine.

    Same checks as `scan_release`, so the version chosen here is one it can read.
    """
    usable = []
    for entry in files:
        if not isinstance(entry, dict) or entry.get("yanked"):
            continue
        if not _python_allows(entry.get("requires_python")):
            continue
        filename = str(entry.get("filename") or "")
        digests = entry.get("digests") if isinstance(entry.get("digests"), dict) else {}
        sha = str(digests.get("sha256") or "").lower()
        url = str(entry.get("url") or "")
        if not (
            lock._SHA256.match(sha)
            and lock._SAFE_FILENAME.match(filename)
            and filename.lower().endswith(ARTIFACT_SUFFIXES)
            and lock.allowed_url(url)
        ):
            continue
        usable.append((filename, sha, url))
    return bool(lock._installable_here(usable))


def _python_allows(requires: object) -> bool:
    if not isinstance(requires, str) or not requires.strip():
        return True
    try:
        spec = SpecifierSet(requires)
    except InvalidSpecifier:
        return True
    version = Version(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return spec.contains(version, prereleases=True)


def _requires_from_index(document: dict) -> list[str] | object:
    """Requires-Dist from the version's JSON, or _UNKNOWN when PyPI has none.

    `null` means the release did not publish static metadata. An empty list
    means it published some and depends on nothing.
    """
    info = document.get("info")
    if not isinstance(info, dict) or "requires_dist" not in info:
        return _UNKNOWN
    raw = info["requires_dist"]
    if raw is None:
        return _UNKNOWN
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise lock.FetchError("unexpected index response")
    return raw


def _read_static_requires(path: Path) -> tuple[list[str] | None, str | None]:
    """Requires-Dist from a hash-checked wheel or sdist, without building it.

    A wheel with no Requires-Dist depends on nothing: wheel metadata is static.
    An sdist that omits it, or marks it dynamic, is not known from here.
    """
    members, _findings = read_archive(path)
    wheel = path.name.lower().endswith(".whl")
    if wheel:
        found = [
            data
            for name, data in members
            if name.count("/") == 1 and name.endswith(".dist-info/METADATA")
        ]
    else:
        found = [
            data
            for name, data in members
            if name.count("/") == 1 and name.endswith("/PKG-INFO")
        ]
    if len(found) != 1:
        if wheel:
            return None, "the wheel has no metadata"
        return None, "the sdist publishes no static dependency metadata"
    return _requires_from_metadata(found[0].decode("utf-8", errors="replace"), wheel=wheel)


def _requires_from_metadata(text: str, *, wheel: bool) -> tuple[list[str] | None, str | None]:
    headers = HeaderParser().parsestr(text)
    dynamic: set[str] = set()
    for raw in headers.get_all("Dynamic") or []:
        dynamic.update(part.strip().lower().replace("_", "-") for part in raw.split(","))
    if "requires-dist" in dynamic:
        return None, "its dependencies are computed at build time"
    fields = headers.get_all("Requires-Dist")
    if not fields:
        if wheel:
            return [], None
        return None, "the sdist publishes no static dependency metadata"
    return [field.strip() for field in fields if field.strip()], None


def _combined(requirements: list[Requirement]) -> SpecifierSet:
    spec = SpecifierSet()
    for requirement in requirements:
        spec &= requirement.specifier
    return spec


def _exact_pin(spec: SpecifierSet) -> str | None:
    """The one version an `==` or `===` specifier without a wildcard demands."""
    found: str | None = None
    for item in spec:
        if item.operator not in ("==", "===") or "*" in item.version:
            continue
        if found is not None and found != item.version:
            return None
        found = item.version
    if found is None:
        return None
    try:
        if Version(found) not in spec:
            return None
    except InvalidVersion:
        return found
    return found


def _extras(requirements: list[Requirement]) -> frozenset[str]:
    return frozenset(extra for requirement in requirements for extra in requirement.extras)


def _marker_applies(requirement: Requirement, extras: frozenset[str]) -> bool | None:
    """Whether this dependency is installed for these extras on this machine.

    None when the marker cannot be evaluated: the dependency is then a gap,
    not silently dropped or assumed.
    """
    if requirement.marker is None:
        return True
    environment = default_environment()
    try:
        return any(
            requirement.marker.evaluate({**environment, "extra": extra})
            for extra in (frozenset({""}) | extras)
        )
    except (UndefinedComparison, UndefinedEnvironmentName, ValueError):
        return None


def _shown(requirement: Requirement) -> str:
    spec = str(requirement.specifier)
    return f"{requirement.name}{spec}" if spec else requirement.name


def _same_requirement(left: Requirement, right: Requirement) -> bool:
    return (
        canonicalize_name(left.name) == canonicalize_name(right.name)
        and str(left.specifier) == str(right.specifier)
        and set(left.extras) == set(right.extras)
        and str(left.marker) == str(right.marker)
    )


def _gap(key: str, message: str) -> Finding:
    return Finding("BKT-MCP-001", message, Severity.INFO, key)


def _unknown_option(key: str) -> Finding:
    return _gap(
        key, "uses a launcher option Buckthorn does not know, so the package is not certain"
    )


def _other_source(key: str) -> Finding:
    message = (
        "changes where the package comes from or what runs (an index, a local path, a "
        "config, an interpreter or a version setting); not checked"
    )
    return _gap(key, message)
