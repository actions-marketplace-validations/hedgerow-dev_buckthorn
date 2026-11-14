"""Check an agent's MCP config: every server it launches, and the PyPI package behind it.

Reads the `mcpServers` table of Claude Code (`.mcp.json`, `~/.claude.json` and its
per-project tables), Claude Desktop, Cursor and Windsurf, and the `servers` table
of VS Code's `mcp.json` (comments and trailing commas allowed). Each server's
launch is classified; a `uvx`, `uv tool run`, `uv run --with` or `pipx run`
launch has its package fetched from PyPI, hash-checked and scanned by
`lock.scan_release`, exactly as `buckthorn check` does for a lockfile pin.

Configs hold credentials in `env`, in arguments and in URLs. Nothing from a
server entry is ever put in a finding except its config key and a package name
that parsed as one. Option values, environment values, URLs and paths are not.
"""

from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from collections.abc import Callable
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from buckthorn import lock
from buckthorn.code import PIPE_TO_SHELL
from buckthorn.findings import Finding, Result, Severity

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
    named by the key for whatever else there is to say about the server."""
    fetch = fetch or lock.fetch_url
    results = []
    for key, entry in entries:
        if progress:
            progress(key)
        requirements, findings = _server(key, entry)
        results.extend(_scan(key, req, fetch, cache_dir) for req in requirements)
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


def _scan(key: str, requirement: Requirement, fetch: lock.Fetch, cache_dir: Path | None) -> Result:
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
    if not pinned:
        message = (
            f"{name} is not pinned to a version, so the agent runs whatever is newest "
            f"each time it starts; {version} was checked"
        )
        result.findings.append(Finding("BKT-MCP-002", message, Severity.INFO, key))
    message = f"the packages {name} depends on are installed with it and were not checked"
    result.findings.append(Finding("BKT-MCP-005", message, Severity.INFO, key))
    return result


def _newest(requirement: Requirement, fetch: lock.Fetch) -> str:
    """The newest release on PyPI the spec allows: not yanked, not a pre-release
    unless only pre-releases match, as uv and pip choose."""
    name = urllib.parse.quote(requirement.name, safe="")
    raw = fetch(f"https://pypi.org/pypi/{name}/json", lock.MAX_INDEX_BYTES)
    try:
        releases = json.loads(raw)["releases"]
        versions = {}
        for text, files in releases.items():
            if any(not f.get("yanked") for f in files):
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
