"""Command line: buckthorn scan <artifacts>, check <lockfile or MCP config>, diff, env <venv>,
hf <repo>.

Exit codes: 0 clean, 1 flagged (or not_verified, unless --allow-not-verified),
2 a usage or input error.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import hashlib
import io
import json
import re
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from buckthorn import hf, lock, mcp_config
from buckthorn.env import scan_env
from buckthorn.findings import COVERAGE_RULE_IDS, Finding, Result, Severity, new_findings
from buckthorn.scan import ARTIFACT_SUFFIXES, scan_artifact, split_artifact_name

_SEVERITY_ORDER = list(Severity)


class InputError(Exception):
    """Bad input from the caller: reported on stderr, exit code 2."""


def main(argv: list[str] | None = None) -> int:
    # A name the console cannot encode (cp1252 on Windows) is escaped, not a crash.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(
        prog="buckthorn",
        description=(
            "Static checks for Python and npm packages. Nothing is installed, imported or run."
        ),
    )
    parser.add_argument("--version", action="version", version=f"buckthorn {version('buckthorn')}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan",
        help="scan wheels, sdists and npm tarballs, folders of them, or a model folder's code",
    )
    scan.add_argument(
        "target", type=Path, nargs="+", help="a .whl, .tar.gz, .tgz or .zip, or a folder"
    )
    _add_report_arguments(scan)
    check = sub.add_parser(
        "check",
        help="fetch every artifact a lockfile pins, or every PyPI package an MCP config "
        "launches, from PyPI, check its hash, scan it",
    )
    check.add_argument(
        "lockfile",
        type=Path,
        nargs="+",
        help="requirements.txt with hashes, uv.lock, poetry.lock, or an agent's MCP config "
        "(.mcp.json, mcp.json, claude_desktop_config.json)",
    )
    check.add_argument(
        "--cache-dir",
        type=Path,
        metavar="DIR",
        help="keep downloads here between runs (default: a temporary folder, removed after)",
    )
    check.add_argument(
        "--all-files",
        action="store_true",
        help="check every pinned file, not only the one this machine would install",
    )
    _add_report_arguments(check)
    diff = sub.add_parser("diff", help="report only what an upgrade adds")
    diff.add_argument("old", help="the version you have: a wheel or sdist, or name==version")
    diff.add_argument("new", help="the version you are moving to, the same way")
    diff.add_argument("--cache-dir", type=Path, metavar="DIR", help="keep downloads here")
    _add_report_arguments(diff)
    env = sub.add_parser("env", help="scan an installed environment in place")
    env.add_argument("path", type=Path, help="a virtualenv, or a site-packages folder")
    _add_report_arguments(env)
    hub = sub.add_parser(
        "hf", help="read the code a Hugging Face model repo runs at load with trust_remote_code"
    )
    hub.add_argument("repo", nargs="+", help="org/name, or org/name@commit to pin it")
    _add_report_arguments(hub)
    sub.add_parser("mcp", help="run a stdio MCP server so a coding agent can check packages")
    args = parser.parse_args(argv)
    if args.command == "mcp":
        # The SDK is an optional extra, imported here and nowhere else: every other
        # command must work without it.
        try:
            import mcp  # noqa: F401
        except ImportError:
            print('buckthorn: the MCP server needs: pip install "buckthorn[mcp]"', file=sys.stderr)
            return 2
        from buckthorn.mcp_server import serve

        serve()
        return 0
    try:
        allow = _load_allowlist(args.allowlist) if args.allowlist else []
        if args.command == "check":
            results = [
                result
                for path in args.lockfile
                for result in _check_lockfile(path, args.cache_dir, args.all_files)
            ]
        elif args.command == "diff":
            results = [_diff(args.old, args.new, args.cache_dir)]
        elif args.command == "env":
            results = _env(args.path)
        elif args.command == "hf":
            results = [_hf(spec) for spec in args.repo]
        else:
            results = [scan_file(path) for path in artifacts(args.target)]
    except InputError as exc:
        print(f"buckthorn: {exc}", file=sys.stderr)
        return 2
    if args.receipt:
        try:
            statement = _receipt(results, args.command)
        except InputError as exc:
            print(f"buckthorn: {exc}", file=sys.stderr)
            return 2
        try:
            args.receipt.write_text(json.dumps(statement, indent=2), encoding="utf-8")
        except OSError as exc:
            print(f"buckthorn: could not write {args.receipt}: {exc}", file=sys.stderr)
            return 2
    _apply_allowlist(results, allow)
    return _report(results, args)


def json_report(results: list[Result]) -> dict:
    """The --format json report; the MCP tools return the same."""
    return {
        "tool": "buckthorn",
        "version": version("buckthorn"),
        "verdict": _overall(results),
        "artifacts": [
            {
                "path": r.path,
                "sha256": r.sha256,
                "verdict": r.verdict,
                "findings": [f.to_dict() for f in _ordered(r.findings)],
                "allowed": [f.to_dict() | {"reason": why} for f, why in r.allowed],
            }
            for r in results
        ],
    }


RECEIPT_PREDICATE = "https://hedgerow.dev/buckthorn/scan-receipt/v1"


def _receipt(results: list[Result], command: str) -> dict:
    """An in-toto Statement of what the scanner found in each artifact, by hash.

    Same shape as Hayward's receipts. Taken before the allowlist, so acceptance
    decisions stay apart from what was seen. Only artifacts whose bytes were read
    are subjects: a pin that was never downloaded names a hash nobody looked at.
    InputError for diff (it reports what is new, not what an artifact holds), env
    (installed files have no artifact hash), and two artifacts with one name.
    """
    if command in ("diff", "env", "hf"):
        raise InputError(f"--receipt is for scan and check, not {command}")
    if any(Path(r.path).is_dir() for r in results):  # a model folder has no artifact hash
        raise InputError("--receipt is for wheels and sdists, not a model folder")
    subjects, artifacts = [], {}
    for r in results:
        never_read = any(f.rule_id in ("BKT-LOCK-002", "BKT-LOCK-003") for f in r.findings)
        if not r.sha256 or never_read:
            continue
        name = Path(r.path).name
        if name in artifacts:
            if {"name": name, "digest": {"sha256": r.sha256}} in subjects:
                continue  # one artifact reached twice, as two MCP servers running one package
            raise InputError(f"two artifacts are named {name}; a receipt needs unique names")
        subjects.append({"name": name, "digest": {"sha256": r.sha256}})
        artifacts[name] = {
            "verdict": r.verdict,
            "rules": sorted({f.rule_id for f in r.findings if f.rule_id not in COVERAGE_RULE_IDS}),
            "coverage_gaps": sorted(
                {f.rule_id for f in r.findings if f.rule_id in COVERAGE_RULE_IDS}
            ),
        }
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": RECEIPT_PREDICATE,
        "predicate": {
            "scanner": {"name": "buckthorn", "version": version("buckthorn")},
            "scanned": datetime.now(UTC).isoformat(timespec="seconds"),
            "note": "Analysis evidence: what Buckthorn found in each artifact, identified by "
            "hash. It is not a safety certificate.",
            "artifacts": artifacts,
        },
    }


def _load_allowlist(path: Path) -> list[dict[str, str]]:
    """Entries of {"allow": [...]}: rule and package required, file and version optional,
    and a reason always. Coverage gaps cannot be allowed: they mean nothing was read."""
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))["allow"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InputError(f"allowlist {path}: {exc}") from exc
    if not isinstance(entries, list):
        raise InputError(f"allowlist {path}: 'allow' must be a list")
    for n, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(key), str) and entry[key].strip()
            for key in ("rule", "package", "reason")
        ):
            raise InputError(f"allowlist {path}: entry {n} needs a rule, a package and a reason")
        if entry["rule"] in COVERAGE_RULE_IDS:
            raise InputError(f"allowlist {path}: entry {n}: {entry['rule']} cannot be allowed")
    return entries


def _apply_allowlist(results: list[Result], entries: list[dict[str, str]]) -> None:
    for result in results:
        # Only results named for a package can be allowed: name==version (env, pins)
        # or an artifact file. Anything else, like the env's unowned files, never matches.
        if "==" in result.path:
            package, _, release = result.path.partition("==")
        elif result.path.lower().endswith(ARTIFACT_SUFFIXES):
            package, release = split_artifact_name(Path(result.path).name)
        elif "@" in result.path:  # a Hub repo at a commit: org/name@sha
            package, _, release = result.path.partition("@")
        else:
            package, release = "", ""
        kept = []
        for finding in result.findings:
            first, sep, rest = finding.file_path.partition("/")
            file = first.replace(f"-{release}", "") + sep + rest if release else finding.file_path
            reason = next(
                (
                    e["reason"]
                    for e in entries
                    if e["rule"] == finding.rule_id
                    and package
                    and _normalise(e["package"]) == _normalise(package)
                    and e.get("version", release) == release
                    and fnmatch.fnmatchcase(file, e.get("file", "*"))
                    # code fetched from another repo's main branch is never allowed
                    and not ("@" in result.path and "@" in finding.file_path)
                ),
                None,
            )
            if reason is None:
                kept.append(finding)
            else:
                result.allowed.append((finding, reason))
        result.findings = kept


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _env(path: Path) -> list[Result]:
    try:
        return scan_env(path)
    except (ValueError, OSError) as exc:  # not an environment, or a folder we cannot list
        raise InputError(str(exc)) from exc


def _hf(spec: str) -> Result:
    try:
        return hf.scan_repo(spec)
    except ValueError as exc:  # a malformed repo id
        raise InputError(f"{spec}: {exc}") from exc


def _diff(old_arg: str, new_arg: str, cache_dir: Path | None) -> Result:
    """The new version's findings that the old version does not have."""
    old, old_version = _resolve(old_arg, cache_dir)
    new, new_version = _resolve(new_arg, cache_dir)
    findings = new_findings(old.findings, new.findings, old_version, new_version)
    if old.path.endswith(".whl") and not new.path.endswith(".whl"):
        message = (
            f"{old.path} installed as a wheel; {new.path} is an sdist, "
            "so installing it now builds from source and runs install-time code"
        )
        findings.append(Finding("BKT-DIFF-001", message, Severity.MEDIUM, new.path))
    return Result(new.path, new.sha256, findings)


def _resolve(arg: str, cache_dir: Path | None) -> tuple[Result, str]:
    """Scan a local artifact, or fetch name==version from PyPI. Also returns the version."""
    path = Path(arg)
    if path.is_file():
        return scan_file(path), split_artifact_name(path.name)[1]
    if "==" not in arg:
        raise InputError(f"{arg}: no such file, and not name==version")
    name, _, version = arg.partition("==")
    try:
        return lock.scan_release(
            name.strip(), version.strip(), cache_dir=cache_dir
        ), version.strip()
    except lock.FetchError as exc:
        raise InputError(f"{arg}: {exc}") from exc


def _check_lockfile(path: Path, cache_dir: Path | None, all_files: bool) -> list[Result]:
    if not path.is_file():
        raise InputError(f"{path}: no such file")

    def progress(name: str) -> None:
        print(_printable(name), file=sys.stderr)  # MCP config keys are not checked names

    try:
        servers = mcp_config.servers(path.read_text(encoding="utf-8"))
        if servers is not None:
            results = mcp_config.check(servers, cache_dir=cache_dir, progress=progress)
        else:
            results = lock.check(path, cache_dir=cache_dir, all_files=all_files, progress=progress)
    except (ValueError, UnicodeDecodeError) as exc:  # unknown name, or TOML that will not parse
        raise InputError(f"{path}: {exc}") from exc
    for result in results:
        result.source = str(path)
    return results


def _add_report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument(
        "-o", "--output", type=Path, metavar="FILE", help="write the report here, not to stdout"
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        metavar="FILE",
        help="JSON file of findings you have reviewed and accept, each with a reason",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        metavar="FILE",
        help="also write an unsigned in-toto scan receipt: each artifact's hash and what "
        "was found, before --allowlist",
    )
    parser.add_argument(
        "--allow-not-verified",
        action="store_true",
        help="exit 0 when something could not be fully read (default: treat it as flagged)",
    )


def artifacts(targets: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for target in targets:
        if target.is_dir():
            found = sorted(
                p
                for p in target.iterdir()
                if p.is_file() and p.name.lower().endswith(ARTIFACT_SUFFIXES)
            )
            if not found and hf.is_model_folder(target):
                paths.append(target)  # a model repo: its remote code is read
                continue
            if not found:
                raise InputError(f"{target}: no wheels or sdists in this folder")
            paths.extend(found)
        elif target.is_file():
            paths.append(target)
        else:
            raise InputError(f"{target}: no such file or folder")
    return paths


def scan_file(path: Path) -> Result:
    if path.is_dir():
        return hf.scan_folder(path)
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return Result(str(path), digest.hexdigest(), scan_artifact(path))


def _overall(results: list[Result]) -> str:
    verdicts = {r.verdict for r in results}
    for name in ("flagged", "not_verified"):
        if name in verdicts:
            return name
    return "clean"


def _report(results: list[Result], args: argparse.Namespace, to_file: bool = False) -> int:
    overall = _overall(results)
    if args.output and not to_file:
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            code = _report(results, args, to_file=True)
        try:
            args.output.write_text(report.getvalue(), encoding="utf-8")
        except OSError as exc:
            print(f"buckthorn: could not write {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"{overall}: report written to {args.output}")
        return code
    if args.format == "sarif":
        print(json.dumps(_sarif(results, args), indent=2))
    elif args.format == "json":
        print(json.dumps(json_report(results), indent=2))
    else:
        hidden = 0
        for r in results:
            print(f"{_printable(r.path)}: {r.verdict}")
            for f in _ordered(r.findings):
                # Info notes are context, not verdicts; JSON keeps them. Coverage gaps always show.
                if f.severity == Severity.INFO and f.rule_id not in COVERAGE_RULE_IDS:
                    hidden += 1
                    continue
                line = f.metadata.get("line") or (f.metadata.get("lines") or [None])[0]
                where = f"{f.file_path}:{line}" if line else f.file_path
                where, message = _printable(where), _printable(f.message)
                print(f"  {f.severity.value:<8} {f.rule_id:<16} {where}  {message}")
        counts = {
            v: sum(r.verdict == v for r in results) for v in ("clean", "flagged", "not_verified")
        }
        summary = ", ".join(f"{n} {v}" for v, n in counts.items() if n)
        print(f"\n{len(results)} scanned: {summary}")
        if hidden:
            print(
                f"{hidden} info note{'s' if hidden > 1 else ''} hidden (--format json shows them)"
            )
        # Unpinned servers are info (most configs have them), so count them where they show.
        unpinned = sum(f.rule_id == "BKT-MCP-002" for r in results for f in r.findings)
        if unpinned:
            s = "s" if unpinned > 1 else ""
            print(f"{unpinned} server{s} not pinned to a version (BKT-MCP-002)")
        allowed = sum(len(r.allowed) for r in results)
        if allowed:
            print(f"{allowed} finding{'s' if allowed > 1 else ''} allowed by the allowlist")
    if overall == "flagged" or (overall == "not_verified" and not args.allow_not_verified):
        return 1
    return 0


_SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _sarif(results: list[Result], args: argparse.Namespace) -> dict:
    """SARIF 2.1.0 for code scanning. Info notes are left out; coverage gaps stay in.

    Findings sit inside archives, so each points at the artifact, or for `check`
    at its lockfile (the file in the repository), with the inner path in the message.
    """
    rules: dict[str, str] = {}
    sarif_results = []
    for r in results:
        uri = r.source or r.path
        for f in _ordered(r.findings):
            gap = f.rule_id in COVERAGE_RULE_IDS
            if f.severity == Severity.INFO and not gap:
                continue
            rules.setdefault(f.rule_id, f.message)
            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": "warning" if gap else _SARIF_LEVELS[f.severity],
                    "message": {"text": f"{r.path}: {f.file_path}: {f.message}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                }
            )
    driver = {
        "name": "buckthorn",
        "version": version("buckthorn"),
        "rules": [{"id": i, "shortDescription": {"text": m}} for i, m in sorted(rules.items())],
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": sarif_results}],
    }


def _printable(text: str) -> str:
    """Control characters escaped: names come from the packages being checked, and a
    carriage return or terminal escape in one could make a flagged line read clean."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda m: repr(m.group())[1:-1], text)


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.file_path))
