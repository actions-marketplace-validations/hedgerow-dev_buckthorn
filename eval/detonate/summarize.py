"""Summarise each detonation from its logs only (strace, audit hook, nft, changed files).

Programs and changed files that the harmless control run also shows (pip's own
probes, bytecode caches) are left out, so what remains is the package's doing.
"""
import json
import re
import sys
from pathlib import Path

DECOYS = ("/root/.ssh", "/root/.aws", "/root/.env", "/root/.pypirc", "/root/.config/solana", "/root/.config/google-chrome")
BORING_EXEC = ("/usr/bin/python3", "/bin/bash", "/usr/bin/bash", "/usr/bin/sleep", "/usr/bin/timeout", "/usr/bin/strace")
BORING_FILES = ("./usr/local/lib/python3", "./tmp/", "./root/.cache/", "./var/", "./run/", "./etc/ld.so.cache")


def read(run, name):
    path = run / name
    return path.read_text(errors="replace") if path.exists() else ""


def execs_of(run):
    return {m.group(1) for m in re.finditer(r'execve\("([^"]+)"', read(run, "strace.log"))}


def changed_of(run):
    return {l.split(" ", 2)[-1] for l in read(run, "changed-files.txt").splitlines() if l.strip()}


def stage_of(stdout):
    return [l[3:] for l in stdout.splitlines() if l.startswith("== ")]


results = Path(sys.argv[1])
base_execs, base_changed = execs_of(results / "control"), changed_of(results / "control")
base_execs -= {"/usr/bin/id", "/usr/local/bin/id"}  # what the control itself did, not pip
for run in sorted(results.iterdir()):
    strace = (run / "strace.log").read_text(errors="replace") if (run / "strace.log").exists() else ""
    stdout = (run / "stdout.log").read_text(errors="replace") if (run / "stdout.log").exists() else ""
    decoys = sorted({m.group(1) for m in re.finditer(r'openat\([^"]*"([^"]+)"', strace) if m.group(1).startswith(DECOYS)})
    ports = sorted({f'{a}:{p}' for p, a in re.findall(r'connect\(\d+, \{sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"', strace)})
    keep_base = run.name == "control"
    execs = sorted(e for e in execs_of(run) if not e.startswith(BORING_EXEC) and (keep_base or e not in base_execs))
    hosts = set()
    if (run / "audit.log").exists():
        for line in (run / "audit.log").read_text(errors="replace").splitlines():
            try:
                _, stage, _, event, args = json.loads(line)
            except ValueError:
                continue
            if event in ("socket.getaddrinfo", "socket.connect", "urllib.Request"):
                hosts.add(f"{stage}: {event} {args[:120]}")
    changed = sorted(p for p in changed_of(run) if not p.startswith(BORING_FILES) and "__pycache__" not in p
                     and (keep_base or p not in base_changed))
    denied = re.search(r"packets (\d+)", (run / "nft-counter.txt").read_text()) if (run / "nft-counter.txt").exists() else None
    collector = (run / "collector.log").stat().st_size if (run / "collector.log").exists() else "?"
    install_ok = "Successfully installed" in stdout
    imported = re.findall(r"^imported (\S+)", stdout, re.M)
    raised = re.findall(r"^import (\S+) raised (.*)$", stdout, re.M)
    print(f"## {run.name}")
    print(f"- install: {'ok' if install_ok else 'FAILED'}; imported: {', '.join(imported) or '-'}; import errors: {len(raised)}")
    print(f"- decoys opened: {', '.join(decoys) or 'none'}")
    print(f"- outbound connects: {', '.join(ports) or 'none'}")
    for h in sorted(hosts)[:8]:
        print(f"- py net: {h}")
    print(f"- programs run: {', '.join(execs[:10]) or 'none'}")
    print(f"- files changed outside install: {', '.join(changed[:8]) or 'none'}{' ...' if len(changed) > 8 else ''}")
    print(f"- packets denied: {denied.group(1) if denied else '?'}; collector bytes: {collector}")
    if not install_ok:
        tail = [l for l in stdout.splitlines() if "error" in l.lower()][:3]
        print(f"- install error: {' | '.join(tail)[:300]}")
    print()
