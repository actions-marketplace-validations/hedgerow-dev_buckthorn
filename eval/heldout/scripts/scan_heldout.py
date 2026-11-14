"""Run Buckthorn or GuardDog on every archive in a list, keeping no matched text.

Runs inside a --network none container, corpus read-only. An archive whose bytes do
not match its name (a zip stored as .tar.gz) is copied to WORK under the right name
first, as ../../pypi-malregistry/scripts/rename_scan.py did. Stored per archive:
verdict, rule ids, severities, file names and lines (Buckthorn) or rule hit counts
(GuardDog). Finding messages are dropped: samples hold live webhook URLs.
Usage: python -I scan_heldout.py buckthorn|guarddog ROOT LIST OUT_JSONL WORK
"""

import json
import shutil
import subprocess
import sys
from multiprocessing import Pool
from pathlib import Path


def target(src, work):
    """Path to scan: src itself, or a copy named for what the bytes are."""
    with open(src, "rb") as fh:
        head = fh.read(4)
    name = src.name
    if head.startswith(b"PK") and not name.endswith((".whl", ".zip")):
        stem = name.removesuffix(".tar.gz").removesuffix(".tgz")
        name = stem + (".whl" if stem.endswith("-any") or "-py" in stem else ".zip")
    elif head.startswith(b"\x1f\x8b") and not name.endswith((".tar.gz", ".tgz")):
        name = name.rsplit(".", 1)[0] + ".tar.gz"
    else:
        return src, None
    dest = work / f"{abs(hash(str(src)))}" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    return dest, name


def buckthorn(path):
    proc = subprocess.run(["buckthorn", "scan", "--format", "json", str(path)],
                          capture_output=True, text=True, timeout=900)
    rec = {"exit": proc.returncode}
    if not proc.stdout.strip():
        return dict(rec, status="error", stderr_tail=proc.stderr[-300:])
    art = json.loads(proc.stdout)["artifacts"][0]
    rec.update(status="scanned", verdict=art["verdict"], sha256=art.get("sha256"))
    rec["findings"] = [
        {"rule_id": f["rule_id"], "severity": f["severity"], "file": f.get("file"),
         "lines": (f.get("metadata") or {}).get("lines")}
        for f in art.get("findings", [])
    ]
    rec["allowed"] = len(art.get("allowed", []))
    return rec


def guarddog(path):
    proc = subprocess.run(["guarddog", "pypi", "scan", str(path), "--output-format", "json"],
                          capture_output=True, text=True, timeout=900)
    rec = {"exit": proc.returncode}
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        return dict(rec, status="error")
    rec["status"] = "scanned"
    rec["rules"] = {
        rule: len(hits) if isinstance(hits, list) else 1
        for rule, hits in (report.get("results") or {}).items()
        if hits
    }
    if report.get("errors"):
        rec["error_rules"] = sorted(report["errors"])[:20]
    return rec


def one(args):
    tool, root, rel, work = args
    rec = {"sample": rel}
    dest = None
    try:
        path, renamed = target(root / rel, work)
        if renamed:
            rec["renamed"], dest = renamed, path
        rec.update(buckthorn(path) if tool == "buckthorn" else guarddog(path))
    except subprocess.TimeoutExpired:
        rec["status"] = "timeout"
    except Exception as exc:  # recorded per archive, the run goes on
        rec.update(status="error", error=type(exc).__name__)
    if dest:
        shutil.rmtree(dest.parent, ignore_errors=True)
    return rec


if __name__ == "__main__":
    tool, root, lst, out, work = sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4], Path(sys.argv[5])
    rels = [l.strip() for l in open(lst) if l.strip()]
    with Pool(4) as pool, open(out, "w") as fh:
        for i, rec in enumerate(pool.imap_unordered(one, [(tool, root, r, work) for r in rels]), 1):
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush()
            if i % 100 == 0:
                print(f"{i}/{len(rels)}", flush=True)
    print(f"{len(rels)} done", flush=True)
