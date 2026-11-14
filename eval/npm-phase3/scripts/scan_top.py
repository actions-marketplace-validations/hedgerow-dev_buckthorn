"""Scan the cached top npm tarballs with Buckthorn and record what it finds.

Nothing is unpacked or run. Usage: python3 -I scan_top.py REPO CACHE OUT.jsonl [WORKERS]
REPO is a Buckthorn checkout; CACHE was filled by fetch_top.py. Benign
packages only: findings are kept with their messages, for triage.
"""

import json
import multiprocessing
import sys
import time
from pathlib import Path

REPO, CACHE, OUT = sys.argv[1:4]
WORKERS = int(sys.argv[4]) if len(sys.argv) > 4 else 4
sys.path.insert(0, REPO)

from buckthorn.findings import verdict  # noqa: E402
from buckthorn.scan import scan_artifact  # noqa: E402


def one(row: dict) -> dict:
    started = time.perf_counter()
    try:
        findings = scan_artifact(Path(CACHE) / row["file"])
    except Exception as exc:  # a scanner bug: recorded, the run goes on
        return row | {"scan": f"error {type(exc).__name__}: {str(exc)[:200]}"}
    row = row | {"scan": "ok", "s": round(time.perf_counter() - started, 2)}
    row["verdict"] = verdict(findings)
    row["findings"] = [
        [f.rule_id, f.severity.value, f.file_path, f.message, f.metadata.get("lines")]
        for f in findings
    ]
    return row


def main() -> None:
    rows = [json.loads(line) for line in open(Path(CACHE) / "index.jsonl")]
    rows = sorted((r for r in rows if r.get("status") == "ok"), key=lambda r: r["rank"])
    with open(OUT, "w") as out, multiprocessing.Pool(WORKERS, maxtasksperchild=50) as pool:
        for row in pool.imap_unordered(one, rows):
            out.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()
