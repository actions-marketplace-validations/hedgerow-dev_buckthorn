"""Scan each spooled file with Buckthorn, in a --network none, read-only
container. Records rule ids, severities and member paths, never finding
messages. A flagged file is kept in QUARANTINE for triage; every other file is
deleted once scanned.

Usage: python -I scan_spool.py SPOOL RESULTS QUARANTINE [WORKERS]
"""

import json
import multiprocessing
import shutil
import sys
import time
from pathlib import Path

from buckthorn.findings import verdict
from buckthorn.scan import scan_artifact

TIMEOUT = 600  # seconds for one file


def scan(path: str) -> dict:
    started = time.time()
    findings = scan_artifact(Path(path))
    return {
        "verdict": verdict(findings),
        "findings": [[f.rule_id, f.severity.value, f.file_path] for f in findings],
        "seconds": round(time.time() - started, 2),
    }


def main() -> None:
    spool, results, quarantine = (Path(a) for a in sys.argv[1:4])
    workers = int(sys.argv[4]) if len(sys.argv) > 4 else 2
    results.mkdir(exist_ok=True)
    pool = multiprocessing.Pool(workers, maxtasksperchild=200)
    while True:
        items = sorted(p for p in spool.iterdir() if not p.name.startswith("."))[: workers * 20]
        if not items:
            time.sleep(5)
            continue
        metas = [json.loads((item / "meta.json").read_text()) for item in items]
        jobs = [pool.apply_async(scan, (str(item / m["file"]),)) for item, m in zip(items, metas)]
        stuck = False
        for item, meta, job in zip(items, metas, jobs):
            if stuck:
                break  # the rest stay in the spool for the next pool
            try:
                record = meta | job.get(TIMEOUT)
            except multiprocessing.TimeoutError:
                record = meta | {"verdict": "error", "error": "timeout"}
                stuck = True
            except Exception as exc:  # a scanner bug: recorded, the run goes on
                record = meta | {"verdict": "error", "error": type(exc).__name__}
            record["scanned"] = time.time()
            if record["verdict"] == "flagged":
                folder = quarantine / meta["eco"]
                folder.mkdir(parents=True, exist_ok=True)
                shutil.move(
                    str(item / meta["file"]), folder / f"{int(record['scanned'])}-{meta['file']}"
                )
            shutil.rmtree(item)
            day = time.strftime("%Y-%m-%d", time.gmtime(record["scanned"]))
            with open(results / f"{day}.jsonl", "a") as fh:
                fh.write(json.dumps(record) + "\n")
        if stuck:  # a stuck worker would hold its slot for good
            pool.terminate()
            pool = multiprocessing.Pool(workers, maxtasksperchild=200)


if __name__ == "__main__":
    main()
