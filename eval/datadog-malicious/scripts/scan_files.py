"""Run `buckthorn scan --format json` on every wheel and sdist under a folder.

Runs inside a --network none container with the folder mounted read-only.
One JSON line per artifact. Nothing is unpacked, installed or run.
Usage: python -I scan_files.py ROOT OUT_JSONL
"""

import json
import subprocess
import sys
from multiprocessing import Pool
from pathlib import Path

SUFFIXES = (".whl", ".tar.gz", ".tgz", ".tar.bz2", ".zip")


def one(path):
    rel = str(path.relative_to(ROOT))
    record = {"sample": rel}
    try:
        proc = subprocess.run(
            ["buckthorn", "scan", "--format", "json", str(path)],
            capture_output=True,
            text=True,
            timeout=900,
        )
        record["exit"] = proc.returncode
        if proc.stdout.strip():
            record["result"] = json.loads(proc.stdout)["artifacts"][0]
            record["status"] = "scanned"
        else:
            record["status"] = "error"
            record["stderr"] = proc.stderr[-2000:]
    except Exception as exc:  # recorded per artifact, the run goes on
        record["status"] = "error"
        record["stderr"] = f"{type(exc).__name__}: {exc}"[-2000:]
    return record


ROOT = Path(sys.argv[1])

if __name__ == "__main__":
    paths = sorted(p for p in ROOT.rglob("*") if p.is_file() and p.name.lower().endswith(SUFFIXES))
    with Pool(4) as pool, open(sys.argv[2], "w") as out:
        for i, record in enumerate(pool.imap_unordered(one, paths), 1):
            out.write(json.dumps(record, sort_keys=True) + "\n")
            if i % 200 == 0:
                print(f"{i}/{len(paths)}", flush=True)
    print(f"{len(paths)} done", flush=True)
