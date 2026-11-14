"""Run GuardDog on the same archives Buckthorn read, for a head-to-head.

Runs inside a --network none container. Records which GuardDog rules matched
and how often, not the matched code (samples hold live webhook URLs).
Usage:
  python -I gd_scan.py files ROOT OUT_JSONL           # wheels and sdists under ROOT
  python -I gd_scan.py datadog CORPUS OUT_JSONL WORK  # DataDog zips, rebuilt as run_corpus.py does
"""

import io
import json
import subprocess
import sys
import zipfile
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, "/driver-dd")  # datadog-malicious/scripts, for plan() and rebuild()

SUFFIXES = (".whl", ".tar.gz", ".tgz", ".tar.bz2", ".zip")


def guarddog(path):
    proc = subprocess.run(
        ["guarddog", "pypi", "scan", str(path), "--output-format", "json"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    record: dict = {"exit": proc.returncode}
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        record["status"] = "error"
        record["stderr"] = proc.stderr[-1000:]
        return record
    record["status"] = "scanned"
    record["rules"] = {
        rule: len(hits) if isinstance(hits, list) else 1
        for rule, hits in (report.get("results") or {}).items()
        if hits
    }
    for key in ("errors", "issues"):
        if report.get(key):
            record[key] = report[key] if key == "issues" else list(report[key])[:20]
    return record


def one_file(args):
    path, root = args
    record: dict = {"sample": str(path.relative_to(root))}
    try:
        record.update(guarddog(path))
    except Exception as exc:  # recorded per artifact, the run goes on
        record.update(status="error", stderr=f"{type(exc).__name__}: {exc}"[-1000:])
    return record


def one_zip(args):
    from run_corpus import PWD, plan, rebuild

    zpath, corpus, work_root = args
    rel = str(zpath.relative_to(corpus))
    record: dict = {"sample": rel, "category": rel.split("/", 1)[0]}
    work = work_root / str(abs(hash(rel)))
    try:
        work.mkdir(parents=True, exist_ok=True)
        zf = zipfile.ZipFile(zpath)
        files = [i for i in zf.infolist() if not i.is_dir()]
        if len(files) == 1 and files[0].filename.endswith(".zip"):
            zf = zipfile.ZipFile(io.BytesIO(zf.read(files[0], pwd=PWD)))
            files = [i for i in zf.infolist() if not i.is_dir()]
        if not files:
            record["status"] = "empty"
            return record
        kind, root, archive, members = plan(zf, zpath.stem)
        path, _ = rebuild(zf, kind, root, archive, members, work)
        record["archive"] = archive
        record.update(guarddog(path))
        path.unlink()
    except Exception as exc:
        record.update(status="error", stderr=f"{type(exc).__name__}: {exc}"[-1000:])
    return record


if __name__ == "__main__":
    mode, root, out = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
    if mode == "files":
        paths = sorted(p for p in root.rglob("*") if p.is_file() and p.name.lower().endswith(SUFFIXES))
        jobs, fn = [(p, root) for p in paths if "/.git/" not in str(p)], one_file
    else:
        work = Path(sys.argv[4])
        jobs, fn = [(z, root, work) for z in sorted(root.rglob("*.zip"))], one_zip
    with Pool(4) as pool, open(out, "w") as fh:
        for i, record in enumerate(pool.imap_unordered(fn, jobs), 1):
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            if i % 200 == 0:
                print(f"{i}/{len(jobs)}", flush=True)
    print(f"{len(jobs)} done", flush=True)
