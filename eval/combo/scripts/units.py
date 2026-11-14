"""Tuning only: for each wheel or sdist, today's verdict and the call-time units
that hold two or more kinds of hit, as Buckthorn's own reading of the archive
finds them. Records call names and rule kinds, never code or string values.

Runs inside a --network none container. Nothing is installed, imported or run.
Usage:
  python -I units.py files ROOT OUT_JSONL
  python -I units.py datadog CORPUS OUT_JSONL WORK   # rebuilt as run_corpus.py does
  python -I units.py one ARCHIVE                     # one archive, JSON on stdout
"""

import io
import json
import subprocess
import sys
import zipfile
from multiprocessing import Pool
from pathlib import Path

SUFFIXES = (".whl", ".tar.gz", ".tgz", ".tar.bz2", ".zip")
HIDE = {"hidden", "encoded", "discord", "telegram"}


def scan_one(path):
    from buckthorn import code, scan
    from buckthorn.findings import verdict

    files = []

    def spy(name, source, entry=None, whole_file=False):
        entry = entry or {}
        record = {"file": name, "whole": whole_file}
        units = []
        if len(source) > scan.MAX_SOURCE_BYTES:
            record["error"] = "too big"
        else:
            try:
                units = code.call_units(source, entry, whole_file)
                extra = code.analyse(source, False) if whole_file else []
            except Exception as exc:  # recorded, the scan goes on
                record["error"] = type(exc).__name__
            else:
                record["units"] = [
                    {"name": u.name, "hits": sorted({(h.kind, h.detail) for h in u.hits})}
                    for u in units
                    if len({h.kind for h in u.hits}) >= 2
                ]
                record["hide"] = sorted({h.kind for h in extra if h.kind in HIDE})
        if record.get("units") or record.get("hide") or record.get("error"):
            files.append(record)
        return scan._combinations(name, units)  # as _call_findings, without parsing again

    scan.CALL_TIME = True
    scan._call_findings = spy
    findings = scan.scan_artifact(Path(path))
    today = [f for f in findings if not f.rule_id.startswith("BKT-CALL-")]
    return {
        "verdict": verdict(today),
        "rules": sorted({f.rule_id for f in today if f.severity.value != "info"}),
        "call_rules": sorted({f.rule_id for f in findings if f.rule_id.startswith("BKT-CALL-")}),
        "files": files,
    }


def run(path):
    proc = subprocess.run(
        [sys.executable, "-I", __file__, "one", str(path)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if proc.returncode or not proc.stdout.strip():
        return {"status": "error", "stderr": proc.stderr[-1000:]}
    return {"status": "scanned", **json.loads(proc.stdout)}


def one_file(args):
    path, root = args
    record = {"sample": str(path.relative_to(root))}
    try:
        record.update(run(path))
    except Exception as exc:  # recorded per artifact, the run goes on
        record.update(status="error", stderr=f"{type(exc).__name__}: {exc}"[-1000:])
    return record


def one_zip(args):
    sys.path.insert(0, "/driver")  # run_corpus.py, for plan() and rebuild()
    from run_corpus import PWD, plan, rebuild

    zpath, corpus, work_root = args
    rel = str(zpath.relative_to(corpus))
    record = {"sample": rel}
    work = work_root / str(abs(hash(rel)))
    try:
        work.mkdir(parents=True, exist_ok=True)
        zf = zipfile.ZipFile(zpath)
        members = [i for i in zf.infolist() if not i.is_dir()]
        if len(members) == 1 and members[0].filename.endswith(".zip"):
            zf = zipfile.ZipFile(io.BytesIO(zf.read(members[0], pwd=PWD)))
            members = [i for i in zf.infolist() if not i.is_dir()]
        if not members:
            record["status"] = "empty"
            return record
        kind, root, archive, files = plan(zf, zpath.stem)
        path, _ = rebuild(zf, kind, root, archive, files, work)
        record["archive"] = archive
        record.update(run(path))
        path.unlink()
    except Exception as exc:  # recorded per sample, the run goes on
        record.update(status="error", stderr=f"{type(exc).__name__}: {exc}"[-1000:])
    return record


def main():
    mode = sys.argv[1]
    if mode == "one":
        print(json.dumps(scan_one(sys.argv[2])))
        return
    root, out = Path(sys.argv[2]), sys.argv[3]
    if mode == "files":
        paths = sorted(
            p for p in root.rglob("*") if p.is_file() and p.name.lower().endswith(SUFFIXES)
        )
        jobs, worker = [(p, root) for p in paths], one_file
    else:
        jobs, worker = [(z, root, Path(sys.argv[4])) for z in sorted(root.rglob("*.zip"))], one_zip
    with Pool(3) as pool, open(out, "w") as fh:
        for i, record in enumerate(pool.imap_unordered(worker, jobs), 1):
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            if i % 200 == 0:
                print(f"{i}/{len(jobs)}", flush=True)
    print(f"{len(jobs)} done", flush=True)


if __name__ == "__main__":
    main()
