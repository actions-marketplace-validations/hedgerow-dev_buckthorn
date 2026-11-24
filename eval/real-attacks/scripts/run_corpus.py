"""Rebuild each DataDog sample into a wheel or sdist and run `buckthorn scan --format json`.

Runs inside a --network none container. The dataset stores each package as an
unpacked tree in an encrypted zip. Members are copied from the zip straight into
a new archive: no tree is written to disk, nothing is installed, imported or run.
Usage: python -I run_corpus.py CORPUS_DIR OUT_DIR WORK_DIR
"""

import email.parser
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from multiprocessing import Pool
from pathlib import Path

PWD = b"infected"


def members(zf):
    """(clean_name, ZipInfo) for every file. Undo the dataset's doubled paths."""
    out = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        parts = info.filename.split("/")
        # Some samples store "P/a/b" as "P/a/b/a/b": drop a repeated tail.
        for k in range(len(parts) // 2, 0, -1):
            if parts[-2 * k : -k] == parts[-k:]:
                parts = parts[:-k]
                break
        out.append(("/".join(parts), info))
    return out


def shallowest(names, pred):
    hits = [n for n in names if pred(n)]
    return min(hits, key=lambda n: n.count("/")) if hits else None


def parent(name):
    return name.rsplit("/", 1)[0] if "/" in name else ""


def under(root, name):
    return name[len(root) + 1 :] if root else name


def plan(zf, sample_name):
    """Decide what archive to rebuild. Returns (kind, root, archive_name, notes)."""
    files = members(zf)
    names = [n for n, _ in files]
    meta = shallowest(names, lambda n: re.search(r"[^/]+\.dist-info/METADATA$", n))
    if meta:
        distinfo = parent(meta)
        root = parent(distinfo)
        wheel_file = distinfo + "/WHEEL"
        tag = "py3-none-any"
        if wheel_file in names:
            info = dict(files)[wheel_file]
            text = zf.read(info, pwd=PWD).decode("utf-8", "replace")
            m = re.search(r"^Tag:\s*(\S+)", text, re.M)
            if m:
                tag = m.group(1)
        stem = distinfo.rsplit("/", 1)[-1][: -len(".dist-info")]
        return "wheel", root, f"{stem}-{tag}.whl", files
    pkg = shallowest(names, lambda n: n.endswith("PKG-INFO") and ".egg-info/" not in n)
    if pkg:
        root = parent(pkg)
        base = root.rsplit("/", 1)[-1]
        if not re.match(r"^.+-\d[^/]*$", base):
            msg = email.parser.Parser().parsestr(
                zf.read(dict(files)[pkg], pwd=PWD).decode("utf-8", "replace")
            )
            base = f"{msg.get('Name', 'unknown')}-{msg.get('Version', '0')}"
        return "sdist", root, f"{base}.tar.gz", files
    # A source tree with no PKG-INFO (the compromised-library samples are git checkouts).
    marker = shallowest(names, lambda n: n.rsplit("/", 1)[-1] in ("setup.py", "pyproject.toml"))
    info_json = shallowest(names, lambda n: re.search(r"package_info-.*\.json$", n))
    root = parent(marker or info_json or names[0])
    m = re.match(r"^\d{4}-\d\d-\d\d-(.+?)(?:-v(.+))?$", sample_name)
    base = f"{m.group(1)}-{m.group(2) or '0'}" if m else sample_name
    return "source", root, f"{base}.tar.gz", files


def rebuild(zf, kind, root, archive, files, work):
    path = work / archive
    keep = [
        (under(root, n), info)
        for n, info in files
        if (not root or n.startswith(root + "/"))
        and not re.search(r"(^|/)package_info-[^/]*\.json$", n)
    ]
    if kind == "wheel":
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as out:
            for name, info in keep:
                out.writestr(name, zf.read(info, pwd=PWD))
    else:
        top = archive[: -len(".tar.gz")]
        with tarfile.open(path, "w:gz") as out:
            for name, info in keep:
                data = zf.read(info, pwd=PWD)
                ti = tarfile.TarInfo(f"{top}/{name}")
                ti.size = len(data)
                out.addfile(ti, io.BytesIO(data))
    return path, len(keep)


def one(args):
    zpath, corpus, out_dir, work_root = args
    rel = str(zpath.relative_to(corpus))
    # Some sample names run past the file-name limit: a short hash keeps names unique.
    sid = hashlib.sha256(rel.encode()).hexdigest()[:10] + "-" + zpath.stem[:80]
    record = {"sample": rel, "category": rel.split("/", 1)[0]}
    work = work_root / sid
    try:
        work.mkdir(parents=True, exist_ok=True)
        zf = zipfile.ZipFile(zpath)
        files = [i for i in zf.infolist() if not i.is_dir()]
        # One sample stores its zip inside the zip.
        if len(files) == 1 and files[0].filename.endswith(".zip"):
            zf = zipfile.ZipFile(io.BytesIO(zf.read(files[0], pwd=PWD)))
            record["note"] = "nested zip"
            files = [i for i in zf.infolist() if not i.is_dir()]
        if not files:
            record["status"] = "empty"
        else:
            kind, root, archive, members_ = plan(zf, zpath.stem)
            path, count = rebuild(zf, kind, root, archive, members_, work)
            record.update(kind=kind, root=root, archive=archive, files=count)
            proc = subprocess.run(
                ["buckthorn", "scan", "--format", "json", str(path)],
                capture_output=True,
                text=True,
                timeout=900,
            )
            record["exit"] = proc.returncode
            if proc.stdout.strip():
                report = json.loads(proc.stdout)
                record["result"] = report["artifacts"][0]
                record["status"] = "scanned"
            else:
                record["status"] = "error"
                record["stderr"] = proc.stderr[-2000:]
            path.unlink()
    except Exception as exc:  # recorded per sample, the run goes on
        record["status"] = "error"
        record["stderr"] = f"{type(exc).__name__}: {exc}"[-2000:]
    (out_dir / f"{sid}.json").write_text(json.dumps(record, indent=1))
    return rel, record.get("status"), (record.get("result") or {}).get("verdict")


def main():
    corpus, out_dir, work = (Path(a) for a in sys.argv[1:4])
    out_dir.mkdir(parents=True, exist_ok=True)
    zips = sorted(corpus.rglob("*.zip"))
    jobs = [(z, corpus, out_dir, work) for z in zips]
    with Pool(4) as pool:
        for i, (rel, status, verdict) in enumerate(pool.imap_unordered(one, jobs), 1):
            print(f"{i}/{len(jobs)} {status} {verdict} {rel}", flush=True)


if __name__ == "__main__":
    main()
