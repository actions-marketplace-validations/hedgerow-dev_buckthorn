"""Hash each archive and the .py files inside it, for de-duplication and family links.

Runs inside a --network none container with the corpus read-only. Members are read
into memory only; nothing is written out but hashes. One JSON line per archive.
Usage:
  python -I file_hashes.py files ROOT OUT_JSONL      # wheels, sdists, zips under ROOT
  python -I file_hashes.py datadog ROOT OUT_JSONL    # DataDog encrypted zips
"""

import hashlib
import io
import json
import sys
import tarfile
import zipfile
from multiprocessing import Pool
from pathlib import Path

PWD = b"infected"
MIN_PY = 512
MAX_MEMBER = 20_000_000
SUFFIXES = (".whl", ".tar.gz", ".tgz", ".tar.bz2", ".zip")


def py_hashes(pairs):
    out = set()
    for name, read in pairs:
        if name.endswith(".py"):
            data = read()
            if len(data) >= MIN_PY:
                out.add(hashlib.sha256(data).hexdigest())
    return sorted(out)


def zip_pairs(zf, pwd=None):
    return [
        (i.filename, lambda i=i: zf.read(i, pwd=pwd))
        for i in zf.infolist()
        if not i.is_dir() and i.file_size < MAX_MEMBER
    ]


def one_file(args):
    path, root = args
    rec = {"sample": str(path.relative_to(root))}
    try:
        data = path.read_bytes()
        rec["sha256"] = hashlib.sha256(data).hexdigest()
        rec["magic"] = data[:4].hex()
        if data[:2] == b"PK":
            rec["pyhashes"] = py_hashes(zip_pairs(zipfile.ZipFile(io.BytesIO(data))))
        else:
            tf = tarfile.open(fileobj=io.BytesIO(data))
            members = [m for m in tf.getmembers() if m.isfile() and m.size < MAX_MEMBER]
            rec["pyhashes"] = py_hashes(
                [(m.name, lambda m=m: tf.extractfile(m).read()) for m in members]
            )
    except Exception as exc:  # recorded per archive
        rec["error"] = type(exc).__name__
    return rec


def one_zip(args):
    path, root = args
    rec = {"sample": str(path.relative_to(root))}
    try:
        zf = zipfile.ZipFile(path)
        inner = [i for i in zf.infolist() if not i.is_dir()]
        if len(inner) == 1 and inner[0].filename.endswith(".zip"):
            zf = zipfile.ZipFile(io.BytesIO(zf.read(inner[0], pwd=PWD)))
        rec["pyhashes"] = py_hashes(zip_pairs(zf, PWD))
    except Exception as exc:
        rec["error"] = type(exc).__name__
    return rec


if __name__ == "__main__":
    mode, root, out = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
    if mode == "files":
        paths = sorted(
            p for p in root.rglob("*")
            if p.is_file() and p.name.lower().endswith(SUFFIXES) and "/.git/" not in str(p)
        )
        fn = one_file
    else:
        paths, fn = sorted(root.rglob("*.zip")), one_zip
    with Pool(4) as pool, open(out, "w") as fh:
        for rec in pool.imap_unordered(fn, [(p, root) for p in paths], chunksize=8):
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    print(f"{len(paths)} done", flush=True)
