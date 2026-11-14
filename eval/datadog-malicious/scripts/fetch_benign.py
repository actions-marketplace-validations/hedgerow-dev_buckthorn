"""Download the latest sdist and one wheel of the top N PyPI packages, sha256-checked.
Usage: python -I fetch_benign.py N OUT_DIR"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

n, out = int(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
top = json.load(
    urllib.request.urlopen(
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    )
)
names = [row["project"] for row in top["rows"][:n]]


def rank(fn):  # prefer a pure wheel, then CPython 3.12 manylinux x86_64
    if fn.endswith("py3-none-any.whl") or fn.endswith("py2.py3-none-any.whl"):
        return 0
    if "cp312" in fn and "manylinux" in fn and "x86_64" in fn:
        return 1
    return 9


for name in names:
    meta = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json"))
    files = meta["urls"]
    picks = [f for f in files if f["packagetype"] == "sdist"][:1]
    wheels = sorted(
        (f for f in files if f["packagetype"] == "bdist_wheel"), key=lambda f: rank(f["filename"])
    )
    picks += [w for w in wheels[:1] if rank(w["filename"]) < 9]
    for f in picks:
        data = urllib.request.urlopen(f["url"]).read()
        if hashlib.sha256(data).hexdigest() != f["digests"]["sha256"]:
            print("HASH MISMATCH", f["filename"])
            continue
        (out / f["filename"]).write_bytes(data)
    print(name, [f["filename"] for f in picks], flush=True)
