"""Rescan archives whose name hides their format: copy each by magic bytes to a
correctly named file in WORK, then run buckthorn on it. Usage: ROOT LIST OUT WORK"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

root, names, out, work = (
    Path(sys.argv[1]),
    Path(sys.argv[2]).read_text().split(),
    sys.argv[3],
    Path(sys.argv[4]),
)
with open(out, "w") as fh:
    for i, rel in enumerate(names):
        src = root / rel
        head = src.read_bytes()[:4]
        stem = src.name.removesuffix(".tar.gz")
        if head.startswith(b"PK") and src.name.endswith(".tar.gz"):
            dest = (
                work
                / f"{i}"
                / (stem + ".whl" if stem.endswith("-any") or "-py" in stem else stem + ".zip")
            )
        elif head.startswith((b"PK", b"\x1f\x8b")):
            dest = work / f"{i}" / src.name
        else:
            fh.write(
                json.dumps({"sample": rel, "status": "unreadable", "magic": head.hex()}) + "\n"
            )
            continue
        dest.parent.mkdir(parents=True)
        shutil.copyfile(src, dest)
        proc = subprocess.run(
            ["buckthorn", "scan", "--format", "json", str(dest)],
            capture_output=True,
            text=True,
            timeout=900,
        )
        rec = {"sample": rel, "renamed": dest.name, "status": "scanned"}
        rec["result"] = json.loads(proc.stdout)["artifacts"][0] if proc.stdout.strip() else None
        fh.write(json.dumps(rec) + "\n")
        shutil.rmtree(dest.parent)
