"""For samples the diff called clean, list the files that differ from the version before.

Runs in a --network none container. Names and sizes only, never content.
Usage: python -I changed.py SAMPLES_DIR DIFF.jsonl... > OUT.jsonl
"""

import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path

samples = Path(sys.argv[1])
clean = set()
for part in sys.argv[2:]:
    for line in open(part):
        r = json.loads(line)
        if r.get("verdict") in ("clean", "not_verified"):
            clean.add((r["sample"], r.get("verdict")))
for zname, verdict in sorted(clean):
    zf = zipfile.ZipFile(samples / "zips" / zname)
    infos = [i for i in zf.infolist() if not i.is_dir()]
    manifest = min(
        (i.filename for i in infos if i.filename.endswith("/package/package.json")),
        key=len,
        default=None,
    )
    if manifest is None:
        continue
    root = manifest[: -len("package.json")]
    new = {
        i.filename[len(root) :]: hashlib.sha256(zf.read(i, pwd=b"infected")).hexdigest()
        for i in infos
        if i.filename.startswith(root)
    }
    old = {}
    prev = samples / "prev" / zname.replace(".zip", ".tgz")
    if prev.is_file():
        with tarfile.open(prev) as tf:
            for m in tf.getmembers():
                if m.isfile():
                    old[m.name.split("/", 1)[-1]] = hashlib.sha256(
                        tf.extractfile(m).read()
                    ).hexdigest()
    changed = sorted(n for n, h in new.items() if old.get(n) != h)
    pkg = json.loads(zf.read(manifest, pwd=b"infected"))
    print(
        json.dumps(
            {
                "sample": zname,
                "verdict": verdict,
                "has_prev": bool(old),
                "changed": changed[:15],
                "n_changed": len(changed),
                "main": pkg.get("main"),
                "scripts": sorted(pkg.get("scripts") or {}),
            }
        )
    )
