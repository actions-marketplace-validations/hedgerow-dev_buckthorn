"""For missed samples: which package.json fields changed, which dependency names were added,
where a new file is referenced, and whether binding.gyp uses <!( command expansion.
Names and booleans only. Runs in a --network none container.
Usage: python -I manifest_diff.py SAMPLES_DIR CHANGED.jsonl
"""

import json
import sys
import tarfile
import zipfile
from pathlib import Path

samples = Path(sys.argv[1])
for line in open(sys.argv[2]):
    r = json.loads(line)
    zf = zipfile.ZipFile(samples / "zips" / r["sample"])
    infos = [i for i in zf.infolist() if not i.is_dir()]
    manifest = min(
        (i.filename for i in infos if i.filename.endswith("/package/package.json")), key=len
    )
    root = manifest[: -len("package.json")]
    new = json.loads(zf.read(manifest, pwd=b"infected"))
    old = {}
    prev = samples / "prev" / r["sample"].replace(".zip", ".tgz")
    if prev.is_file():
        with tarfile.open(prev) as tf:
            m = next(
                (m for m in tf.getmembers() if m.name.split("/", 1)[-1] == "package.json"), None
            )
            if m:
                old = json.loads(tf.extractfile(m).read())
    fields = sorted(k for k in set(new) | set(old) if k != "version" and new.get(k) != old.get(k))
    added = {}
    for dep in ("dependencies", "optionalDependencies", "peerDependencies"):
        a = sorted(set(new.get(dep) or {}) - set(old.get(dep) or {}))
        if a:
            added[dep] = a
    text = json.dumps(new)
    refs = {
        f: [k for k, v in new.items() if f in json.dumps(v)]
        for f in r["changed"]
        if f != "package.json" and f in text
    }
    gyp = [i for i in infos if i.filename.startswith(root) and i.filename.endswith("binding.gyp")]
    expands = any(b"<!(" in zf.read(i, pwd=b"infected") for i in gyp)
    print(
        json.dumps(
            {
                "sample": r["sample"],
                "fields": fields,
                "added": added,
                "refs": refs,
                "gyp": bool(gyp),
                "gyp_expands": expands,
            }
        )
    )
