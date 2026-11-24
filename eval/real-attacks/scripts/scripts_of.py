"""Print the lifecycle script names, and whether each names bundle.js, for the 2025-09-14 samples."""

import json
import zipfile

rows = [l.split("\t") for l in open("/s/picked.tsv").read().splitlines()]
for z, _, _, p in rows:
    if "/2025-09-14-" not in p:
        continue
    zf = zipfile.ZipFile("/s/zips/" + z)
    manifest = min(
        (i.filename for i in zf.infolist() if i.filename.endswith("/package/package.json")), key=len
    )
    scripts = json.loads(zf.read(manifest, pwd=b"infected")).get("scripts") or {}
    life = {
        k: ("bundle.js" in str(v))
        for k, v in scripts.items()
        if k in ("preinstall", "install", "postinstall", "prepare")
    }
    print(p.split("/")[3], p.split("/")[4], life)
