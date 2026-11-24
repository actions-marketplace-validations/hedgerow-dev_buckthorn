import json
import sys
import zipfile
from pathlib import Path

s = Path(sys.argv[1])
for line in open(sys.argv[2]):
    r = json.loads(line)
    if not r["added"]:
        continue
    zf = zipfile.ZipFile(s / "zips" / r["sample"])
    m = min(
        (i.filename for i in zf.infolist() if i.filename.endswith("/package/package.json")), key=len
    )
    pkg = json.loads(zf.read(m, pwd=b"infected"))
    kinds = {}
    for field, names in r["added"].items():
        for n in names:
            v = str((pkg.get(field) or {}).get(n, ""))
            kinds[n] = (
                "url" if any(t in v for t in ("://", "github:", "git+", "file:")) else "registry"
            )
    print(json.dumps({"sample": r["sample"], "kinds": kinds}))
