"""For each cached top package: how many JavaScript files it ships and how
many the npm rules read, to find packages whose code is missed (a clean
verdict with nothing read). Nothing is unpacked or run.
Usage: python3 -I reach_top.py REPO CACHE OUT.jsonl
"""

import json
import posixpath
import sys
from pathlib import Path

REPO, CACHE, OUT = sys.argv[1:4]
sys.path.insert(0, REPO)

from buckthorn import npm  # noqa: E402
from buckthorn.scan import read_archive  # noqa: E402

JS = (".js", ".cjs", ".mjs")
with open(OUT, "w") as out:
    for line in open(Path(CACHE) / "index.jsonl"):
        row = json.loads(line)
        if row.get("status") != "ok":
            continue
        members, _ = read_archive(Path(CACHE) / row["file"])
        files, tops = {}, {}
        for name, data in members:
            top, sep, rest = posixpath.normpath(name).lstrip("/").partition("/")
            if sep:
                files[rest], tops[rest] = data, top
        manifest = json.loads(files["package.json"])
        package = npm._Package(files, tops, manifest)
        package.install()
        package.load()
        shipped = [p for p in files if p.endswith(JS) and not p.startswith("node_modules/")]
        record = {
            "rank": row["rank"],
            "name": row["name"],
            "js": len(shipped),
            "read": len(package.read),
            "entries": len(package.entries()),
            "fields": sorted(k for k in ("main", "exports", "module", "browser", "bin") if k in manifest),
        }
        out.write(json.dumps(record) + "\n")
