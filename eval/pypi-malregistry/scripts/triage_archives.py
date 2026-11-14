"""Where risky calls sit in each missed archive (malregistry). Text only, nothing runs.
Usage: python -I triage_archives.py ROOT LIST OUT"""

import ast
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, "/driver")
from triage import calls  # noqa: E402

root, names, out = Path(sys.argv[1]), Path(sys.argv[2]).read_text().split(), sys.argv[3]


def members(path):
    data = path.read_bytes()
    if data[:2] == b"PK":
        zf = zipfile.ZipFile(io.BytesIO(data))
        return [
            (i.filename, zf.read(i))
            for i in zf.infolist()
            if not i.is_dir() and i.file_size < 5_000_000
        ]
    tf = tarfile.open(fileobj=io.BytesIO(data))
    return [
        (m.name, tf.extractfile(m).read())
        for m in tf.getmembers()
        if m.isfile() and m.size < 5_000_000
    ]


with open(out, "w") as fh:
    for rel in names:
        row = {"sample": rel, "files": []}
        try:
            mem = members(root / rel)
        except Exception as exc:
            row["error"] = type(exc).__name__
            fh.write(json.dumps(row) + "\n")
            continue
        top = {n.split("/")[0] for n, _ in mem}
        strip = len(top) == 1 and all("/" in n for n, _ in mem)
        for name, data in mem:
            rel_name = name.split("/", 1)[1] if strip else name
            entry = {"path": rel_name, "size": len(data)}
            if rel_name.endswith(".py"):
                try:
                    entry["calls"] = sorted({f"{n}@{w}" for n, w in calls(ast.parse(data))})
                except Exception as exc:
                    entry["parse_error"] = type(exc).__name__
            elif rel_name.endswith(("PKG-INFO", "METADATA")):
                entry["requires"] = [
                    l[14:]
                    for l in data.decode("utf-8", "replace").splitlines()
                    if l.startswith("Requires-Dist:")
                ][:8]
            row["files"].append(entry)
        fh.write(json.dumps(row) + "\n")
