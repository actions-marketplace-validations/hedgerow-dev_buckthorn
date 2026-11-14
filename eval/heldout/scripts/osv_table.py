"""Compact table of OSV MAL reports for PyPI: one JSON line per report.
Usage: python3 -I osv_table.py OSV_PYPI_DIR OUT_JSONL"""
import json
import re
import sys
from pathlib import Path


def norm(n):
    return re.sub(r"[-_.]+", "-", n).lower()


with open(sys.argv[2], "w") as out:
    for p in sorted(Path(sys.argv[1]).rglob("*.json")):
        d = json.loads(p.read_text())
        for a in d.get("affected", []):
            pkg = a.get("package", {})
            if pkg.get("ecosystem") != "PyPI":
                continue
            out.write(json.dumps({
                "id": d.get("id"), "name": norm(pkg.get("name", "")),
                "published": d.get("published"), "modified": d.get("modified"),
                "withdrawn": d.get("withdrawn"),
                "versions": a.get("versions") or [],
                "all_versions": not a.get("versions"),
            }, sort_keys=True) + "\n")
