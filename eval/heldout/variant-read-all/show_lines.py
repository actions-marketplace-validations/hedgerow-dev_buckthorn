"""For the triage draw: print each flagging finding's source lines from the benign archive."""

import gzip
import json
import random
import sys
import tarfile
import zipfile

V = {json.loads(line)["sample"]: json.loads(line) for line in gzip.open(sys.argv[1], "rt")}
D = {json.loads(line)["sample"]: json.loads(line) for line in gzip.open(sys.argv[2], "rt")}
COV = {"BKT-SKIP-001", "BKT-SKIP-002", "BKT-SKIP-003", "BKT-SKIP-004", "BKT-SKIP-005"}


def flagged(rec):
    return bool(rec) and rec.get("status") == "scanned" and rec["verdict"] == "flagged"


added = [s for s in V if flagged(V[s]) and not flagged(D.get(s))]
pick = sorted(random.Random(20261116).sample(sorted(added), min(30, len(added))))
for s in pick:
    path = "data/" + s  # run from the folder that holds the held-out data
    if s.endswith(".whl"):
        arc = zipfile.ZipFile(path)
        read = arc.read
    else:
        arc = tarfile.open(path)
        read = lambda n: arc.extractfile(n).read()  # noqa: E731
    print("=====", s)
    seen = 0
    for f in V[s]["findings"]:
        if f["severity"] == "info" or f["rule_id"] in COV or seen >= 4:
            continue
        seen += 1
        try:
            src = read(f["file"]).decode("utf-8", "replace").splitlines()
        except Exception as exc:
            print(" ", f["rule_id"], f["file"], "unreadable", type(exc).__name__)
            continue
        for ln in (f.get("lines") or [])[:2]:
            text = src[ln - 1].strip()[:150] if 0 < ln <= len(src) else "?"
            print(f"  {f['rule_id']} {f['file']}:{ln}: {text}")
