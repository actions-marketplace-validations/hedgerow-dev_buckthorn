"""Where Buckthorn and GuardDog differ, per sample. Usage: python3 -I overlap.py BKT.jsonl.gz GD.jsonl.gz"""

import collections
import gzip
import json
import sys

B = {json.loads(l)["sample"]: json.loads(l) for l in gzip.open(sys.argv[1], "rt")}
G = {json.loads(l)["sample"]: json.loads(l) for l in gzip.open(sys.argv[2], "rt")}
c = collections.Counter()
for s in B.keys() & G.keys():
    bf = B[s].get("verdict") == "flagged"
    gt = any(r.startswith("threat-") for r in G[s].get("rules", {}))
    c[("Buckthorn flagged" if bf else "Buckthorn not flagged", "GuardDog threat" if gt else "GuardDog no threat")] += 1
for k, v in sorted(c.items()):
    print(k, v)
nv = [s for s, r in B.items() if r.get("verdict") == "not_verified"]
print("not_verified:", nv, [sorted({f["rule_id"] for f in B[s]["findings"]}) for s in nv])
