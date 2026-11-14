"""Draw the protocol's random triage samples.

  python3 -I triage_sample.py misses BKT.jsonl.gz SCAN_LIST OUT     # 50 malicious misses, seed 20261114
  python3 -I triage_sample.py flags  BKT.jsonl.gz SCAN_LIST OUT     # 50 benign flags, seed 20261113
"""

import gzip
import json
import random
import sys

kind, bkt, lst, out = sys.argv[1:5]
results = {}
for line in gzip.open(bkt, "rt"):
    r = json.loads(line)
    results[r["sample"]] = r
samples = [l.strip() for l in open(lst) if l.strip()]


def flagged(s):
    r = results.get(s) or {}
    return r.get("status") == "scanned" and r.get("verdict") == "flagged"


if kind == "misses":
    pool, seed = sorted(s for s in samples if not flagged(s)), 20261114
else:
    pool, seed = sorted(s for s in samples if flagged(s)), 20261113
pick = sorted(random.Random(seed).sample(pool, min(50, len(pool))))
open(out, "w").write("".join(p + "\n" for p in pick))
print(f"{kind}: {len(pick)} of {len(pool)}")
