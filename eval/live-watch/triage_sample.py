"""Draw the day's triage sample per PROTOCOL.md. Usage: python3 -I sample.py RUN DAY"""

import json
import random
import sys
from pathlib import Path

run, day = Path(sys.argv[1]), sys.argv[2]
seen, high, medium = set(), [], []
for line in open(run / "results" / f"{day}.jsonl"):
    r = json.loads(line)
    key = (r["eco"], r["name"], r["version"])
    if r["verdict"] != "flagged" or key in seen:
        continue
    seen.add(key)
    q = f"{r['eco']}/{int(r['scanned'])}-{r['file']}"
    if not (run / "quarantine" / q).exists():
        continue
    item = {"eco": r["eco"], "name": r["name"], "version": r["version"], "q": q}
    (high if any(f[1] in ("high", "critical") for f in r["findings"]) else medium).append(item)


def order(xs):
    return sorted(xs, key=lambda i: (i["eco"], i["name"], i["version"]))


rng = random.Random(day)
pick_high = order(high) if len(high) <= 30 else rng.sample(order(high), 30)
pick_medium = rng.sample(order(medium), min(20, len(medium)))
out = run / "triage" / day
out.mkdir(parents=True, exist_ok=True)
with open(out / "sample.jsonl", "w") as fh:
    for kind, items in (("high", pick_high), ("medium", pick_medium)):
        for i in items:
            fh.write(json.dumps(i | {"kind": kind}) + "\n")
print(
    "flags",
    len(high) + len(medium),
    "high",
    len(high),
    "medium",
    len(medium),
    "sampled",
    len(pick_high),
    len(pick_medium),
)
