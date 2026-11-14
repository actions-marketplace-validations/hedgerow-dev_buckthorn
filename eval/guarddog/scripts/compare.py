"""Join Buckthorn's and GuardDog's results per sample and count agreement.

GuardDog has two levels of rule: threat-* (alarms) and capability-* (what the
code can do). Both are counted, so neither tool is judged on the other's terms.
Usage: python compare.py NAME OURS_JSONL GUARDDOG_JSONL
"""

import collections
import gzip
import json
import sys


def load(path):
    rows = {}
    opener = gzip.open if path.endswith(".gz") else open
    for line in opener(path, "rt"):
        record = json.loads(line)
        rows[record["sample"]] = record
    return rows


def ours_verdict(record):
    return (record.get("result") or {}).get("verdict") or record.get("status")


def gd_verdict(record):
    if record.get("status") != "scanned":
        return record.get("status")
    rules = record.get("rules", {})
    if any(rule.startswith("threat-") for rule in rules):
        return "threat"
    return "capability only" if rules else "nothing"


name, ours, theirs = sys.argv[1], load(sys.argv[2]), load(sys.argv[3])
both = ours.keys() & theirs.keys()
table = collections.Counter((ours_verdict(ours[s]), gd_verdict(theirs[s])) for s in both)
rules = collections.Counter(rule for s in both for rule in theirs[s].get("rules", {}))

print(f"## {name}: {len(both)} samples in both (ours {len(ours)}, GuardDog {len(theirs)})\n")
print("| Buckthorn | GuardDog | Samples |\n|---|---|---|")
for (a, b), count in sorted(table.items()):
    print(f"| {a} | {b} | {count} |")
totals = collections.Counter()
for (a, b), count in table.items():
    totals["buckthorn flagged"] += count * (a == "flagged")
    totals["guarddog threat"] += count * (b == "threat")
    totals["guarddog any rule"] += count * (b in ("threat", "capability only"))
    totals["either flagged or threat"] += count * (a == "flagged" or b == "threat")
print("\n" + ", ".join(f"{k}: {v}" for k, v in totals.items()))
print("\nGuardDog rules by samples hit:", ", ".join(f"{r} {c}" for r, c in rules.most_common(12)))
