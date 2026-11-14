"""Verdict counts for the read-all variant on the tuning corpora, and benign files
added or lost against the default (../../guarddog/buckthorn/benign.jsonl.gz).
Result files only. Usage: python3 -I tuning_counts.py OUT_DIR DEFAULT_BENIGN_JSONL_GZ
"""

import collections
import gzip
import json
import sys
from pathlib import Path


def verdict(rec):
    if rec.get("status") != "scanned":
        return rec.get("status") or "error"
    return rec["result"]["verdict"]


out, default = Path(sys.argv[1]), sys.argv[2]
sets = {
    "benign": [json.loads(line) for line in open(out / "benign.jsonl")],
    "malreg": [json.loads(line) for line in open(out / "malreg.jsonl")],
    "datadog": [json.loads(p.read_text()) for p in sorted((out / "dd").glob("*.json"))],
}
for name, recs in sets.items():
    c = collections.Counter(verdict(r) for r in recs)
    print(name, len(recs), dict(c.most_common()))
    slow = [r["sample"] for r in recs if r.get("status") == "error" or "Timeout" in r.get("stderr", "")]
    print("  errors or timeouts:", slow[:20])
D = {json.loads(line)["sample"]: json.loads(line) for line in gzip.open(default, "rt")}
V = {r["sample"]: r for r in sets["benign"]}
added = sorted(s for s in V if verdict(V[s]) == "flagged" and verdict(D.get(s, {})) != "flagged")
lost = sorted(s for s in V if verdict(V[s]) != "flagged" and verdict(D.get(s, {})) == "flagged")
print(f"benign: default flagged {sum(verdict(r) == 'flagged' for r in D.values())}, added {len(added)}, lost {len(lost)} {lost}")
rules = collections.Counter(
    f["rule_id"]
    for s in added
    for f in {(x["rule_id"], x["severity"]): x for x in V[s]["result"]["findings"]}.values()
    if f["severity"] != "info"
)
print("rules on added benign flags:", rules.most_common(12))
