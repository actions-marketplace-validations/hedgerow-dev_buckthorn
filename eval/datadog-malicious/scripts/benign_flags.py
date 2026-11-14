"""List every finding above info on a benign scan, grouped by rule and message shape.

Usage: python3 benign_flags.py SCAN_JSONL
"""

import collections
import json
import re
import sys

rows = [json.loads(line) for line in open(sys.argv[1])]
verdicts = collections.Counter(r.get("result", {}).get("verdict", r["status"]) for r in rows)
print("files:", len(rows), dict(verdicts))
groups = collections.defaultdict(list)
for r in rows:
    for f in r.get("result", {}).get("findings", []):
        if f["severity"] == "info":
            continue
        # Group by rule and the message with names and numbers taken out.
        shape = re.sub(r"\(in [^)]*\)", "(in F)", f["message"])
        shape = re.sub(r"\d+", "N", shape)[:110]
        groups[(f["rule_id"], shape)].append(f"{r['sample']} :: {f['file']}")
for (rule, shape), where in sorted(groups.items(), key=lambda g: -len(g[1])):
    print(f"\n{len(where):4} {rule} {shape}")
    for w in where:
        print("       ", w[:150])
