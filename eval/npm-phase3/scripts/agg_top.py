"""Summarise scan_top.py output for triage. Usage: python3 -I agg_top.py OUT.jsonl [RULE_PREFIX]

Prints verdicts, then every finding of the code rules (or of RULE_PREFIX) with
its package and message, then the coverage notes by kind.
"""

import json
import re
import sys
from collections import Counter

rows = [json.loads(line) for line in open(sys.argv[1])]
prefix = sys.argv[2] if len(sys.argv) > 2 else ("BKT-NPM-INSTALL", "BKT-NPM-IMPORT", "BKT-NPM-HIDE")
prefix = tuple(prefix.split(",")) if isinstance(prefix, str) else prefix
errors = [r for r in rows if r.get("scan") != "ok"]
print(f"scanned: {len(rows)}, scan errors: {len(errors)}")
for r in errors:
    print("  error:", r["rank"], r["name"], r["scan"])
ok = [r for r in rows if r.get("scan") == "ok"]
print("verdicts:", dict(Counter(r["verdict"] for r in ok)))

by_rule: dict[str, list] = {}
for r in sorted(ok, key=lambda r: r["rank"]):
    for rule, severity, path, message, lines in r["findings"]:
        if rule.startswith(prefix) or rule.startswith("BKT-EXFIL"):
            by_rule.setdefault(f"{rule} {severity}", []).append((r["name"], path, message, lines))
for rule, found in sorted(by_rule.items()):
    print(f"\n{rule}: {len(found)} findings in {len({n for n, *_ in found})} packages")
    for name, path, message, lines in found:
        print(f"  {name}: {path} {lines[:5] if lines else ''} {message[:300]}")

notes = Counter()
for r in ok:
    for rule, _, _, message, _ in r["findings"]:
        if rule == "BKT-SKIP-003":
            notes[re.sub(r"\d+", "N", message)[:120]] += 1
print("\ncoverage notes:")
for message, n in notes.most_common(40):
    print(f"  {n:5} {message}")
print("\nslowest:", sorted(((r["s"], r["name"]) for r in ok), reverse=True)[:5])
