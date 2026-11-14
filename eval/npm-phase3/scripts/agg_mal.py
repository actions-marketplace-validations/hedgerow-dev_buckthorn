"""Summarise run_mal.py output against phase 1's: rule ids and verdicts only.
Usage: python3 -I agg_mal.py NEW.jsonl PHASE1.jsonl
"""

import collections
import json
import sys

new = {r["n"]: r for r in map(json.loads, open(sys.argv[1]))}
old = {r["n"]: r for r in map(json.loads, open(sys.argv[2]))}
CATEGORIES = ("compromised_lib", "malicious_intent")


def group(rule: str, path: str) -> str | None:
    """Which phase 3 rule group a finding above info belongs to."""
    if rule.startswith("BKT-NPM-INSTALL-"):
        return "install (JS)" if not path.endswith("/package.json") or rule != "BKT-NPM-INSTALL-001" else None
    if rule.startswith("BKT-NPM-IMPORT-"):
        return "import"
    if rule.startswith("BKT-NPM-HIDE-"):
        return "hide"
    if rule.startswith("BKT-EXFIL-") and not path.endswith("/package.json"):
        return "exfil (JS)"
    return None


def groups(record: dict) -> set[str]:
    found = set()
    for rule, severity, path, _, _ in record.get("findings", []):
        if severity != "info" and (g := group(rule, path)):
            found.add(g)
    return found


print("statuses:", collections.Counter(r["status"] for r in new.values()))
for category in CATEGORIES:
    rows = [r for r in new.values() if r["category"] == category and r["status"] == "scanned"]
    print(f"\n== {category} ({len(rows)})")
    print("  phase 3 verdicts:", dict(collections.Counter(r["verdict"] for r in rows)))
    print("  phase 1 verdicts:", dict(collections.Counter(old[r["n"]]["verdict"] for r in rows)))
    by_group = collections.Counter(g for r in rows for g in groups(r))
    print("  samples flagged by each group:", dict(by_group))
    newly = [r for r in rows if r["verdict"] == "flagged" and old[r["n"]]["verdict"] != "flagged"]
    print("  newly flagged:", len(newly), dict(collections.Counter(g for r in newly for g in groups(r))))
    only = collections.Counter(
        tuple(sorted(groups(r))) for r in rows if groups(r)
    )
    print("  group combinations:", dict(only))
    rules = collections.Counter(
        rule for r in rows for rule in {f[0] for f in r["findings"] if f[1] != "info"}
    )
    print("  samples per rule above info:", dict(sorted(rules.items())))
    moved = collections.Counter((old[r["n"]]["verdict"], r["verdict"]) for r in rows)
    print("  phase 1 -> phase 3:", dict(moved))
    missed = [r for r in rows if r["verdict"] != "flagged"]
    for r in missed:
        notes = collections.Counter(
            f[0] for f in r["findings"] if f[0].startswith("BKT-SKIP") or f[1] == "info"
        )
        print(f"    missed n={r['n']} {r['verdict']} js={r.get('js')} {dict(notes)}")
for r in new.values():
    if r["status"] != "scanned":
        print("  not scanned:", r["n"], r["category"], r["status"], r.get("error"))
