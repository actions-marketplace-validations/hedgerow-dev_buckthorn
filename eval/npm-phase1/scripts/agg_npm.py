"""Aggregate npm run results: rule ids and verdicts only. Usage: python3 -I agg_npm.py OUT_DIR FETCH_LOG"""

import collections
import json
import sys
from pathlib import Path

out, log = Path(sys.argv[1]), Path(sys.argv[2])
names = {}
for line in log.read_text().splitlines():
    parts = line.split()
    if len(parts) >= 3 and parts[0].isdigit():
        names[f"{int(parts[0]):03d}"] = parts[1]


def flagged_rules(rec):
    return sorted({r for r, sev, _, _ in rec["findings"] if sev != "info" and not r.startswith("BKT-SKIP")})


print("== benign")
ben = [json.loads(x) for x in (out / "benign.jsonl").read_text().splitlines()]
print(collections.Counter(r["verdict"] for r in ben))
for r in ben:
    name = names.get(r["file"].split("/")[0], r["file"])
    detail = sorted({(rule, sev, s) for rule, sev, _, s in r["findings"] if rule != "BKT-SKIP-003"})
    if r["verdict"] == "flagged" or detail:
        print(f"  {name:22} {r['verdict']:13} {detail}")
skips = collections.Counter(
    rule for r in ben for rule, *_ in r["findings"] if rule.startswith("BKT-SKIP")
)
print("  skip rules:", skips)

print("== malicious")
mal = [json.loads(x) for x in (out / "mal.jsonl").read_text().splitlines()]
print(collections.Counter(r["status"] for r in mal))
for cat in ("compromised_lib", "malicious_intent"):
    rs = [r for r in mal if r["category"] == cat and r["status"] == "scanned"]
    print(cat, len(rs), collections.Counter(r["verdict"] for r in rs))
    by_rule = collections.Counter(rule for r in rs for rule in flagged_rules(r))
    print("  samples per flagged rule:", dict(by_rule))
    scripts = collections.Counter(
        s for r in rs for rule, sev, _, s in r["findings"] if rule == "BKT-NPM-SCRIPT-001" and sev == "medium"
    )
    print("  SCRIPT-001 medium by script:", dict(scripts))
    nojs = [r for r in rs if r["js"] == 0]
    print("  no .js files:", len(nojs), collections.Counter(r["verdict"] for r in nojs))
    only_meta = [r for r in rs if flagged_rules(r) == ["BKT-NPM-META-001"]]
    print("  flagged by META-001 alone:", len(only_meta))
    big = [r for r in rs if r.get("outside_root")]
    print("  samples with files outside package root:", len(big))
    print("  file count min/median/max:", sorted(r["files"] for r in rs)[:: max(1, len(rs) // 4)])
    missed = [r for r in rs if r["verdict"] != "flagged"]
    print("  missed:", len(missed), collections.Counter(r["verdict"] for r in missed))
    print("    with js:", sum(r["js"] > 0 for r in missed), "no js:", sum(r["js"] == 0 for r in missed))
    print("    exts:", collections.Counter(e for r in missed for e in r.get("exts", [])).most_common(10))
    print("    keys:", collections.Counter(k for r in missed for k in (r.get("keys") or [])).most_common(14))
    print("    has deps:", sum(bool(r.get("deps")) for r in missed), "dep url/git:", sum(bool(r.get("dep_url")) for r in missed))
    for r in missed:
        if r["js"] == 0:
            print("    no-js miss:", r["n"], r["verdict"], r.get("exts"), r.get("keys"), r.get("deps"), r.get("dep_url"))
for r in mal:
    if r["status"] != "scanned":
        print("  not scanned:", r["n"], r["category"], r["status"], r.get("error"))
