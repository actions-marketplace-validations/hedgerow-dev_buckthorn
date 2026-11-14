"""Flag counts from a call-time run of the corpus drivers (scan_files.py, run_corpus.py).

"Today" is the same scan with the BKT-CALL findings left out: those rules are the
only change call-time mode makes. Reads JSON results only; no sample is opened.
Usage: python final_counts.py BENIGN.jsonl MALREG.jsonl DATADOG_DIR
"""

import json
import sys
from pathlib import Path

COVERAGE = {f"BKT-SKIP-00{i}" for i in range(1, 7)} | {"BKT-LOCK-002", "BKT-MCP-001"}
RULES = [f"BKT-CALL-00{i}" for i in range(1, 6)]


def flagged(findings):
    return any(f["severity"] != "info" and f["rule_id"] not in COVERAGE for f in findings)


def counts(name, records):
    scanned = [r for r in records if r.get("status") == "scanned"]
    today = combo = 0
    total, alone = dict.fromkeys(RULES, 0), dict.fromkeys(RULES, 0)
    for r in scanned:
        findings = r["result"]["findings"]
        base = [f for f in findings if not f["rule_id"].startswith("BKT-CALL-")]
        call = {f["rule_id"] for f in findings if f["rule_id"].startswith("BKT-CALL-")}
        today += flagged(base)
        combo += flagged(findings)
        for rule in call:
            total[rule] += 1
        if len(call) == 1 and not flagged(base):
            alone[call.pop()] += 1
    others = len(records) - len(scanned)
    print(f"{name}: {len(records)} records, {len(scanned)} scanned, {others} not scanned")
    print(f"  flagged today {today}, with call-time rules {combo} (+{combo - today})")
    for rule in RULES:
        print(f"  {rule}: fires on {total[rule]}, alone flags {alone[rule]}")


def main():
    benign, malreg, datadog = sys.argv[1:4]
    counts("benign", [json.loads(line) for line in open(benign)])
    counts("pypi_malregistry", [json.loads(line) for line in open(malreg)])
    dd = [json.loads(p.read_text()) for p in sorted(Path(datadog).glob("*.json"))]
    counts("datadog", [r for r in dd if r.get("status") != "empty"])
    print(f"  datadog empty samples left out: {sum(r.get('status') == 'empty' for r in dd)}")


if __name__ == "__main__":
    main()
