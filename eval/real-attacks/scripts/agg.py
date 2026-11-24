"""Count scan and diff verdicts per attack, unseen samples apart from tuning ones.

Reads results/{scan,diff}-*.jsonl and results/picked-*.tsv as the run on the
container host wrote them. Usage: python -I agg.py EVAL_DIR
"""

import collections
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
tuned = set((root / "lists" / "npm-tuning-overlap.txt").read_text().split())


def campaign(path: str) -> str:
    day = path.rsplit("/", 1)[-1][:10]
    if "2025-09-14" <= day <= "2025-09-16":
        return "Shai-Hulud, wave 1 (Sep 2025)"
    if day == "2025-11-24":
        return "Shai-Hulud 2.0 (Nov 2025)"
    return "Other npm takeovers"


def load(name: str) -> list[dict]:
    rows = []
    for part in sorted((root / "results").glob(f"{name}*.jsonl")):
        rows += [json.loads(line) for line in part.read_text().splitlines()]
    return rows


scan_table: dict[tuple[str, bool], collections.Counter] = collections.defaultdict(
    collections.Counter
)
diff_table: dict[tuple[str, bool], collections.Counter] = collections.defaultdict(
    collections.Counter
)
for wave in ("w1", "w2", "w3"):
    picked = [
        line.split("\t")
        for line in (root / "results" / f"picked-{wave}.tsv").read_text().splitlines()
    ]
    by_zip = {row[0]: row[3] for row in picked}
    for record in load(f"scan-{wave}"):
        path = picked[record["n"]][3]
        key = (campaign(path), path in tuned)
        scan_table[key][record.get("verdict") or record["status"]] += 1
    for record in load(f"diff-{wave}"):
        path = by_zip[record["sample"]]
        key = (campaign(path), path in tuned)
        diff_table[key][record.get("verdict") or record["status"]] += 1

for title, table in (("scan", scan_table), ("diff against the version before", diff_table)):
    print(f"\n{title}")
    for (name, was_tuned), counts in sorted(table.items()):
        total = sum(counts.values())
        label = f"{name}{' (tuning set)' if was_tuned else ''}"
        print(f"  {label}: {total}  " + ", ".join(f"{k} {v}" for k, v in counts.most_common()))
