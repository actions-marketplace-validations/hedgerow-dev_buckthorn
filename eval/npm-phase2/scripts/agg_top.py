"""Summarise run_top.py output. Usage: python3 -I agg_top.py OUT.jsonl"""

import json
import sys
from collections import Counter, defaultdict

rows = [json.loads(line) for line in open(sys.argv[1])]
fetched = [r for r in rows if r.get("status") == "ok"]
print(f"packages: {len(rows)}, fetched and integrity ok: {len(fetched)}")
for r in rows:
    if r.get("status") != "ok":
        print("  not read:", r["rank"], r["name"], r.get("status"))

files = [(r["name"], f) for r in fetched for f in r["files"]]
with_js = sum(1 for r in fetched if r["files"])
print(f"packages with JS: {with_js}, JS files: {len(files)}")
print("by extension:", Counter(f["path"].rsplit(".", 1)[-1].lower() for _, f in files))

outcomes = Counter(f["shipped"]["outcome"] for _, f in files)
print("outcomes (shipped limits):", dict(outcomes))
examples = defaultdict(list)
for name, f in files:
    kind = f["shipped"]["outcome"]
    if kind != "ok":
        examples[kind].append((name, f))
for kind, found in sorted(examples.items()):
    print(f"\n{kind}: {len(found)} files in {len({n for n, _ in found})} packages")
    for name, f in found[:15]:
        extra = {k: f[k] for k in ("raised", "as_script", "as_module") if k in f}
        line = f["shipped"].get("line")
        print(f"  {name}: {f['path']} ({f['bytes']} bytes, line {line}) {extra or ''}")

ok = [f for _, f in files if f["shipped"]["outcome"] == "ok"]
if not ok:
    raise SystemExit("no file tokenized: nothing more to summarise")
times = sorted(f["shipped"]["s"] for _, f in files)
sizes = sorted(f["bytes"] for _, f in files)


def pct(values, p):
    return values[min(len(values) - 1, int(len(values) * p))] if values else None


print("\nper-file seconds: p50", pct(times, 0.5), "p99", pct(times, 0.99), "max", times[-1])
print("per-file bytes: p50", pct(sizes, 0.5), "p99", pct(sizes, 0.99), "max", sizes[-1])
total_bytes = sum(f["bytes"] for f in ok)
total_s = sum(f["shipped"]["s"] for f in ok)
print(f"ok files: {total_bytes} bytes in {total_s:.1f} s, {total_bytes / total_s / 1e6:.2f} MB/s")
print("max tokens (ok):", max(f["shipped"]["tokens"] for f in ok))
print("max depth (ok):", max(f["shipped"]["depth"] for f in ok))
print("depth over 100 (ok):", sum(f["shipped"]["depth"] > 100 for f in ok))
slow = sorted(files, key=lambda nf: -nf[1]["shipped"]["s"])[:5]
for name, f in slow:
    print(f"  slow: {name}: {f['path']} {f['bytes']} bytes {f['shipped']['s']} s")

raised = [(n, f) for n, f in files if "raised" in f]
for name, f in raised:
    print(f"  over a limit: {name}: {f['path']} {f['bytes']} bytes, raised: {f['raised']}")

scan_s = sorted(r["scan_s"] for r in fetched)
print("\nscan_artifact seconds per package: p50", pct(scan_s, 0.5), "max", scan_s[-1])
print("sum scan seconds:", round(sum(scan_s), 1))
verdicts = Counter()
for r in fetched:
    rules = set(r["rules"])
    if not rules:
        verdicts["clean"] += 1
    elif rules <= {"BKT-SKIP-003", "BKT-SKIP-001", "BKT-SKIP-002"}:
        verdicts["coverage only"] += 1
    else:
        verdicts["other rules"] += 1
print("by findings:", dict(verdicts))
print("packages with per-file untokenized notes:", sum(r["untokenized_notes"] > 0 for r in fetched))
notes = sum(r["untokenized_notes"] for r in fetched)
failed = sum(1 for _, f in files if f["shipped"]["outcome"] != "ok")
print(f"untokenized notes from scan: {notes}, failures from direct tokenizing: {failed}")
clean_with_js = [r["name"] for r in fetched if r["files"] and not r["rules"]]
print("clean despite JS (must be none):", clean_with_js)
print("read_archive rules:", Counter(x for r in fetched for x in r["read_rules"]))
