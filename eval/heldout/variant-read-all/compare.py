"""Read-all variant against the default on the held-out sets (see ../VARIANT-read-all.md).

Reads result files only (per-sample rule ids, files and lines), never samples.
Usage:
  python3 -I compare.py malicious VARIANT.jsonl.gz DEFAULT.jsonl.gz GD.jsonl.gz \
      malicious-candidates.jsonl triage-malicious-misses.csv
  python3 -I compare.py benign VARIANT.jsonl.gz DEFAULT.jsonl.gz GD.jsonl.gz benign-manifest.jsonl.gz
"""

import collections
import csv
import gzip
import json
import math
import random
import sys

COVERAGE = {"BKT-SKIP-001", "BKT-SKIP-002", "BKT-SKIP-003", "BKT-SKIP-004", "BKT-SKIP-005"}
# Folders whose code is tests, docs or examples (the pre-registered location split).
SIDE_FOLDERS = {"test", "tests", "testing", "doc", "docs", "example", "examples"}


def load(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def wilson(k, n, z=1.96):
    if n == 0:
        return "n/a"
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{k}/{n} = {100 * p:.1f}% ({100 * (c - h):.1f} to {100 * (c + h):.1f})"


def verdict(rec):
    return rec["verdict"] if rec and rec.get("status") == "scanned" else "error"


def threat(rec):
    return bool(rec and rec.get("status") == "scanned"
                and any(r.startswith("threat-") for r in rec.get("rules", {})))


def flagging(rec):
    return [f for f in rec.get("findings", [])
            if f["severity"] != "info" and f["rule_id"] not in COVERAGE]


def side_only(rec):
    """Every finding that flags this file sits under a tests, docs or examples folder."""
    found = flagging(rec)
    return bool(found) and all(
        any(part.lower() in SIDE_FOLDERS for part in (f.get("file") or "").split("/")[:-1])
        for f in found
    )


def table(title, S, V, D, G):
    n = len(S)
    vv = collections.Counter(verdict(V.get(s)) for s in S)
    dv = collections.Counter(verdict(D.get(s)) for s in S)
    added = [s for s in S if verdict(V.get(s)) == "flagged" and verdict(D.get(s)) != "flagged"]
    lost = [s for s in S if verdict(D.get(s)) == "flagged" and verdict(V.get(s)) != "flagged"]
    gt = sum(threat(G.get(s)) for s in S)
    print(f"\n### {title} (n={n}; missing variant {sum(s not in V for s in S)})")
    print(f"- Variant flagged: {wilson(vv['flagged'], n)}")
    print(f"- Variant not_verified: {wilson(vv['not_verified'], n)}; clean {vv['clean']}; error or timeout {vv['error']}")
    print(f"- Default flagged: {wilson(dv['flagged'], n)}; not_verified {dv['not_verified']}")
    print(f"- Added by the variant: {len(added)}; lost: {len(lost)}")
    print(f"- GuardDog threat: {wilson(gt, n)}")
    both = collections.Counter((verdict(V.get(s)) == "flagged", threat(G.get(s))) for s in S)
    print(f"- Variant flagged and GuardDog threat {both[(True, True)]}; variant only {both[(True, False)]};"
          f" GuardDog only {both[(False, True)]}; neither {both[(False, False)]}")
    print(f"- Either (variant flagged or GuardDog threat): {wilson(n - both[(False, False)], n)}")
    return added


def rules(title, samples, V):
    c = collections.Counter(r for s in samples for r in {f["rule_id"] for f in flagging(V[s])})
    print(f"- {title}: " + ", ".join(f"{r} {k}" for r, k in c.most_common(12)))


def main():
    kind, vpath, dpath, gpath, mpath = sys.argv[1:6]
    V = {r["sample"]: r for r in load(vpath)}
    D = {r["sample"]: r for r in load(dpath)}
    G = {r["sample"]: r for r in load(gpath)}
    meta = load(mpath)
    if kind == "malicious":
        S = ["mr/" + m["sample"] for m in meta if "excluded" not in m]
        added = table("Held-out malicious archives", S, V, D, G)
        rules("Rules on added flags", added, V)
        late = ["mr/" + m["sample"] for m in meta
                if "excluded" not in m and m.get("osv_first_published", "") >= "2026-11-03"]
        table("OSV first report on or after 2026-11-03", late, V, D, G)
        with open(sys.argv[6]) as fh:
            tri = list(csv.DictReader(fh))
        print("\n### The 50 triaged misses")
        by = collections.Counter()
        for row in tri:
            s = "mr/" + row["sample"].removeprefix("mr/")
            by[(row["reason"], verdict(V.get(s)) == "flagged")] += 1
        for reason in sorted({r for r, _ in by}):
            print(f"- {reason}: now flagged {by[(reason, True)]} of {by[(reason, True)] + by[(reason, False)]}")
        print(f"- All: now flagged {sum(v for (r, f), v in by.items() if f)} of {len(tri)}")
    else:
        allS, alladded = [], []
        for stratum in ("b1", "b2"):
            rows = [m for m in meta if m["stratum"] == stratum]
            S = [f"{stratum}/{m['filename']}" for m in rows]
            allS += S
            added = table(f"{stratum} files", S, V, D, G)
            alladded += added
            projects = collections.defaultdict(list)
            for m in rows:
                projects[m["project"]].append(f"{stratum}/{m['filename']}")
            n = len(projects)
            fv = sum(any(verdict(V.get(s)) == "flagged" for s in v) for v in projects.values())
            fd = sum(any(verdict(D.get(s)) == "flagged" for s in v) for v in projects.values())
            print(f"- Projects with a variant flag: {wilson(fv, n)}; default {wilson(fd, n)}")
            for pt in ("sdist", "bdist_wheel"):
                sub = [f"{stratum}/{m['filename']}" for m in rows if m["packagetype"] == pt]
                fl = sum(verdict(V.get(s)) == "flagged" for s in sub)
                print(f"- {pt}: variant flagged {wilson(fl, len(sub))}")
        table("B1 and B2 files", allS, V, D, G)
        side = [s for s in alladded if side_only(V[s])]
        print(f"\n- Added flags only from tests, docs or examples folders: {len(side)} of {len(alladded)}")
        rules("Rules on added flags", alladded, V)
        pick = sorted(random.Random(20261116).sample(sorted(alladded), min(30, len(alladded))))
        print("\n### Triage sample (seed 20261116)")
        for s in pick:
            found = sorted({(f["rule_id"], f.get("file")) for f in flagging(V[s])})
            print(s, json.dumps(found[:8]))


if __name__ == "__main__":
    main()
