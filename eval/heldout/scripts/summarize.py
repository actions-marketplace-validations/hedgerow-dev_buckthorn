"""Rates with Wilson 95% intervals for the held-out runs (see ../PROTOCOL.md).

Usage:
  python3 -I summarize.py malicious BKT.jsonl.gz GD.jsonl.gz lists/malicious-candidates.jsonl
  python3 -I summarize.py benign BKT.jsonl.gz GD.jsonl.gz lists/benign-manifest.jsonl
"""

import collections
import gzip
import json
import math
import random
import sys

INTEG = {"BKT-META-001", "BKT-REC-001", "BKT-REC-002"}


def load(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def wilson(k, n, z=1.96):
    if n == 0:
        return "n/a"
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{k}/{n} = {100 * p:.1f}% ({100 * (c - h):.1f} to {100 * (c + h):.1f})"


def bkt(rec):
    if not rec or rec.get("status") != "scanned":
        return "error"
    return rec["verdict"]


def gd(rec):
    if not rec or rec.get("status") != "scanned":
        return "error"
    rules = rec.get("rules", {})
    if any(r.startswith("threat-") for r in rules):
        return "threat"
    return "capability" if rules else "nothing"


def integrity_only(rec):
    sev = [f for f in rec.get("findings", []) if f["severity"] != "info"]
    return bool(sev) and all(f["rule_id"] in INTEG for f in sev)


def table(title, samples, B, G):
    n = len(samples)
    vb = collections.Counter(bkt(B.get(s)) for s in samples)
    vg = collections.Counter(gd(G.get(s)) for s in samples)
    either = sum(bkt(B.get(s)) == "flagged" or gd(G.get(s)) == "threat" for s in samples)
    integ = sum(bkt(B.get(s)) == "flagged" and integrity_only(B[s]) for s in samples)
    print(f"\n### {title} (n={n})")
    print(f"- Buckthorn flagged: {wilson(vb['flagged'], n)}; of which integrity rules only: {integ}")
    print(f"- Buckthorn not_verified: {wilson(vb['not_verified'], n)}")
    print(f"- Buckthorn clean: {wilson(vb['clean'], n)}; error or timeout: {vb['error']}")
    print(f"- GuardDog threat: {wilson(vg['threat'], n)}")
    print(f"- GuardDog any rule: {wilson(vg['threat'] + vg['capability'], n)}; error: {vg['error']}")
    print(f"- Either (Buckthorn flagged or GuardDog threat): {wilson(either, n)}")


def rules_hit(samples, B, G):
    rb = collections.Counter(r for s in samples for r in {f["rule_id"] for f in B.get(s, {}).get("findings", [])})
    rg = collections.Counter(r for s in samples for r in G.get(s, {}).get("rules", {}))
    print("\nBuckthorn rules by samples:", ", ".join(f"{r} {c}" for r, c in rb.most_common(15)))
    print("GuardDog rules by samples:", ", ".join(f"{r} {c}" for r, c in rg.most_common(15)))


def main():
    kind, bpath, gpath, mpath = sys.argv[1:5]
    B = {r["sample"]: r for r in load(bpath)}
    G = {r["sample"]: r for r in load(gpath)}
    meta = load(mpath)
    if kind == "malicious":
        kept = [m for m in meta if "excluded" not in m]
        key = {m["sample"]: "mr/" + m["sample"] for m in kept}
        S = [key[m["sample"]] for m in kept]
        print(f"missing Buckthorn: {sum(s not in B for s in S)}, missing GuardDog: {sum(s not in G for s in S)}")
        table("All held-out malicious archives", S, B, G)
        for fam in ("new", "seen"):
            table(f"{fam} family", [key[m["sample"]] for m in kept if m["family"] == fam], B, G)
        late = [key[m["sample"]] for m in kept if m.get("osv_first_published", "") >= "2026-11-03"]
        early = [key[m["sample"]] for m in kept if m.get("osv_first_published", "9") < "2026-11-03"]
        none = [key[m["sample"]] for m in kept if not m.get("osv_first_published")]
        table("OSV first report on or after 2026-11-03", late, B, G)
        table("OSV first report before 2026-11-03", early, B, G)
        if none:
            table("No OSV report", none, B, G)
        by_pkg = collections.defaultdict(list)
        for m in kept:
            by_pkg[m["name"]].append(key[m["sample"]])
        rng = random.Random(20261115)
        one = [rng.choice(sorted(by_pkg[p])) for p in sorted(by_pkg)]
        table("One archive per package", one, B, G)
        rules_hit(S, B, G)
    else:
        for stratum in ("b1", "b2"):
            rows = [m for m in meta if m["stratum"] == stratum]
            S = [f"{stratum}/{m['filename']}" for m in rows]
            print(f"\n## {stratum}: missing Buckthorn {sum(s not in B for s in S)}, missing GuardDog {sum(s not in G for s in S)}")
            table(f"{stratum} files", S, B, G)
            for pt in ("sdist", "bdist_wheel"):
                table(f"{stratum} {pt}", [f"{stratum}/{m['filename']}" for m in rows if m["packagetype"] == pt], B, G)
            projects = collections.defaultdict(list)
            for m in rows:
                projects[m["project"]].append(f"{stratum}/{m['filename']}")
            n = len(projects)
            fb = sum(any(bkt(B.get(s)) == "flagged" for s in v) for v in projects.values())
            nv = sum(any(bkt(B.get(s)) == "not_verified" for s in v) for v in projects.values())
            gt = sum(any(gd(G.get(s)) == "threat" for s in v) for v in projects.values())
            ga = sum(any(gd(G.get(s)) in ("threat", "capability") for s in v) for v in projects.values())
            print(f"\n### {stratum} projects (n={n})")
            print(f"- Buckthorn any file flagged: {wilson(fb, n)}; any not_verified: {wilson(nv, n)}")
            print(f"- GuardDog any file threat: {wilson(gt, n)}; any rule: {wilson(ga, n)}")
            rules_hit(S, B, G)


if __name__ == "__main__":
    main()
