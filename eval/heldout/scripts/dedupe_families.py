"""Apply the protocol's exclusions to the malicious candidates and label families.

Reads hashes and names only (file_hashes.py output, tuning result files, OSV table);
no sample content. Writes one JSON line per candidate archive and the scan list.
Usage: python3 -I dedupe_families.py HASH_DIR TUNING_DIRS_ROOT OSV_JSONL OUT_DIR
  HASH_DIR          heldout-malreg.jsonl, tuning-{malreg,datadog,benign}.jsonl
  TUNING_DIRS_ROOT  this repo's eval/ folder (tuning result files with sha256)
"""

import collections
import gzip
import json
import re
import sys
from pathlib import Path


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def normver(v):
    v = v.lower()
    return v[1:] if v.startswith("v") and v[1:2].isdigit() else v


def strip_tail(name):
    return re.sub(r"[-\d]+$", "", name)


def lev1(a, b):
    """True when a and b are at Levenshtein distance exactly 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1 :] if len(a) < len(b) else a[i + 1 :] == b[i + 1 :]


def load(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def benign_pair(filename):
    if filename.endswith(".whl"):
        parts = filename.split("-")
        return norm(parts[0]), normver(parts[1])
    base = re.sub(r"\.(tar\.gz|tgz|zip|tar\.bz2)$", "", filename)
    name, _, ver = base.rpartition("-")
    return norm(name), normver(ver)


def main():
    hdir, ev, osv_path, out = (Path(a) for a in sys.argv[1:5])
    held = load(hdir / "heldout-malreg.jsonl")
    t_mr = load(hdir / "tuning-malreg.jsonl")
    t_dd = load(hdir / "tuning-datadog.jsonl")
    t_bn = load(hdir / "tuning-benign.jsonl")

    # Tuning artifact hashes: archives as stored, DataDog rebuilt archives, benign files.
    tuning_sha = {r["sha256"] for r in t_mr + t_bn if r.get("sha256")}
    for f in (ev / "datadog-malicious/results-final.jsonl", ev / "guarddog/buckthorn/datadog.jsonl.gz",
              ev / "pypi-malregistry/results-final.jsonl", ev / "guarddog/buckthorn/malreg.jsonl.gz",
              ev / "guarddog/buckthorn/benign.jsonl.gz"):
        for r in load(f):
            sha = (r.get("result") or {}).get("sha256")
            if sha:
                tuning_sha.add(sha)

    # Tuning (name, version) pairs and malicious names.
    pairs, mal_names = set(), set()
    for r in t_mr:
        name, ver = r["sample"].split("/")[:2]
        pairs.add((norm(name), normver(ver)))
        mal_names.add(norm(name))
    for r in t_dd:
        _, name, ver = r["sample"].split("/")[:3]
        pairs.add((norm(name), normver(ver)))
        mal_names.add(norm(name))
    for r in t_bn:
        pairs.add(benign_pair(r["sample"].rsplit("/", 1)[-1]))

    benign_py = {h for r in t_bn for h in r.get("pyhashes", [])}
    mal_py = collections.defaultdict(set)  # file hash -> tuning malicious names
    tagged = [(r, r["sample"].split("/")[0]) for r in t_mr]
    tagged += [(r, r["sample"].split("/")[1]) for r in t_dd]
    for r, name in tagged:
        name = norm(name)
        for h in r.get("pyhashes", []):
            if h not in benign_py:
                mal_py[h].add(name)

    stripped = collections.defaultdict(set)
    by_len = collections.defaultdict(set)
    for n in mal_names:
        s = strip_tail(n)
        if len(s) >= 4:
            stripped[s].add(n)
        by_len[len(n)].add(n)

    osv = collections.defaultdict(list)
    for r in load(osv_path):
        osv[r["name"]].append(r)

    rows, seen_sha = [], {}
    for r in sorted(held, key=lambda r: r["sample"]):
        name, ver = r["sample"].split("/")[:2]
        row = {"sample": r["sample"], "name": norm(name), "version": normver(ver),
               "sha256": r.get("sha256"), "magic": r.get("magic")}
        reports = osv.get(norm(name), [])
        if reports:
            row["osv_first_published"] = min(x["published"] for x in reports)
            row["osv_ids"] = sorted({x["id"] for x in reports})
        if r.get("sha256") in tuning_sha:
            row["excluded"] = "sha256 in a tuning corpus"
        elif (row["name"], row["version"]) in pairs:
            row["excluded"] = "name and version in a tuning corpus"
        elif r.get("sha256") in seen_sha:
            row["excluded"] = f"duplicate of {seen_sha[r['sha256']]}"
        else:
            seen_sha[r.get("sha256")] = r["sample"]
        n = row["name"]
        why = []
        if n in mal_names:
            why.append(f"F1:{n}")
        s = strip_tail(n)
        if len(s) >= 4 and stripped.get(s):
            why.append("F2:" + ",".join(sorted(stripped[s])[:3]))
        if len(n) >= 6:
            near = sorted(m for L in (len(n) - 1, len(n), len(n) + 1) for m in by_len[L]
                          if len(m) >= 6 and lev1(n, m))
            if near:
                why.append("F3:" + ",".join(near[:3]))
        shared = sorted({m for h in r.get("pyhashes", []) for m in mal_py.get(h, ())})
        if shared:
            why.append("F4:" + ",".join(shared[:3]))
        row["family"] = "seen" if why else "new"
        row["family_why"] = why
        row["_py"] = [h for h in r.get("pyhashes", []) if h not in benign_py]
        if r.get("error"):
            row["hash_error"] = r["error"]
        rows.append(row)

    # Group held-out samples among themselves by F1 to F4 (union-find).
    parent = list(range(len(rows)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        parent[find(i)] = find(j)

    first = {}
    for i, row in enumerate(rows):
        keys = [("n", row["name"])] + [("h", h) for h in row["_py"]]
        s = strip_tail(row["name"])
        if len(s) >= 4:
            keys.append(("s", s))
        for k in keys:
            if k in first:
                union(i, first[k])
            else:
                first[k] = i
    names = sorted({(row["name"], i) for i, row in enumerate(rows)})
    for a in range(len(names)):
        for b in range(a + 1, len(names)):
            na, nb = names[a][0], names[b][0]
            if len(na) >= 6 and len(nb) >= 6 and lev1(na, nb):
                union(names[a][1], names[b][1])
    for i, row in enumerate(rows):
        row["group"] = rows[find(i)]["name"]
        del row["_py"]

    out.mkdir(parents=True, exist_ok=True)
    with open(out / "malicious-candidates.jsonl", "w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    kept = [row for row in rows if "excluded" not in row]
    (out / "malicious-scan-list.txt").write_text("".join(f"mr/{row['sample']}\n" for row in kept))
    c = collections.Counter(row.get("excluded", "kept") for row in rows)
    fam = collections.Counter(row["family"] for row in kept)
    group_seen = collections.defaultdict(bool)
    for row in kept:
        group_seen[row["group"]] |= row["family"] == "seen"
    groups = [("seen" if v else "new", g) for g, v in group_seen.items()]
    print(json.dumps({"candidates": len(rows), "outcome": c, "kept_by_family": fam,
                      "kept_packages": len({row["name"] for row in kept}),
                      "groups": collections.Counter(f for f, _ in groups)}, indent=1))


if __name__ == "__main__":
    main()
