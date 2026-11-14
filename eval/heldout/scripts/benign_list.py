"""Benign scan list: the downloaded files minus any whose sha256 is a tuning file's
(checked again here against every file in the tuning benign volume).
Usage: python3 -I benign_list.py TUNING_BENIGN_HASHES MANIFEST SKIPPED PROJECTS OUT_LIST"""

import collections
import json
import sys

tuning, manifest, skipped, projects, out = sys.argv[1:6]
sha = {json.loads(l).get("sha256") for l in open(tuning)}
rows = [json.loads(l) for l in open(manifest)]
kept = [r for r in rows if r["sha256"] not in sha]
print("files downloaded", len(rows), "tuning sha256 hits", len(rows) - len(kept))
print("files by stratum and type", dict(collections.Counter((r["stratum"], r["packagetype"]) for r in kept)))
print("projects", dict(collections.Counter(json.loads(l)["stratum"] for l in open(projects))))
print("skipped", dict(collections.Counter((json.loads(l)["stratum"], json.loads(l)["reason"]) for l in open(skipped))))
with open(out, "w") as fh:
    fh.writelines(f"{r['stratum']}/{r['filename']}\n" for r in kept)
