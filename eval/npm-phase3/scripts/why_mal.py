"""Sort the malicious samples a scan did not flag by why, for the note.

Same locked-down container as run_mal.py; zips read in memory. For each
sample not flagged in RESULTS.jsonl, every JavaScript file is also read
whole (as an install file is) to see where code these rules would flag
sits. Prints counts and per-sample categories only: no file content.
Usage: python -I why_mal.py SAMPLES_DIR RESULTS.jsonl
"""

import collections
import json
import sys
import zipfile
from pathlib import Path

from buckthorn import js, npm

PWD = b"infected"
FLAGGING = {"network", "process", "exec", "secrets", "persistence", "hidden", "discord", "telegram"}


def main() -> None:
    samples, results = Path(sys.argv[1]), Path(sys.argv[2])
    rows = [line.split("\t") for line in (samples / "picked.tsv").read_text().splitlines()]
    counts: collections.Counter = collections.Counter()
    for record in map(json.loads, results.open()):
        if record.get("verdict") in ("flagged", None):
            continue
        n = record["n"]
        zf = zipfile.ZipFile(samples / "zips" / rows[n][0])
        infos = [i for i in zf.infolist() if not i.is_dir()]
        roots = sorted(
            (i.filename for i in infos if i.filename.endswith("/package/package.json")),
            key=lambda x: x.count("/"),
        )
        root = roots[0][: -len("package.json")]
        files = {i.filename[len(root) :]: zf.read(i, pwd=PWD) for i in infos if i.filename.startswith(root)}
        try:
            manifest = json.loads(files["package.json"])
        except ValueError:
            manifest = {}
        package = npm._Package(files, {p: "package" for p in files}, manifest)
        package.install()
        package.load()
        code = [p for p in files if p.endswith((".js", ".cjs", ".mjs")) and not p.startswith("node_modules/")]
        in_read, in_unread = False, False
        for path in code:
            try:
                kinds = {h.kind for h in js.analyse(js.tokenize(files[path], None), True).hits}
            except js.JSError:
                continue
            if kinds & FLAGGING:
                if path in package.read:
                    in_read = True
                else:
                    in_unread = True
        bins = manifest.get("bin") or (manifest.get("directories") or {}).get("bin")
        if not code:
            why = "no JavaScript (binaries or package.json only)"
        elif in_read:
            why = "flaggable code only in functions that run when called"
        elif in_unread and bins:
            why = "flaggable code only in bin commands or files they load"
        elif in_unread:
            why = "flaggable code only in files nothing loads"
        elif not package.read:
            why = "nothing runs on its own, no flaggable code"
        else:
            why = "code runs, nothing these rules flag"
        counts[(record["category"], record["verdict"], why)] += 1
        print(n, record["category"], record["verdict"], why)
    print()
    for (category, verdict, why), count in sorted(counts.items()):
        print(f"{category:17} {verdict:13} {count:3}  {why}")


if __name__ == "__main__":
    main()
