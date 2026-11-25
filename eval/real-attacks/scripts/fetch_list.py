"""Fetch the DataDog sample zips named in LIST (blob id TAB path) into OUT, checked by git blob id.

The zips are encrypted and are written as they are: nothing is unpacked, read
inside or run. Usage: python -I fetch_list.py LIST COMMIT OUT
"""

import hashlib
import sys
import urllib.parse
import urllib.request
from pathlib import Path

listing, commit, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
rows = [line.split("\t", 1) for line in Path(listing).read_text().splitlines() if line]
base = f"https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/{commit}/"
(out / "zips").mkdir(parents=True, exist_ok=True)
with open(out / "picked.tsv", "w") as index:
    for n, (blob, path) in enumerate(rows):
        url = base + urllib.parse.quote(path)
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
            data = resp.read(200 * 1024 * 1024)
        got = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324
        ok = got == blob
        name = f"{n:03d}.zip"
        if ok:
            (out / "zips" / name).write_bytes(data)
        index.write(f"{name}\t{'ok' if ok else 'BAD'}\t{len(data)}\t{path}\n")
        print(n, "ok" if ok else "BAD", len(data), flush=True)
