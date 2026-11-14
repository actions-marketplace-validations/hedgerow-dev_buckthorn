"""Tokens of one line of one file in a malicious sample, strings masked.

Same container rules as run_mal.py. A string shows as S<length>, with e
when it was spelt with escapes; its value is never printed.
Usage: python -I line_mal.py SAMPLES_DIR N PATH LINE
"""

import sys
import zipfile
from pathlib import Path

from buckthorn import js

samples, n, path, line = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
rows = [r.split("\t") for r in (samples / "picked.tsv").read_text().splitlines()]
zf = zipfile.ZipFile(samples / "zips" / rows[n][0])
member = next(i for i in zf.infolist() if i.filename.endswith("/package/" + path))
tokens = js.tokenize(zf.read(member, pwd=b"infected"), None)
out = []
for t in tokens:
    if t.line != line:
        continue
    if t.kind in ("string", "template", "template_head", "template_middle", "template_tail"):
        out.append(f"S{len(t.value)}{'e' if t.escaped else ''}")
    elif t.kind in ("num", "regex"):
        out.append(t.kind)
    else:
        out.append(t.value[:20])
print(" ".join(out)[:1500])
