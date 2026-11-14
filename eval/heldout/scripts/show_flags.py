"""For hand triage of benign flags: rescan each file and print every finding above
info with its rule message and the flagged lines (2 lines of context). Strings longer
than 16 characters are replaced by their length, so no URL or token is copied out.

Runs inside a --network none container. Usage: python -I show_flags.py ROOT LIST
"""

import io
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

LONG_STR = re.compile(r"""(?P<q>'''|\"\"\"|'|")(?P<body>(?:\\.|(?!(?P=q)).){17,}?)(?P=q)""")


def read_member(path, member):
    data = path.read_bytes()
    if data[:2] == b"PK":
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = {i.filename: i for i in zf.infolist()}
        for n in names:
            if n == member or n.endswith("/" + member):
                return zf.read(names[n])
    else:
        tf = tarfile.open(fileobj=io.BytesIO(data))
        for m in tf.getmembers():
            if m.isfile() and (m.name == member or m.name.endswith("/" + member)):
                return tf.extractfile(m).read()
    return None


root = Path(sys.argv[1])
for rel in (l.strip() for l in open(sys.argv[2]) if l.strip()):
    path = root / rel
    out = subprocess.run(["buckthorn", "scan", "--format", "json", str(path)],
                         capture_output=True, text=True, timeout=900).stdout
    art = json.loads(out)["artifacts"][0]
    print(f"\n##### {rel}: {art['verdict']}")
    for f in art["findings"]:
        if f["severity"] == "info":
            continue
        lines = (f.get("metadata") or {}).get("lines") or []
        print(f"- {f['rule_id']} {f['severity']} {f.get('file')} {lines}: {f['message'][:200]}")
        data = read_member(path, f.get("file") or "") if lines else None
        if not data:
            continue
        text = data.decode("utf-8", "replace").splitlines()
        for ln in lines[:3]:
            for i in range(max(1, ln - 2), min(len(text), ln + 2) + 1):
                shown = LONG_STR.sub(lambda m: f"<str{len(m.group('body'))}>", text[i - 1])
                print(f"    {i:5}{'>' if i == ln else ' '} {shown[:150]}")
