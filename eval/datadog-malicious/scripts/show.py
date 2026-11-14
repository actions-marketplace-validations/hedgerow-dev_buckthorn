"""Print a sample's Python and metadata files as text. Usage: python -I show.py CORPUS MAXCHARS SAMPLE..."""

import io
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, "/driver")
from run_corpus import PWD, plan  # noqa: E402

corpus, limit, only = Path(sys.argv[1]), int(sys.argv[2]), re.compile(sys.argv[3])
for sample in sys.argv[4:]:
    zf = zipfile.ZipFile(corpus / sample)
    inner = [i for i in zf.infolist() if not i.is_dir()]
    if len(inner) == 1 and inner[0].filename.endswith(".zip"):
        zf = zipfile.ZipFile(io.BytesIO(zf.read(inner[0], pwd=PWD)))
    kind, root, archive, files = plan(zf, Path(sample).stem)
    print(f"##### {sample} -> {kind} {archive}")
    for name, info in files:
        rel = name[len(root) + 1 :] if root else name
        if not only.search(name):
            continue
        if not rel.lower().endswith((".py", ".pth", "entry_points.txt", ".cfg")):
            print(f"  [file] {rel} {info.file_size}")
            continue
        text = zf.read(info, pwd=PWD).decode("utf-8", "replace")
        text = re.sub(r"[A-Za-z0-9+/=]{200,}", "<LONG-BLOB>", text)
        print(f"=== {rel} ({info.file_size} bytes)\n{text[:limit]}")
