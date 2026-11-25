"""Re-scan each sampled file and print each non-info finding with the code
around it. Runs in a --network none container. Usage: python -I excerpt.py SAMPLE QUARANTINE"""

import json
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from buckthorn.scan import scan_artifact


def members(path):
    if path.name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(path) as z:
            return {n: z.read(n) for n in z.namelist() if z.getinfo(n).file_size < 5_000_000}
    with tarfile.open(path) as t:
        return {
            m.name: t.extractfile(m).read()
            for m in t.getmembers()
            if m.isfile() and m.size < 5_000_000
        }


def clip(s, n=220):
    s = s.replace("\t", " ")
    return s if len(s) <= n else s[:n] + f" ...[{len(s)} chars]"


for n, line in enumerate(open(sys.argv[1]), 1):
    item = json.loads(line)
    # Quarantine adds "<time>-" to the name; scan a copy under the registry's name.
    tmp = Path(tempfile.mkdtemp())
    path = tmp / item["q"].split("/", 1)[1].split("-", 1)[1]
    shutil.copyfile(Path(sys.argv[2]) / item["q"], path)
    print(f"\n===== #{n} [{item['kind']}] {item['eco']} {item['name']} {item['version']}")
    files = members(path)
    for name, data in files.items():
        if name.count("/") == 1 and name.endswith("/package.json"):
            try:
                m = json.loads(data)
                print(
                    "manifest:",
                    clip(
                        json.dumps(
                            {
                                k: m.get(k)
                                for k in ("description", "repository", "main", "bin")
                                if m.get(k)
                            }
                        ),
                        400,
                    ),
                )
                hooks = {
                    k: v
                    for k, v in (m.get("scripts") or {}).items()
                    if k in ("preinstall", "install", "postinstall")
                }
                if hooks:
                    print("install hooks:", clip(json.dumps(hooks), 400))
            except ValueError:
                print("manifest: does not parse")
    shown = 0
    for f in scan_artifact(path):
        if f.severity.value == "info" or shown >= 5:
            continue
        shown += 1
        ln = f.metadata.get("line") or (f.metadata.get("lines") or [None])[0]
        print(f"-- {f.rule_id} {f.severity.value} {f.file_path}:{ln} {clip(f.message, 300)}")
        # The finding's path, or (for a wheel or sdist named another way) the
        # member whose path ends with it; never a nested file of the same name.
        data = files.get(f.file_path) or next(
            (v for k, v in files.items() if f.file_path.endswith("/" + k)), None
        )
        if data is None:
            continue
        text = data.decode("utf-8", "replace").splitlines()
        lo = max(0, (ln or 1) - 5)
        for i in range(lo, min(len(text), lo + (10 if ln else 12))):
            print(f"   {i + 1}: {clip(text[i])}")
