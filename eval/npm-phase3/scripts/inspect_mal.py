"""Why a malicious sample was missed: its manifest's run fields, its
JavaScript files, which were read, and what each would do if read whole.

Runs in the same locked-down container as run_mal.py, reading the zips in
memory. Prints structure only: no string literal is ever printed, and URLs,
IP addresses and long tokens in script commands are redacted.
Usage: python -I inspect_mal.py SAMPLES_DIR N [N ...]
"""

import json
import re
import sys
import traceback
import zipfile
from pathlib import Path

from buckthorn import js, npm

PWD = b"infected"
JS = (".js", ".cjs", ".mjs")


def redact(text: str) -> str:
    text = re.sub(r"[a-z][a-z0-9+.-]*://\S+", "<URL>", text, flags=re.I)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", text)
    text = re.sub(r"\b[\w.-]+\.(?:com|net|org|io|xyz|me|ru|cn|site|online|app|dev)\b", "<HOST>", text)
    return re.sub(r"[A-Za-z0-9_+/=-]{24,}", "<TOKEN>", text)[:300]


def skeleton(tokens: list) -> str:
    """Top-level tokens, strings as S, cut short."""
    out = []
    for t in tokens:
        if t.depth:
            continue
        if t.kind in ("string", "template", "template_head", "template_tail", "regex"):
            out.append("S")
        elif t.kind == "num":
            out.append("N")
        else:
            out.append(t.value[:30])
        if len(out) > 120:
            break
    return redact(" ".join(out))


def main() -> None:
    samples = Path(sys.argv[1])
    rows = [line.split("\t") for line in (samples / "picked.tsv").read_text().splitlines()]
    for n in map(int, sys.argv[2:]):
        zname = rows[n][0]
        zf = zipfile.ZipFile(samples / "zips" / zname)
        infos = [i for i in zf.infolist() if not i.is_dir()]
        manifests = sorted(
            (i.filename for i in infos if i.filename.endswith("/package/package.json")),
            key=lambda x: x.count("/"),
        )
        root = manifests[0][: -len("package.json")]
        files = {i.filename[len(root) :]: zf.read(i, pwd=PWD) for i in infos if i.filename.startswith(root)}
        tops = {p: "package" for p in files}
        print(f"\n=== n={n} files={len(files)}")
        try:
            manifest = json.loads(files["package.json"])
            for key in ("main", "exports", "bin", "type", "browser", "module"):
                if key in manifest:
                    print(f"  {key}: {redact(json.dumps(manifest[key]))}")
            scripts = manifest.get("scripts") or {}
            for key, command in scripts.items():
                print(f"  script {redact(str(key))}: {redact(str(command))}")
            package = npm._Package(files, tops, manifest)
            package.install()
            package.load()
            print(f"  entries: {package.entries()}  read: {sorted(package.read)}")
            for path, data in sorted(files.items()):
                if not path.endswith(JS) or path.startswith("node_modules/"):
                    continue
                try:
                    tokens = js.tokenize(data, None if path.endswith(".js") else path.endswith(".mjs"))
                    whole = js.analyse(tokens, True)
                    kinds = sorted({(h.kind, h.line) for h in whole.hits})[:12]
                    print(f"  {path} {len(data)}B read={path in package.read} whole={kinds}")
                    print(f"    top: {skeleton(tokens)}")
                except js.JSError as exc:
                    print(f"  {path} {len(data)}B tokenize error {exc.kind}")
        except Exception:
            print("  error:", traceback.format_exc()[-1500:])


if __name__ == "__main__":
    main()
