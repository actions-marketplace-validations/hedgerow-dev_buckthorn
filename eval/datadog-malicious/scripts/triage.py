"""Describe each missed sample's Python code by where risky calls sit. Text only, nothing runs.

Usage: python -I triage.py CORPUS_DIR RESULTS_DIR OUT_JSONL
"""

import ast
import glob
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, "/driver")
from run_corpus import PWD, plan  # noqa: E402

INTEG = {"BKT-META-001", "BKT-REC-001", "BKT-REC-002"}
RISKY = re.compile(
    r"^(requests\.|urllib|http\.client|socket\.|subprocess\.|os\.system|os\.popen|os\.startfile"
    r"|exec$|eval$|compile$|__import__$|base64\.|zlib\.|marshal\.|webbrowser\.|ctypes\.|shutil\.copy"
    r"|open$|os\.remove|os\.rename|winreg|aiohttp|httpx|ftplib|smtplib|platform\.|getpass|threading\.)"
)
TEXT = re.compile(
    r"https?://[^\s'\"<>)]+|discord(?:app)?\.com/api/webhooks|pastebin|transfer\.sh|\.exe\b|powershell"
    r"|Local State|Login Data|wallet|token|keylog|pynput|mshta|curl |wget ",
    re.I,
)


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = dotted(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def calls(tree):
    """(call name, enclosing function or None) for risky calls, names resolved through
    imports. A function counts as TOP when module-level code reaches it: called directly,
    passed as a thread target, or through another such function (same module only)."""
    alias = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                alias[(a.asname or a.name).split(".")[0]] = (
                    a.name if a.asname else a.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                alias[a.asname or a.name] = f"{node.module}.{a.name}"

    def name_of(node):
        d = dotted(node)
        head, _, rest = d.partition(".")
        return (alias.get(head, head) + ("." + rest if rest else "")) if d else ""

    risky = {}  # function name (or None) -> risky call names
    edges = {}  # function name (or None) -> local names it calls or hands to Thread
    defined = set()

    def walk(node, fn):
        for child in ast.iter_child_nodes(node):
            f = fn
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                f = child.name
                defined.add(child.name)
            elif isinstance(child, ast.Lambda):
                f = fn
            elif isinstance(child, ast.ClassDef) and fn is None:
                f = None
            elif (
                isinstance(child, ast.If)
                and fn is None
                and "__main__" in ast.unparse(child.test)
                and "__name__" in ast.unparse(child.test)
            ):
                f = "__main__"  # runs only as a script, never on import
            if isinstance(child, ast.Call):
                name = name_of(child.func)
                if RISKY.match(name):
                    risky.setdefault(fn, set()).add(name)
                refs = (
                    [dotted(child.func)]
                    + [dotted(a) for a in child.args]
                    + [dotted(k.value) for k in child.keywords]
                )
                for r in refs:
                    if r:
                        edges.setdefault(fn, set()).add(r.split(".")[-1])
            walk(child, f)

    walk(tree, None)
    reached, todo = set(), [None]
    while todo:
        cur = todo.pop()
        for n in edges.get(cur, ()):
            if n in defined and n not in reached:
                reached.add(n)
                todo.append(n)
    out = []
    for fn, names in risky.items():
        where = "TOP" if fn is None else (f"TOP-via-{fn}" if fn in reached else fn)
        out.extend((n, where) for n in names)
    return out


def main():
    corpus, results, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    with out.open("w") as fh:
        for f in sorted(glob.glob(str(results / "*.json"))):
            rec = json.loads(Path(f).read_text())
            if rec["status"] != "scanned":
                continue
            sev = [x for x in rec["result"]["findings"] if x["severity"] != "info"]
            if any(x["rule_id"] not in INTEG for x in sev):
                continue
            zf = zipfile.ZipFile(corpus / rec["sample"])
            inner = [i for i in zf.infolist() if not i.is_dir()]
            if len(inner) == 1 and inner[0].filename.endswith(".zip"):
                import io

                zf = zipfile.ZipFile(io.BytesIO(zf.read(inner[0], pwd=PWD)))
            kind, root, _, files = plan(zf, Path(rec["sample"]).stem)
            row = {
                "sample": rec["sample"],
                "kind": kind,
                "verdict": rec["result"]["verdict"],
                "rules": sorted({x["rule_id"] for x in rec["result"]["findings"]}),
                "files": [],
            }
            digest = hashlib.sha256()
            for name, info in sorted(files, key=lambda x: x[0]):
                rel = name[len(root) + 1 :] if root else name
                low = rel.lower()
                if not low.endswith((".py", ".cfg", ".toml", "pkg-info", "metadata", ".pth")):
                    if not low.endswith((".txt", ".md", ".json", ".rst", "record", "wheel")):
                        row["files"].append({"path": rel, "other": True, "size": info.file_size})
                    continue
                data = zf.read(info, pwd=PWD)
                text = data.decode("utf-8", "replace")
                entry = {"path": rel, "size": len(data)}
                if low.endswith(".py"):
                    norm = re.sub(r"version\s*=\s*['\"][^'\"]*['\"]", "", text)
                    norm = re.sub(r"name\s*=\s*['\"][^'\"]*['\"]", "", norm)
                    digest.update(rel.split("/")[-1].encode() + norm.encode())
                    try:
                        entry["calls"] = sorted({f"{n}@{fn}" for n, fn in calls(ast.parse(text))})
                    except (SyntaxError, ValueError, RecursionError) as exc:
                        entry["parse_error"] = type(exc).__name__
                if low.endswith(("pkg-info", "metadata")):
                    entry["requires"] = re.findall(r"^Requires-Dist:\s*(.+)$", text, re.M)
                if low.endswith("setup.py"):
                    m = re.search(r"install_requires\s*=\s*\[([^\]]*)\]", text)
                    entry["install_requires"] = m.group(1).strip()[:300] if m else None
                    entry["entry_points"] = "entry_points" in text
                    try:
                        mods = set()
                        for node in ast.walk(ast.parse(text)):
                            if isinstance(node, ast.Import):
                                mods.update(a.name.split(".")[0] for a in node.names)
                            elif (
                                isinstance(node, ast.ImportFrom) and node.module and not node.level
                            ):
                                mods.add(node.module.split(".")[0])
                        entry["imports"] = sorted(mods)
                    except (SyntaxError, ValueError, RecursionError):
                        pass
                hits = sorted({h[:120] for h in TEXT.findall(text)})
                if hits:
                    entry["text"] = hits[:15]
                row["files"].append(entry)
            row["cluster"] = digest.hexdigest()[:12]
            fh.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()
