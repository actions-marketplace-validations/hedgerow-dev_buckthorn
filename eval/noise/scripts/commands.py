"""For artifacts flagged only for a process at install (BKT-INSTALL-002), name the
program each flagged call runs. Prints counts, never the command lines themselves.

Runs inside a --network none container with the corpus read-only.
Usage: python -I commands.py RESULTS_JSONL ROOT_PREFIX MOUNT
  ROOT_PREFIX is the path prefix in the results, replaced by MOUNT.
"""

import ast
import collections
import json
import sys
import tarfile
import zipfile


def program(arg):
    """What the first argument of a process call names."""
    if isinstance(arg, (ast.List, ast.Tuple)):
        if not arg.elts:
            return "empty list"
        first = arg.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return "list:" + first.value.rsplit("/", 1)[-1][:30]
        return "list:" + ast.unparse(first)[:30]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        words = arg.value.split()
        return "str:" + (words[0].rsplit("/", 1)[-1][:30] if words else "")
    return "dynamic:" + type(arg).__name__


def read(path, member):
    if path.endswith(".whl") or path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            return z.read(member)
    with tarfile.open(path) as t:
        return t.extractfile(member).read()


results, prefix, mount = sys.argv[1:4]
counts = collections.Counter()
for line in open(results):
    r = json.loads(line).get("result") or {}
    found = [f for f in r.get("findings", []) if f["severity"] != "info"]
    if r.get("verdict") != "flagged" or {f["rule_id"] for f in found} != {"BKT-INSTALL-002"}:
        continue
    path = mount + r["path"][len(prefix):]
    for f in found:
        try:
            tree = ast.parse(read(path, f["file"]))
        except Exception as exc:
            counts["unreadable:" + type(exc).__name__] += 1
            continue
        lines = set(f.get("metadata", {}).get("lines", []))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.lineno in lines:
                name = ast.unparse(node.func)
                if name.split(".")[-1] in {"run", "call", "check_call", "check_output", "Popen", "system", "popen", "startfile", "main"}:
                    counts[program(node.args[0]) if node.args else "no args"] += 1
for name, n in counts.most_common(40):
    print(f"{n:6} {name}")
