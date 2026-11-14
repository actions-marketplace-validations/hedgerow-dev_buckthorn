"""Tokenize every .js, .mjs and .cjs file in the latest tarball of the top npm packages.

Run on a throwaway machine with no Node or npm: nothing here runs package code.
Usage: python3 -I run_top.py REPO NAMES OUT.jsonl SCRATCH [WORKERS [TOP]]

REPO is a Buckthorn checkout. NAMES is npm-high-impact's lib/top.js (MIT), read
in its order, most downloaded first; the first 1,000 are used. Each tarball is
fetched from registry.npmjs.org, checked against its sha512 integrity, held in
SCRATCH only while Buckthorn reads it into memory, then deleted. Nothing is
unpacked. Results keep paths, sizes, counts and times, never file content.

Each file is tokenized twice: as `buckthorn scan` does, with the shipped
limits, and again with the size and token limits raised, to see what the
limits cut and how long large files take. The whole tarball is also scanned
with `scan_artifact`, for the verdict and rule ids.
"""

import base64
import hashlib
import json
import multiprocessing
import posixpath
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO, NAMES, OUT, SCRATCH = sys.argv[1:5]
WORKERS = int(sys.argv[5]) if len(sys.argv) > 5 else 4
TOP = int(sys.argv[6]) if len(sys.argv) > 6 else 1000
sys.path.insert(0, REPO)

from buckthorn import js  # noqa: E402
from buckthorn.npm import _JS_MODULE as MODULE  # noqa: E402  as `buckthorn scan` reads them
from buckthorn.scan import read_archive, scan_artifact  # noqa: E402

SHIPPED = (js.MAX_SOURCE_BYTES, js.MAX_TOKENS)
RAISED = (32 * 1024 * 1024, 16_000_000)


def _get(url: str, limit: int) -> bytes:
    if urllib.parse.urlsplit(url).netloc != "registry.npmjs.org":
        raise ValueError("off-registry")
    with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310
        return r.read(limit + 1)


def _tokenize(data: bytes, module: bool | None, limits: tuple[int, int]) -> dict:
    js.MAX_SOURCE_BYTES, js.MAX_TOKENS = limits
    started = time.perf_counter()
    try:
        tokens = js.tokenize(data, module)
        result = {"outcome": "ok", "tokens": len(tokens)}
        result["depth"] = max((t.depth for t in tokens), default=0)
        del tokens
    except js.JSError as exc:
        result = {"outcome": exc.kind, "line": exc.line}
    result["s"] = round(time.perf_counter() - started, 4)
    return result


def one(job: tuple[int, str]) -> dict:
    rank, name = job
    row: dict = {"rank": rank, "name": name}
    try:
        quoted = urllib.parse.quote(name, safe="@")
        dist = json.loads(_get(f"https://registry.npmjs.org/{quoted}/latest", 64 << 20))
        row["version"] = dist.get("version")
        url, integrity = dist["dist"]["tarball"], dist["dist"].get("integrity", "")
        started = time.perf_counter()
        data = _get(url, 512 << 20)
        row["fetch_s"] = round(time.perf_counter() - started, 2)
        algo, _, want = integrity.partition("-")
        if algo != "sha512" or base64.b64encode(hashlib.sha512(data).digest()).decode() != want:
            row["status"] = "bad-integrity"
            return row
    except Exception as exc:  # recorded, the run goes on
        row["status"] = f"fetch-error {type(exc).__name__} {str(exc)[:80]}"
        return row
    row["status"], row["tar_bytes"] = "ok", len(data)
    folder = Path(SCRATCH) / f"{rank:04d}"
    folder.mkdir(exist_ok=True)
    path = folder / posixpath.basename(urllib.parse.urlsplit(url).path)  # as the registry names it
    path.write_bytes(data)
    del data
    try:
        js.MAX_SOURCE_BYTES, js.MAX_TOKENS = SHIPPED
        started = time.perf_counter()
        findings = scan_artifact(path)
        row["scan_s"] = round(time.perf_counter() - started, 2)
        row["rules"] = sorted(f.rule_id for f in findings)
        row["untokenized_notes"] = sum(f.message.startswith("JavaScript does not") for f in findings)
        members, read = read_archive(path)
        row["read_rules"] = sorted(f.rule_id for f in read)
    except Exception as exc:  # a scanner bug: recorded, the run goes on
        row["status"] = f"scan-error {type(exc).__name__}"
        return row
    finally:
        path.unlink()
        folder.rmdir()
    files = []
    for member, content in members:
        _, sep, rest = posixpath.normpath(member).lstrip("/").partition("/")
        extension = posixpath.splitext(rest)[1].lower()
        if not sep or extension not in MODULE:
            continue
        entry = {"path": rest, "bytes": len(content)}
        entry["shipped"] = _tokenize(content, MODULE[extension], SHIPPED)
        if entry["shipped"]["outcome"] in ("too-large", "too-many-tokens"):
            entry["raised"] = _tokenize(content, MODULE[extension], RAISED)
        if entry["shipped"]["outcome"] == "html-comment":
            entry["as_script"] = _tokenize(content, False, SHIPPED)["outcome"]
            entry["as_module"] = _tokenize(content, True, SHIPPED)["outcome"]
        files.append(entry)
    js.MAX_SOURCE_BYTES, js.MAX_TOKENS = SHIPPED
    row["files"] = files
    return row


def main() -> None:
    text = Path(NAMES).read_text()
    names = re.findall(r"^\s*'([^']+)',?$", text, re.M)[:TOP]
    if len(names) != TOP:
        raise SystemExit(f"{len(names)} names read, {TOP} wanted")
    Path(SCRATCH).mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as out, multiprocessing.Pool(WORKERS, maxtasksperchild=20) as pool:
        for n, row in enumerate(pool.imap_unordered(one, enumerate(names, 1)), 1):
            out.write(json.dumps(row) + "\n")
            out.flush()
            if n % 50 == 0:
                print(n, "done", flush=True)


if __name__ == "__main__":
    main()
