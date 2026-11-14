"""Fetch the latest tarball of the top npm packages, integrity checked.

Run on a throwaway machine with no Node or npm: nothing here runs package code
and nothing is unpacked. Usage: python3 -I fetch_top.py NAMES CACHE [WORKERS [TOP]]

NAMES is npm-high-impact 1.13.0's lib/top.js (MIT), read in its order, most
downloaded first, as phase 2 used it. Each tarball comes from
registry.npmjs.org and is kept in CACHE only if its sha512 matches the
registry's `integrity`. CACHE/index.jsonl lists rank, name, version, file.
"""

import base64
import hashlib
import json
import multiprocessing
import posixpath
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

NAMES, CACHE = sys.argv[1:3]
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 8
TOP = int(sys.argv[4]) if len(sys.argv) > 4 else 1000


def _get(url: str, limit: int) -> bytes:
    if urllib.parse.urlsplit(url).netloc != "registry.npmjs.org":
        raise ValueError("off-registry")
    with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310
        return r.read(limit + 1)


def one(job: tuple[int, str]) -> dict:
    rank, name = job
    row: dict = {"rank": rank, "name": name}
    try:
        quoted = urllib.parse.quote(name, safe="@")
        dist = json.loads(_get(f"https://registry.npmjs.org/{quoted}/latest", 64 << 20))
        row["version"] = dist.get("version")
        url, integrity = dist["dist"]["tarball"], dist["dist"].get("integrity", "")
        data = _get(url, 512 << 20)
        algo, _, want = integrity.partition("-")
        if algo != "sha512" or base64.b64encode(hashlib.sha512(data).digest()).decode() != want:
            row["status"] = "bad-integrity"
            return row
    except Exception as exc:  # recorded, the run goes on
        row["status"] = f"fetch-error {type(exc).__name__}"
        return row
    folder = Path(CACHE) / f"{rank:04d}"
    folder.mkdir(exist_ok=True)
    path = folder / posixpath.basename(urllib.parse.urlsplit(url).path)  # as the registry names it
    path.write_bytes(data)
    row["status"], row["file"] = "ok", str(path.relative_to(CACHE))
    return row


def main() -> None:
    names = re.findall(r"^\s*'([^']+)',?$", Path(NAMES).read_text(), re.M)[:TOP]
    if len(names) != TOP:
        raise SystemExit(f"{len(names)} names read, {TOP} wanted")
    Path(CACHE).mkdir(parents=True, exist_ok=True)
    with open(Path(CACHE) / "index.jsonl", "w") as out, multiprocessing.Pool(WORKERS) as pool:
        for row in pool.imap_unordered(one, enumerate(names, 1)):
            out.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()
