"""Fetch the latest stable .nupkg of the top NuGet packages, hash checked.

Run on a throwaway machine with no .NET: nothing here runs package code and
nothing is unpacked. Usage: python3 -I fetch_top.py CACHE [WORKERS [TOP]]

The list: nuget.org search with no query, stable only, the first 3,000 results
(the most the search API pages to), sorted by total downloads, top TOP kept.
It is written to CACHE/top.jsonl. Each .nupkg comes from nuget.org's flat
container and is kept in CACHE only if its sha512 matches the catalog's
packageHash. CACHE/index.jsonl lists rank, name, version, file.
"""

import base64
import gzip
import hashlib
import json
import multiprocessing
import sys
import urllib.parse
import urllib.request
from pathlib import Path

CACHE = sys.argv[1]
WORKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 8
TOP = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
SEARCH = "https://azuresearch-usnc.nuget.org/query?q=&prerelease=false&semVerLevel=2.0.0"
HOSTS = {"api.nuget.org", "azuresearch-usnc.nuget.org"}


def _get(url: str, limit: int) -> bytes:
    if urllib.parse.urlsplit(url).netloc not in HOSTS:
        raise ValueError("off-registry")
    with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310
        data = r.read(limit + 1)
        if r.headers.get("Content-Encoding") == "gzip":
            data = gzip.decompress(data)
    if len(data) > limit:
        raise ValueError("too big")
    return data


def _json(url: str) -> dict:
    return json.loads(_get(url, 64 << 20))


def top() -> list[dict]:
    seen: dict[str, dict] = {}
    for skip in (0, 1000, 2000):
        for hit in _json(f"{SEARCH}&skip={skip}&take=1000")["data"]:
            leaf = next((v["@id"] for v in hit["versions"] if v["version"] == hit["version"]), None)
            if leaf is None:  # unlisted since the index was built
                continue
            seen.setdefault(
                hit["id"].lower(),
                {
                    "name": hit["id"],
                    "version": hit["version"],
                    "downloads": hit["totalDownloads"],
                    "leaf": leaf,
                },
            )
    ranked = sorted(seen.values(), key=lambda h: -h["downloads"])[:TOP]
    return [h | {"rank": n} for n, h in enumerate(ranked, 1)]


def one(hit: dict) -> dict:
    row = {k: hit[k] for k in ("rank", "name", "version")}
    try:
        catalog = _json(_json(hit["leaf"])["catalogEntry"])
        if catalog.get("packageHashAlgorithm", "").upper() != "SHA512":
            row["status"] = "no-sha512"
            return row
        lower_id, lower_version = catalog["id"].lower(), catalog["version"].lower()
        name = f"{lower_id}.{lower_version.partition('+')[0]}.nupkg"
        url = f"https://api.nuget.org/v3-flatcontainer/{lower_id}/{lower_version.partition('+')[0]}/{name}"
        data = _get(url, 1 << 30)
        if base64.b64encode(hashlib.sha512(data).digest()).decode() != catalog["packageHash"]:
            row["status"] = "bad-hash"
            return row
    except Exception as exc:  # recorded, the run goes on
        row["status"] = f"fetch-error {type(exc).__name__}"
        return row
    folder = Path(CACHE) / f"{hit['rank']:04d}"
    folder.mkdir(exist_ok=True)
    (folder / name).write_bytes(data)
    row["status"], row["file"] = "ok", f"{folder.name}/{name}"
    return row


def main() -> None:
    Path(CACHE).mkdir(parents=True, exist_ok=True)
    hits = top()
    if len(hits) != TOP:
        raise SystemExit(f"{len(hits)} packages listed, {TOP} wanted")
    with open(Path(CACHE) / "top.jsonl", "w") as out:
        out.writelines(json.dumps(h) + "\n" for h in hits)
    with open(Path(CACHE) / "index.jsonl", "w") as out, multiprocessing.Pool(WORKERS) as pool:
        for row in pool.imap_unordered(one, hits):
            out.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()
