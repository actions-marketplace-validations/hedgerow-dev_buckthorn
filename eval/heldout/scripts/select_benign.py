"""Pick and download the benign held-out sets B1 and B2 (see ../PROTOCOL.md).

Runs on the Azure VM with the network on. Downloads files and checks PyPI's sha256;
nothing is unpacked, installed or run. Standard library only.
Usage: python3 -I select_benign.py TOP_JSON OSV_JSONL EXCLUDE_NAMES TUNING_SHA256 TAGS OUT_DIR
  TOP_JSON       hugovk top-pypi-packages-30-days.min.json
  OSV_JSONL      one OSV MAL report per line (osv_table.py)
  EXCLUDE_NAMES  tuning benign project names, one per line
  TUNING_SHA256  sha256 of every tuning file, one per line
  TAGS           wheel tags the scan image accepts, best first (sys_tags order)
"""

import datetime as dt
import gzip
import hashlib
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

UA = {"User-Agent": "heldout-eval/1.0"}
B2_SEED = 20261112
B2_WANT = 1000


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def get(url, accept=None, tries=4):
    headers = dict(UA, **({"Accept": accept} if accept else {}))
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if attempt == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == tries - 1:
                raise
        time.sleep(2 * (attempt + 1))


def wheel_tags(filename):
    parts = filename[: -len(".whl")].split("-")
    py, abi, plat = parts[-3], parts[-2], parts[-1]
    return {f"{a}-{b}-{c}" for a in py.split(".") for b in abi.split(".") for c in plat.split(".")}


def pick_files(meta, rank):
    """The latest release's first sdist plus the best wheel this image would install."""
    files = meta.get("urls") or []
    picks = [f for f in files if f["packagetype"] == "sdist"][:1]
    best = None
    for f in files:
        if f["packagetype"] != "bdist_wheel" or not f["filename"].endswith(".whl"):
            continue
        r = min((rank[t] for t in wheel_tags(f["filename"]) if t in rank), default=None)
        if r is not None and (best is None or r < best[0]):
            best = (r, f)
    if best:
        picks.append(best[1])
    return picks


def latest_upload(meta):
    times = [
        f["upload_time_iso_8601"]
        for files in (meta.get("releases") or {}).values()
        for f in files
    ]
    return max(times) if times else None


def project_json(name):
    for attempt in range(4):  # a response can arrive cut short
        data = get(f"https://pypi.org/pypi/{name}/json")
        if data is None:
            return None
        try:
            return json.loads(data)
        except ValueError:
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"bad JSON for {name}")


def safe_json(name):
    try:
        return project_json(name)
    except Exception:  # recorded as a fetch error, the walk goes on
        return "ERROR"


def download(stratum, extra, meta, picks, out, tuning_sha, manifest, skipped):
    for f in picks:
        dest = out / stratum / f["filename"]
        row = dict(extra, stratum=stratum, project=norm(meta["info"]["name"]),
                   version=meta["info"]["version"], filename=f["filename"],
                   packagetype=f["packagetype"], sha256=f["digests"]["sha256"],
                   size=f["size"], upload_time=f["upload_time_iso_8601"], url=f["url"])
        if f["digests"]["sha256"] in tuning_sha:
            skipped.append(dict(row, reason="sha256 in a tuning corpus"))
            continue
        if not dest.exists():
            data = get(f["url"])
            if data is None or hashlib.sha256(data).hexdigest() != f["digests"]["sha256"]:
                skipped.append(dict(row, reason="download failed or hash mismatch"))
                continue
            dest.write_bytes(data)
        manifest.append(row)


def main():
    top_path, osv_path, excl_path, sha_path, tags_path, out = sys.argv[1:7]
    out = Path(out)
    (out / "b1").mkdir(parents=True, exist_ok=True)
    (out / "b2").mkdir(parents=True, exist_ok=True)
    top = json.load(open(top_path))["rows"]
    top3000 = {norm(r["project"]) for r in top[:3000]}
    tuning = {norm(l.strip()) for l in open(excl_path) if l.strip()}
    tuning |= {norm(r["project"]) for r in top[:1000]}
    tuning_sha = {l.strip() for l in open(sha_path) if l.strip()}
    rank = {t.strip(): i for i, t in enumerate(open(tags_path)) if t.strip()}
    mal = set()
    for line in open(osv_path):
        r = json.loads(line)
        if not r.get("withdrawn"):
            mal.add(r["name"])

    manifest, skipped, projects = [], [], []

    # B1: ranks 1,001 to 3,000.
    b1 = [(i + 1, norm(r["project"])) for i, r in enumerate(top) if 1000 <= i < 3000]
    with ThreadPoolExecutor(8) as pool:
        metas = list(pool.map(lambda x: safe_json(x[1]), b1))
    for (rk, name), meta in zip(b1, metas):
        row = {"stratum": "b1", "rank": rk, "project": name}
        if name in tuning:
            skipped.append(dict(row, reason="in a tuning benign set"))
        elif meta is None:
            skipped.append(dict(row, reason="not on PyPI"))
        elif meta == "ERROR":
            skipped.append(dict(row, reason="fetch error"))
        elif not (picks := pick_files(meta, rank)):
            skipped.append(dict(row, reason="no fetchable file"))
        else:
            projects.append(dict(row, version=meta["info"]["version"]))
            download("b1", {"rank": rk}, meta, picks, out, tuning_sha, manifest, skipped)
        print("b1", rk, name, flush=True)

    # B2: random projects with an upload in the last 30 days.
    # A restart reuses the first walk's start time and index, so the walk is the same.
    start_file, index_file = out / "b2-start.txt", out / "simple-index.json.gz"
    if not start_file.exists():
        start_file.write_text(dt.datetime.now(dt.timezone.utc).isoformat())
        index = get("https://pypi.org/simple/", accept="application/vnd.pypi.simple.v1+json")
        index_file.write_bytes(gzip.compress(index, mtime=0))
    start = dt.datetime.fromisoformat(start_file.read_text().strip())
    since = (start - dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
    index = gzip.decompress(index_file.read_bytes())
    names = sorted(p["name"] for p in json.loads(index)["projects"])
    order = names[:]
    random.Random(B2_SEED).shuffle(order)
    info = {"walk_start_utc": start.isoformat(), "upload_since": since,
            "simple_index_sha256": hashlib.sha256(index).hexdigest(),
            "simple_index_projects": len(names), "seed": B2_SEED}
    taken, walked, pos, batch = 0, 0, 0, 64
    with ThreadPoolExecutor(8) as pool:
        while taken < B2_WANT and pos < len(order):
            chunk = order[pos : pos + batch]
            pos += batch
            todo = [n for n in chunk if norm(n) not in top3000 | tuning | mal]
            metas = dict(zip(todo, pool.map(safe_json, todo)))
            for n in chunk:
                if taken >= B2_WANT:
                    break
                walked += 1
                name = norm(n)
                row = {"stratum": "b2", "walk": walked, "project": name}
                if name in top3000:
                    skipped.append(dict(row, reason="in top 3,000"))
                elif name in tuning:
                    skipped.append(dict(row, reason="in a tuning benign set"))
                elif name in mal:
                    skipped.append(dict(row, reason="OSV MAL report"))
                elif metas.get(n) is None:
                    skipped.append(dict(row, reason="not on PyPI"))
                elif metas[n] == "ERROR":
                    skipped.append(dict(row, reason="fetch error"))
                elif (latest_upload(metas[n]) or "") < since:
                    continue  # not recent: the common case, counted only in walked
                elif not (picks := pick_files(metas[n], rank)):
                    skipped.append(dict(row, reason="no fetchable file"))
                else:
                    taken += 1
                    projects.append(dict(row, version=metas[n]["info"]["version"],
                                         latest_upload=latest_upload(metas[n])))
                    download("b2", {"walk": walked}, metas[n], picks, out, tuning_sha,
                             manifest, skipped)
                    print("b2", taken, walked, name, flush=True)
    info.update(walked=walked, taken=taken)

    for fname, rows in (("manifest.jsonl", manifest), ("skipped.jsonl", skipped),
                        ("projects.jsonl", projects)):
        with open(out / fname, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    (out / "b2-walk.json").write_text(json.dumps(info, indent=1))
    print("DONE", json.dumps(info), flush=True)


if __name__ == "__main__":
    main()
