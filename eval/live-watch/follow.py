"""Follow npm and PyPI for new releases, fetch each file, check its hash and
put it in the spool for scan_spool.py. Runs on the host. Nothing is unpacked
or run here: files are bytes on disk until the scanner container reads them.

Usage: python3 -I follow.py STATE_DIR
STATE_DIR holds state.json, spool/, removals.jsonl, skipped.jsonl, and the
scanner's results/ (read for the hourly re-check of flagged releases).
"""

import base64
import concurrent.futures
import hashlib
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xmlrpc.client
from pathlib import Path

MAX_BYTES = 50 * 1024 * 1024
SPOOL_MAX = 2000  # items waiting; fetching pauses above this
WORKERS = 8
LATER = 300  # a new npm tarball can 404 for minutes: try again after 5, then 10 minutes
DEADLINE = 120  # seconds for one download, so one slow file cannot stall a batch
PACKUMENT_MAX = 50 * 1024 * 1024
NPM_HOST = "https://registry.npmjs.org/"
PYPI_FILES = "https://files.pythonhosted.org/"
HEADERS = {"User-Agent": "buckthorn-live-watch"}


# On 2026-11-24 the mini's IPv6 route to npm's CDN went dark, and each connection
# waited out its timeout on every IPv6 address first. IPv4 works, so use only that.
_resolve = socket.getaddrinfo


def _ipv4_only(host, port, family=0, *rest, **kwargs):
    return _resolve(host, port, socket.AF_INET, *rest, **kwargs)


socket.getaddrinfo = _ipv4_only
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!~-]*")
_PYPI_ADD = re.compile(r"add \S+ file (.+)")
_PYPI_REMOVE = re.compile(r"(remove (?:release|project|file\b.*)|yank release)")


def get(url: str, limit: int = MAX_BYTES) -> bytes:
    end, chunks, size = time.time() + DEADLINE, [], 0
    with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=60) as r:
        while chunk := r.read(1 << 20):
            size += len(chunk)
            if size > limit:
                raise ValueError("too big")
            if time.time() > end:
                raise TimeoutError("download too slow")
            chunks.append(chunk)
    return b"".join(chunks)


# What is new. Pure, so it can be tested on recorded feed pages.


def npm_new(packument: dict, after: str) -> list[tuple[str, str, str, str]]:
    """(version, published, tarball url, sha512 base64) for versions published
    after `after` (ISO time, as the registry writes it), oldest first."""
    times = packument.get("time") if isinstance(packument.get("time"), dict) else {}
    versions = packument.get("versions") if isinstance(packument.get("versions"), dict) else {}
    found = []
    for version, meta in versions.items():
        published = times.get(version)
        if not isinstance(published, str) or published <= after or not isinstance(meta, dict):
            continue
        dist = meta.get("dist") if isinstance(meta.get("dist"), dict) else {}
        sha512 = next(
            (p[7:] for p in str(dist.get("integrity", "")).split() if p.startswith("sha512-")), ""
        )
        found.append((version, published, str(dist.get("tarball", "")), sha512))
    return sorted(found, key=lambda row: row[1])


def pypi_events(events: list) -> tuple[list[tuple], list[tuple]]:
    """Split changelog_since_serial rows into files added
    (name, version, filename, when, serial) and removals (name, version, action, when)."""
    added, removed = [], []
    for name, version, when, action, serial in events:
        if match := _PYPI_ADD.fullmatch(action):
            added.append((name, version, match.group(1), when, serial))
        elif _PYPI_REMOVE.fullmatch(action):
            removed.append((name, version, action, when))
    return added, removed


def sampled(name: str, version: str) -> bool:
    """1 in 4 PyPI releases, by a hash of the normalized name and the version."""
    key = f"{re.sub(r'[-_.]+', '-', name).lower()}=={version}".encode()
    return hashlib.sha256(key).digest()[0] % 4 == 0


def pick(urls: list) -> dict | None:
    """The one file scanned from a release: the sdist, else a pure-Python
    wheel, else the first wheel by name."""
    files = sorted((u for u in urls if isinstance(u, dict)), key=lambda u: str(u.get("filename")))
    for test in (
        lambda n: n.endswith((".tar.gz", ".zip")),
        lambda n: n.endswith("-none-any.whl"),
        lambda n: True,
    ):
        found = [u for u in files if test(str(u.get("filename", "")))]
        if found:
            return found[0]
    return None


def safe_file(url: str, host: str) -> str | None:
    """The file name a registry URL ends in, if the URL is on that host and the
    name is a plain file name."""
    if not url.startswith(host):
        return None
    name = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
    return name if _FILENAME.fullmatch(name) and ".." not in name else None


def matches(data: bytes, algorithm: str, expected: str) -> bool:
    digest = hashlib.new(algorithm, data).digest()
    if algorithm == "sha512":
        return base64.b64encode(digest).decode() == expected
    return digest.hex() == expected


# Spool and logs.


class Watch:
    def __init__(self, root: Path, fetch=get) -> None:
        self.root, self.fetch = root, fetch
        self.spool = root / "spool"
        self.spool.mkdir(parents=True, exist_ok=True)
        state = root / "state.json"
        self.state = json.loads(state.read_text()) if state.exists() else {}
        self.state.setdefault("later", [])
        self.state.setdefault("pypi_done", {})
        self.n = 0

    def save(self) -> None:
        tmp = self.root / "state.json.tmp"
        tmp.write_text(json.dumps(self.state))
        os.replace(tmp, self.root / "state.json")

    def log(self, name: str, record: dict) -> None:
        with open(self.root / name, "a") as fh:
            fh.write(json.dumps(record | {"at": time.time()}) + "\n")

    def put(
        self, meta: dict, url: str, host: str, algorithm: str, expected: str, tries: int = 0
    ) -> None:
        """Fetch one file, check its hash, and add it to the spool, or log why
        not. A failed fetch is queued to try again later (state["later"])."""
        filename = safe_file(url, host)
        if filename is None:
            return self.log("skipped.jsonl", meta | {"why": "url"})
        if not expected:
            return self.log("skipped.jsonl", meta | {"why": "no hash"})
        try:
            data = self.fetch(url)
        except ValueError:
            return self.log("skipped.jsonl", meta | {"why": "too big"})
        except (OSError, urllib.error.URLError) as exc:
            why = f"fetch {exc.code}" if isinstance(exc, urllib.error.HTTPError) else "fetch"
            if tries >= 2:
                return self.log("skipped.jsonl", meta | {"why": why})
            due = time.time() + LATER * (tries + 1)
            self.state["later"].append([due, meta, url, host, algorithm, expected, tries + 1])
            return None
        if not matches(data, algorithm, expected):
            return self.log("skipped.jsonl", meta | {"why": "hash"})
        self.n += 1
        tmp = self.spool / f".tmp-{os.getpid()}-{self.n}-{time.time_ns()}"
        tmp.mkdir()
        (tmp / filename).write_bytes(data)
        meta = meta | {"file": filename, "fetched": time.time(), "bytes": len(data)}
        (tmp / "meta.json").write_text(json.dumps(meta))
        os.replace(tmp, self.spool / tmp.name[5:])  # complete items only

    def due(self) -> list[list]:
        """Queued fetches whose time has come, taken off the queue."""
        now, later = time.time(), self.state["later"]
        ready = [row[1:] for row in later if row[0] <= now]
        self.state["later"] = [row for row in later if row[0] > now]
        return ready

    # npm.

    def npm(self, name: str) -> None:
        start = self.state["started"]
        after = max(start, self.state["npm_after"].get(name, start))
        try:
            packument = json.loads(
                self.fetch(NPM_HOST + urllib.parse.quote(name, safe="@"), PACKUMENT_MAX)
            )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            return self.log("skipped.jsonl", {"eco": "npm", "name": name, "why": repr(exc)[:80]})
        for version, published, url, sha512 in npm_new(packument, after):
            meta = {"eco": "npm", "name": name, "version": version, "published": published}
            self.put(meta, url, NPM_HOST, "sha512", sha512)
            self.state["npm_after"][name] = published

    def npm_batch(self, pool) -> int:
        url = f"https://replicate.npmjs.com/_changes?since={self.state['npm_seq']}&limit=500"
        page = json.loads(self.fetch(url))
        names = sorted({row["id"] for row in page["results"] if not row["id"].startswith("_")})
        list(pool.map(self.npm, names))
        self.state["npm_seq"] = page["last_seq"]
        return len(names)

    # PyPI.

    def pypi_release(self, key: tuple, when: int, info: dict | None) -> None:
        meta = {"eco": "pypi", "name": key[0], "version": key[1], "published": when}
        entry = pick(info.get("urls") or []) if isinstance(info, dict) else None
        if entry is None:
            return self.log("skipped.jsonl", meta | {"why": "gone"})
        sha256 = (entry.get("digests") or {}).get("sha256", "")
        self.put(meta, entry.get("url", ""), PYPI_FILES, "sha256", sha256)

    def release(self, key: tuple) -> dict | None:
        url = (
            f"https://pypi.org/pypi/{urllib.parse.quote(key[0])}/{urllib.parse.quote(key[1])}/json"
        )
        try:
            return json.loads(self.fetch(url))
        except (OSError, ValueError, urllib.error.URLError):
            return None

    def pypi_batch(self, pool, rpc) -> int:
        events = rpc.changelog_since_serial(self.state["pypi_serial"])[:2000]
        added, removed = pypi_events(events)
        for name, version, action, when in removed:
            self.log(
                "removals.jsonl",
                {"eco": "pypi", "name": name, "version": version, "action": action, "when": when},
            )
        # One file from 1 in 4 releases, each release once: the files it had
        # when first seen.
        first: dict[tuple, int] = {}
        for name, version, _, when, _ in added:
            key = (name, version)
            if sampled(name, version) and f"{name}=={version}" not in self.state["pypi_done"]:
                first.setdefault(key, when)
        keys = sorted(first)
        for name, version in keys:
            self.state["pypi_done"][f"{name}=={version}"] = first[(name, version)]
        releases = pool.map(self.release, keys)
        list(
            pool.map(lambda kr: self.pypi_release(kr[0], first[kr[0]], kr[1]), zip(keys, releases))
        )
        if events:
            self.state["pypi_serial"] = events[-1][4]
        return len(keys)

    # Re-check flagged releases: when did each disappear?

    def recheck(self) -> None:
        gone = {(r["eco"], r["name"], r["version"]) for r in self.read("removals.jsonl")}
        for record in [
            r for part in sorted((self.root / "results").glob("*.jsonl")) for r in self.read(part)
        ]:
            key = (record["eco"], record["name"], record["version"])
            if record.get("verdict") != "flagged" or key in gone:
                continue
            gone.add(key)  # once per release per pass
            url = (
                NPM_HOST + urllib.parse.quote(key[1], safe="@")
                if key[0] == "npm"
                else f"https://pypi.org/pypi/{urllib.parse.quote(key[1])}/{urllib.parse.quote(key[2])}/json"
            )
            try:
                doc = json.loads(self.fetch(url, PACKUMENT_MAX))
                present = key[0] == "pypi" or key[2] in (doc.get("versions") or {})
            except urllib.error.HTTPError as exc:
                present = exc.code != 404
            except (OSError, ValueError, urllib.error.URLError):
                present = True  # unknown: ask again next hour
            if not present:
                self.log(
                    "removals.jsonl",
                    {"eco": key[0], "name": key[1], "version": key[2], "action": "recheck: gone"},
                )

    def read(self, name) -> list[dict]:
        path = self.root / name
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def main() -> None:
    watch = Watch(Path(sys.argv[1]))
    rpc = xmlrpc.client.ServerProxy("https://pypi.org/pypi")
    if "started" not in watch.state:
        watch.state = {
            "started": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "npm_seq": json.loads(watch.fetch("https://replicate.npmjs.com/"))["update_seq"],
            "pypi_serial": rpc.changelog_last_serial(),
            "npm_after": {},
            "later": [],
            "pypi_done": {},
        }
        watch.save()
    last_check = time.time()
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
        while True:
            waiting = sum(1 for p in watch.spool.iterdir() if not p.name.startswith("."))
            if waiting > SPOOL_MAX:
                time.sleep(30)
                continue
            try:
                n_npm = watch.npm_batch(pool)
                n_pypi = watch.pypi_batch(pool, rpc)
            except (
                OSError,
                ValueError,
                KeyError,
                urllib.error.URLError,
                xmlrpc.client.Error,
            ) as exc:
                print(time.strftime("%FT%T"), "feed error", repr(exc)[:200], flush=True)
                time.sleep(60)
                continue
            retried = watch.due()  # between batches, so no fetch is adding to the queue
            list(pool.map(lambda args: watch.put(*args), retried))
            watch.save()
            counts = f"npm {n_npm} pypi {n_pypi} retried {len(retried)} spool {waiting}"
            print(time.strftime("%FT%T"), counts, flush=True)
            if time.time() - last_check > 3600:
                watch.recheck()
                last_check = time.time()
            if n_npm < 50 and n_pypi < 50:
                time.sleep(60)


if __name__ == "__main__":
    main()
