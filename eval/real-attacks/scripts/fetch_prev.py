"""For each sample in SAMPLES/picked.tsv, fetch the version npm published just before it.

That earlier version is the one a lockfile bump moves from. Each tarball is
checked against the registry's sha512 integrity. Runs on the host, not in the
scan container; nothing is unpacked or run. Usage: python -I fetch_prev.py SAMPLES
"""

import base64
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

samples = Path(sys.argv[1])
(samples / "prev").mkdir(exist_ok=True)
packuments = {}


def get(url, limit):
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
        return resp.read(limit)


def key(v):
    head = v.split("-")[0].split("+")[0]
    try:
        return tuple(int(x) for x in head.split("."))
    except ValueError:
        return None


with open(samples / "prev.tsv", "w") as index:
    for line in (samples / "picked.tsv").read_text().splitlines():
        zname, _, _, dpath = line.split("\t")
        _, _, _, enc, version, _ = dpath.split("/")
        name = "@" + enc[1:].replace("@", "/", 1) if enc.startswith("@") else enc
        status, prev = "none", ""
        try:
            if name not in packuments:
                url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
                packuments[name] = json.loads(get(url, 100 * 1024 * 1024))
            doc = packuments[name]
            bad = key(version)
            older = [
                v
                for v in doc.get("versions", {})
                if key(v) and bad and key(v) < bad and "-" not in v
            ]
            if older:
                prev = max(older, key=key)
                dist = doc["versions"][prev]["dist"]
                data = get(dist["tarball"], 60 * 1024 * 1024)
                algo, _, want = dist.get("integrity", "").partition("-")
                ok = algo == "sha512" and base64.b64decode(want) == hashlib.sha512(data).digest()
                status = "ok" if ok else "BAD"
                if ok:
                    (samples / "prev" / zname.replace(".zip", ".tgz")).write_bytes(data)
        except Exception as exc:  # recorded per sample, the run goes on
            status = "error:" + type(exc).__name__
        index.write(f"{zname}\t{name}\t{version}\t{prev}\t{status}\n")
        print(zname, name, version, prev, status, flush=True)
