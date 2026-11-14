"""Fetch the latest tarball of each named npm package from registry.npmjs.org.

Each tarball is checked against the sha512 integrity the registry gives and
written as it is: nothing is unpacked or run. Usage: python -I fetch_benign_npm.py OUT
"""

import base64
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

# With install scripts or native builds, then common packages without.
NAMES = """
esbuild sharp bcrypt node-sass sqlite3 better-sqlite3 canvas bufferutil utf-8-validate
fsevents cpu-features ssh2 re2 argon2 node-pty keytar leveldown deasync @swc/core core-js
husky puppeteer cypress electron msw protobufjs es5-ext @parcel/watcher lmdb
msgpackr-extract nx @sentry/cli prisma @prisma/client @prisma/engines node-gyp
prebuild-install node-gyp-build unrs-resolver @biomejs/biome lefthook @scarf/scarf
lodash react react-dom express chalk debug commander axios typescript webpack vue moment
uuid semver yargs glob minimist ws dotenv jest mocha eslint prettier rxjs tslib classnames
underscore async bluebird request body-parser cross-env rimraf mkdirp npm yarn pnpm
node-fetch @babel/core @types/node next vite rollup zod
""".split()

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
for n, name in enumerate(NAMES):
    quoted = urllib.parse.quote(name, safe="@")
    try:
        with urllib.request.urlopen(f"https://registry.npmjs.org/{quoted}/latest", timeout=60) as r:  # noqa: S310
            dist = json.load(r)["dist"]
        url = dist["tarball"]
        if urllib.parse.urlsplit(url).netloc != "registry.npmjs.org":
            print(n, name, "OFF-REGISTRY", flush=True)
            continue
        with urllib.request.urlopen(url, timeout=300) as r:  # noqa: S310
            data = r.read(512 * 1024 * 1024)
        algo, _, want = dist["integrity"].partition("-")
        ok = algo == "sha512" and base64.b64encode(hashlib.sha512(data).digest()).decode() == want
        if ok:
            folder = out / f"{n:03d}"
            folder.mkdir(exist_ok=True)
            (folder / url.rsplit("/", 1)[1]).write_bytes(data)
        print(n, name, "ok" if ok else "BAD-INTEGRITY", len(data), flush=True)
    except Exception as exc:  # recorded, the run goes on
        print(n, name, "ERROR", type(exc).__name__, flush=True)
