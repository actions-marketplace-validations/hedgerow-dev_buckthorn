# Top 1,000 PyPI packages: benign run

Run 2026-11-05. Internal working note. Per `SPEC.md`, no accuracy number is
published until both corpora are reviewed; the counts here are for triage.

## What was scanned

- **Set:** the top 1,000 projects by 30-day downloads (hugovk's
  `top-pypi-packages` list, fetched 2026-11-05). For each, the latest sdist
  plus one wheel (pure Python, else CPython 3.12 manylinux x86_64), each
  checked against PyPI's sha256. 1,875 files; some projects ship only one.
  Script: `../datadog-malicious/scripts/fetch_benign.py`.
- **Where:** the Mac mini, in a container with `--network none` and the files
  mounted read-only (`scan_files.py`).
- **Before:** Buckthorn as merged in hedgerow-dev/buckthorn#1 (`ccc10db`).
  **After:** `312d9a2` (`scan-after.jsonl`), which also has the two rules
  found on the second malicious corpus (`../pypi-malregistry/RESULTS.md`).

## Results

| | Before | After |
|---|---|---|
| `clean` | 1,691 | 1,733 |
| `flagged` | 160 | 118 |
| `not_verified` | 22 | 24 |
| Scan errors (timeouts) | 2 | 0 |
| High or critical findings | 37 | 17 |
| Files newly flagged by the fixes | | 0 |

On DataDog's malicious corpus the false-alarm fixes lost no flag; with the
later rules it is 2,098 flagged, none lost
(`../datadog-malicious/results-final.jsonl`).

## What the run found and fixed

- **A hang.** nltk's Snowball stemmer chains `.replace()` dozens of times.
  Name resolution looked up a call's function twice, so each link doubled the
  work and the scan never finished. Now linear.
- **Building a client is not network.** `requests.Session()`,
  `urllib3.PoolManager()`, `httpx.Client()`, `aiohttp.ClientSession()` and
  `HTTPConnection()` connect nothing until used (sentry_sdk, posthog,
  courlan, htmldate build one at import). A call on one (`s.get`,
  `pm.request`) is the network access, as with sockets.
- **Strings that only name a path.** A default value (`os.environ.get`,
  `os.getenv`), a regex and `Path` methods were taken as reading a credential
  path (kubernetes, moto, smart_open). "crontab" matched a class name
  (google-cloud-spanner).
- **sdist files that are not installed.** Test folders at any depth and
  root-level `scripts`, `devscripts`, `dev`, `tools`, `build` and similar are
  skipped. An egg-info `top_level.txt` can add a root folder back but never
  hide one, since the uploader writes it.
- **The version-file trick in its real forms.** `with open(p) as f:
  exec(f.read())`, paths joined onto setup.py's own folder, `Path(__file__)
  .parent / ...`, a path held in a name bound once. Each must provably be
  setup.py's own folder; any other folder still reports exec. An exec'd file
  is now read at top level, as exec runs it.
- **An evasion, found on the way.** `exec(open('/tmp/p').read())` was looked
  up as the archive's own `tmp/p`, so a shipped decoy could stand in for the
  real file. An absolute path is now never the package's own file.

## The 118 still flagged

By each file's most serious finding. All read as real behaviour the rules
mean to report; none is a scanner bug.

| Finding | Files | What it is |
|---|---|---|
| Runs a process at install | 53 | Building C extensions: compilers, pkg-config, git (cffi, asyncpg, grpcio, psutil) |
| `exec` at import | 19 | Generated code (dill, attrs-style libraries, cryptography, gevent) |
| Runs a process at import | 17 | Version checks, tool probes, test modules shipped in packages (sphinx, networkx, gevent tests) |
| `exec` at install | 13 | 4 version files read through helpers not followed yet; 9 other (`eval` of a version line, a backend's exec) |
| Network at import | 5 | execnet's socket scripts, urllib3's test server, twisted's tests, matplotlib's URL loader reached at import |
| Start-up `.pth` | 4 | coverage, coloredlogs, setuptools, google-cloud-aiplatform's namespace `.pth` |
| Network at install | 4 | cmake, ddtrace, pymupdf, reportlab download at build time (cmake and ddtrace also read the environment: critical) |
| Encoded blob | 2 | python-pptx's embedded media |
| Native library in a pure wheel | 1 | debugpy's attach helpers |

`flags-after.txt` lists every finding, grouped by rule.

## Open

- **Symlinks make an sdist not_verified.** Most of the 24 are links to docs
  or licence files (deepdiff, beautifulsoup4, aiofile). Links are never
  followed, which is right, but only a link that is code (or named like it)
  should stop a clean verdict.
- **Test modules inside wheels** (gevent, twisted) are read like any installed
  module, though nothing imports them. Skipping them in wheels too would
  match the sdist rule; it is a policy call.
- **Version files read through a helper** (`read("pkg/v.py")` with a
  `def read`) or a variable path are still reported as exec.
