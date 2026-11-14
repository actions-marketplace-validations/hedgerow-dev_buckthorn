# DataDog malicious PyPI corpus: first run

Run 2026-11-03 with Buckthorn at commit `0ff1f80` (branch `m1-artifact-scan`),
then again after the G6, G2 and G1 rule changes (see below).
A working note from tuning. The counts below are what this run produced, for
triage, not a detection rate. The headline numbers are in
`../heldout/RESULTS.md`.

## What was scanned

- **Corpus:** `DataDog/malicious-software-packages-dataset`, commit `9c24607`,
  `samples/pypi` only: 2,532 zips (2,503 `malicious_intent`, 29
  `compromised_lib`).
- **Where:** the Mac mini container host. The corpus was sparse-cloned into a
  Podman volume. The scan ran in a container with `--network none`,
  `--read-only`, `--cap-drop all`, the corpus volume mounted read-only and a
  tmpfs for scratch. Nothing was downloaded or unpacked on the MacBook.
- **Samples are unpacked trees, not the original files.** Each zip holds the
  dataset's extraction of a wheel or sdist (sometimes beside a git checkout of
  the project). `scripts/run_corpus.py` copies the members straight from the
  zip into a rebuilt archive (no tree is written to disk) and runs
  `buckthorn scan --format json` on it:
  - a `.dist-info/METADATA` present: rebuilt as a wheel (tag from `WHEEL`);
  - else a `PKG-INFO`: rebuilt as an sdist;
  - else (git checkouts, mostly `compromised_lib`): rebuilt as an sdist with no
    `PKG-INFO`, so `BKT-META-001` fires by construction on those.
  - Some samples store `a/b` as `a/b/a/b`; the doubled tail is dropped.

Because of the rebuild, the integrity rules (`BKT-REC-*`, `BKT-META-001`) say
little here. A hash mismatch may be the attacker's edit or the dataset's
extraction.

## Results

| | Samples |
|---|---|
| Zips | 2,532 |
| Empty zips (no files) | 28 |
| Scanned | 2,504 |
| `flagged` | 1,597 |
| ... of which only by integrity rules | 12 |
| `clean` | 896 |
| `not_verified` | 11 |

By group: `malicious_intent` 1,577 flagged, 887 clean, 11 not_verified;
`compromised_lib` 20 flagged, 9 clean.

Rules that fired (samples with at least one finding of that rule):

| Rule | Samples | Rule | Samples |
|---|---|---|---|
| BKT-INSTALL-002 | 979 | BKT-REC-001 | 16 |
| BKT-INSTALL-001 | 491 | BKT-PTH-001 | 15 |
| BKT-HIDE-001 | 159 | BKT-META-001 | 11 |
| BKT-HIDE-002 | 95 | BKT-IMPORT-003 | 11 |
| BKT-IMPORT-001 | 86 | BKT-START-001 | 4 |
| BKT-INSTALL-003 | 60 | BKT-INSTALL-004 | 2 |
| BKT-IMPORT-002 | 36 | BKT-INSTALL-005 | 2 |
| BKT-INSTALL-008 | 25 | BKT-BIN-002 | 2 |
| BKT-INSTALL-006 | 25 | BKT-BIN-003 | 1 |
| BKT-SKIP-003 | 18 | BKT-IMPORT-006 | 1 |
| BKT-REC-002 | 17 | | |

Per-sample verdicts and findings: `results.jsonl` (one line per zip).

## Triage of the misses

Triaged: all 896 clean, the 12 flagged only on integrity, and the 11
not_verified (919 samples). Every one has a row in `triage.csv` with the reason
and the gap that would catch it.

**How:** `scripts/triage.py` parses each sample (offline, in the same
container) and records where risky calls sit: install code, module top level,
reached from top level through a same-module function or thread target, or
only inside functions. `scripts/classify.py` turns that into a reason.
Representatives of every bucket were read by hand, and 113 samples carry a
hand-written reason (the `hand` bucket). The rest are labelled from the
extracted features, so a single row can be wrong; the buckets held up on
every sample read. A first pass counted calls under `if __name__ ==
"__main__":` as import-time code; the counts here are after fixing that.

| Why it was missed | Samples | Gap |
|---|---|---|
| Payload in an **sdist's package modules**, runs at import after install | 251 | G1 |
| **setup.py calls a function in a local module** it imports (`from main import main; main()`) | 210 | G6 |
| **Module-level code calls a same-module function** or starts it as a thread target; the risky call is inside that function | 68 (53 primary) | G2 |
| Payload only in functions the user calls, a console script, `__main__`, or CI | 184 | out of scope |
| **No payload in the sample**: placeholders, probes, dependency-only packages, files missing from the sample, payload in native code | 138 | none |
| Inert as shipped (payload never executed, broken PoC, request never sent) | 39 | none |
| Install code builds a start-up or home path at run time (f-string, `chr()` list, base64), so the path regex never sees it | 16 | G3 |
| Correctly `not_verified` (a file does not parse) | 11 | none |
| setup.py imports and runs a **malicious dependency** from `install_requires` | 9 | none here |
| Install code reaches a call through `importlib` + `getattr` with a built name | 3 | G7 |
| TLS socket: `ssl` `wrap_socket(...)` then `connect`/`send` | 3 | G4 |
| Executable shipped inside an sdist | 1 | G8 |

G5 (GitPython clone and `pip._internal.main` not counted as network or process)
is a secondary cause on 13 samples.

### Compromised libraries (all 9 clean ones read by hand)

- **telnyx 4.87.1, 4.87.2:** `_client.py` calls `setup()` and `FetchAudio()`
  at module level. They download a payload, drop it in the Windows Startup
  folder (path base64-encoded) and run `python -c exec(b64decode(...))`. G2.
- **mistralai 2.4.6:** `client/__init__.py` calls `_run_background_task()` at
  module level, which runs `Popen`. G2.
- **lightning 2.6.2, 2.6.3:** `__init__.py` starts
  `threading.Thread(target=_run_runtime)` at import. G2.
- **litellm 1.82.7 (sdist):** `proxy/proxy_server.py` writes a decoded base64
  blob to a temp file and runs it at module level. G1.
- **ultralytics 8.3.41, 8.3.42:** the miner starts when a YOLO model is
  created. Runtime code, out of scope. (8.3.45 and 8.3.46 were flagged:
  `BKT-IMPORT-001`, `BKT-IMPORT-002` in `__init__.py`.)
- **memoryos 2.0.34:** the downloader is a CI-time script, not run at install
  or import. Out of scope.

## G6 and G2: implemented and rescanned

Both are now in the scanner (see `docs/rules.md`):

- **G6:** a local module that `setup.py` or a shipped backend imports is read
  at top level, plus the functions the install code calls from it
  (`from main import main; main()` reads `main()`). Unused functions of the
  module are not read, so `from pkg import __version__` stays quiet.
- **G2:** a module-level function counts as top-level code when module-level
  code calls it, passes it (or a lambda that calls it) as a thread or process
  `target=`, or passes it to `atexit.register`, directly or through other
  functions in the same file. `exec` inside a followed function is not
  reported: it runs code its caller hands it (six's `exec_`, attrs).

Both corpora were rescanned on the mini, offline, with the old and new
builds. `results-g2g6.jsonl` holds the new per-sample results.

| | Before | After |
|---|---|---|
| Malicious: `flagged` | 1,597 | 1,858 |
| Malicious: `clean` | 896 | 635 |
| Malicious: `not_verified` | 11 | 11 |
| Malicious samples that lost a flag | | 0 |
| Benign (top 100 PyPI, 197 files): `flagged` | 10 | 12 |

- **G6:** 205 of the 210 G6 misses are now flagged. The rest: three
  crytic-compilers samples whose imported module is not in the sample, and
  two (b10connoisseur, randrange) not yet checked by hand.
- **G2:** 50 of the 53 wheel-only G2 misses are now flagged, including
  telnyx, mistralai and lightning. The other three call only `ctypes` or
  version-parsing code, which no rule lists. G2 misses in sdists wait on G1.
- **Compromised libraries:** 27 of 29 are flagged; litellm 1.82.7 (needs G1)
  and memoryos (CI script) are not. ultralytics 8.3.41 and 8.3.42 are now
  flagged, but for its own `is_online()` check at import, not for the miner.
- **Benign cost:** two newly flagged files, both real behaviour at medium
  severity. lxml's `setup.py` runs pkg-config through its `setupinfo.py`
  helper, and websockets runs git at import to work out its version. A first
  build also flagged attrs, six, botocore, scipy, typing_inspection, fsspec,
  jsonschema and setuptools; narrowing "handed to a call" to `target=` and
  `atexit.register`, and leaving out `exec` in followed functions, removed
  those.

Known limits, left for later: functions imported from a sibling module and
called at import (license-utils-kit) are not followed; `src/` layouts and
`sys.path` changes in `setup.py` are not resolved; `atexit.register` is
matched by name only, not through import aliases.

## G1 and BlankOBF: implemented and rescanned

- **G1:** the modules of an sdist's packages are read with the import and
  hidden-code rules, as a wheel's are. A file counts when every folder from
  the package root (top of the sdist or `src/`) down to it has an
  `__init__.py`. Root-level `tests`, `docs` and `examples` packages are
  skipped: reading them would newly flag 5 of the 100 benign sdists (aiohttp
  and pyparsing examples, sqlalchemy, truststore and urllib3 tests). A
  payload placed there only runs if something imports it.
- **BlankOBF:** about 55 G1 misses were one obfuscator family that does
  `_ = eval("\145\166\141\154")`, which hands back `eval` under another
  name. `exec`/`eval` of a literal that is only a dangerous builtin's name is
  now `BKT-HIDE-001`.

`results-g1.jsonl` holds the per-sample results after both.

| | Baseline | After G6+G2 | After G1 |
|---|---|---|---|
| Malicious: `flagged` | 1,597 | 1,858 | 2,088 |
| Malicious: `clean` | 896 | 635 | 388 |
| Malicious: `not_verified` | 11 | 11 | 28 |
| Malicious samples that lost a flag | | 0 | 0 |
| Benign (197 files): `flagged` | 10 | 12 | 15 |

- **G1:** 224 of the 251 G1 misses are now flagged, litellm 1.82.7 among
  them. Of the 27 left, 11 are now `not_verified` (package code that does not
  parse, which is the right answer) and 15 are clean.
- **Compromised libraries:** 28 of 29 are flagged; only memoryos (a CI-time
  script) is not.
- **not_verified** rose by 17: sdist package modules that do not parse are now
  reported as not read, as they are for wheels.
- **Benign cost of G1:** three more files flagged, all real behaviour:
  cryptography's `_cffi_src` execs a file named at run time, scipy ships a
  test generator inside the package and execs generated code in
  `_distn_infrastructure`, and urllib3's `dummyserver` test helper does a DNS
  lookup at import.

## Proposed rule changes still open

Ordered by how many misses each covers.

1. **G3: fold simple string building before path matching.** f-strings with
   constant parts, `''.join`, `chr()` lists and `b64decode` of a constant.
   Also consider an install-time write (`open(..., "w"/"a")`) to a path under
   the home folder or `%APPDATA%`.
2. **Small list additions:** `git.Repo.clone_from` and `git.Git().clone` as
   network (G5); `pip._internal.main` / `pip.main` as process (G5); a socket
   wrapped by `ssl` keeps its socket alias (G4).
3. **Lower value:** `importlib.import_module` + `getattr` with a computed name
   in install code (G7, 3 samples); `BKT-BIN-*` checks for sdists (G8, 1).
4. **Coverage limits found on the way:** functions imported from a sibling
   module and called at import; namespace packages and loose `src/` modules
   in sdists; `src/` layouts and `sys.path` changes in `setup.py`.

One more shape worth a rule: decoding a blob to a file and running it with
`subprocess` (litellm). It is now `BKT-IMPORT-002`, but it is hidden code in
the same sense as `BKT-HIDE-001`.

## Caveats

- The dataset was mostly found by GuardDog, so it leans to what GuardDog
  detects (the dataset README says so).
- Many samples are near-duplicates (same campaign, many versions). Counts are
  of samples, not of distinct techniques.
- 28 empty zips and the 136 "no payload" samples carry nothing a static
  scanner of this sample could find.
- The benign set is the top 100 PyPI packages by 30-day downloads (hugovk's
  list), latest sdist plus one wheel each, sha256-checked against PyPI. It is
  rebuilt for this run, not the earlier 47-package set.
- The Backstabber's Knife Collection (the second corpus in `SPEC.md`) was not
  run.

## Reproduce

On the mini, from `scripts/`: build the image from `Containerfile` with this
repo's `git archive HEAD` as `buckthorn-src.tar`
(`--platform linux/amd64`), sparse-clone the dataset's `samples/pypi` into a
volume, then:

```bash
podman run --rm --network none --user 0 --read-only --cap-drop all \
  --security-opt no-new-privileges --tmpfs /work:size=3g \
  -v bkt-malcorpus:/c:ro -v ./scripts:/driver:ro -v ./out:/out \
  localhost/buckthorn-scan:0ff1f80 \
  python -I /driver/run_corpus.py /c/ds/samples/pypi /out /work
```

`triage.py` then writes `missed.jsonl` from `out/`, and `classify.py` turns it
into `triage.csv`. `missed.jsonl` is not committed: it holds raw strings from
the samples, including live webhook URLs.
