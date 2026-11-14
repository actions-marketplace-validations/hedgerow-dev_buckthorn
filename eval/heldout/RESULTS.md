# Held-out run: Buckthorn c80b090 and GuardDog 3.2.0

Run 2026-11-12.
Protocol in `PROTOCOL.md`, committed as `f3a5701` at 2026-11-12 21:46 +0100,
before any held-out sample was fetched or scanned. Nothing in the rules was
changed during or after this run.

## Answer first

- **Malicious: Buckthorn flags about half of what it has never seen.** 225 of
  430 held-out archives, 52.3% (95% interval 47.6 to 57.0). On the tuning
  corpora the same rules (`17cc527`, identical code) flagged 93%
  (pypi_malregistry) and 85% (DataDog). GuardDog's threat rules catch 68.6%
  (64.1 to 72.8) of the same archives.
- **Most misses are out of Buckthorn's scope, by design.** In 39 of 50 sampled
  misses the payload runs only when the user calls a function: a downloader
  behind `fetch(url)`, a miner behind `harness.run()`, a stealer behind
  `init()`. Buckthorn reads install, start-up and import code only. Only one
  of the 50 is an install-time payload a rule should have caught.
- **Benign: the noise holds up.** Buckthorn flags 308 of 5,723 benign files
  it never saw, 5.4% (4.8 to 6.0), against 6.9% on the top 1,000 it was
  tuned on. GuardDog's threat rules flag 23.7% (22.6 to 24.8). Of 50 sampled
  Buckthorn flags, 42 are real behaviour the rule describes, 8 are false
  alarms, none is malicious.

The headline number for Buckthorn is the held-out one, not the tuning one.

## What was scanned

**Malicious.** pypi_malregistry added 431 archives on 2026-11-11 (`76e8530`),
after both tuning snapshots (pypi_malregistry `5f2592d`, 2026-09-03; DataDog
`9c24607`, 2026-11-03). DataDog added no PyPI sample after our clone. One
archive (memoryos 2.0.34) shares name and version with a DataDog sample and
was dropped, leaving **430 archives (365 sdists, 65 wheels) from 227
packages**. No sha256 matched a tuning file and none repeated.

- **Families.** 424 archives are new family, 6 seen (same name after
  stripping digits, one edit from a tuning name, or a shared `.py` file). The
  430 fall into 205 groups.
- **First reported (OSV).** 38 archives belong to packages first reported on
  or after 2026-11-03, 392 to packages reported earlier (all but one name
  after the pypi_malregistry snapshot).

**Benign.** Latest release of each project: the sdist plus the wheel the
scan image would install. No project is in a tuning set and no file matches
a tuning file's sha256.

- **B1:** PyPI ranks 1,001 to 3,000 (hugovk's list of 2026-11-01, the same
  snapshot as the top 1,000): 1,999 projects, 3,834 files. One project had
  no file this image could install and no sdist.
- **B2:** 1,000 projects with an upload between 2026-10-13 and 2026-11-12,
  from a seeded walk (seed 20261112) of 10,866 projects in the PyPI simple
  index (938,498 projects): 1,889 files. 321 names in the index were gone
  from PyPI, 37 were in the top 3,000, 1 had an OSV MAL report, 1 was in a
  tuning set, 7 had no fetchable file and 1 fetch failed. A recheck
  of OSV at `af35de5` found no B2 project reported since.

**Code.** `git archive c80b090` (sha256 `dfb3dd7f...c28d`), one image
(`0c551ce9...7f33`) built on the Mac mini and loaded on the Azure VM with the
same id. GuardDog 3.2.0, image `166c1e89...3a2e`, offline, so its metadata
rules did not run. Malware ran on the mini only, benign files on Azure only,
in containers with no network, read-only and no capabilities.

## Results: malicious (430 archives)

| | Rate (95% interval) |
|---|---|
| **Buckthorn flagged** | **225 (52.3%, 47.6 to 57.0)** |
| Buckthorn not_verified | 1 (0.2%, 0.0 to 1.3) |
| Buckthorn clean | 204 (47.4%, 42.8 to 52.2) |
| GuardDog threat | 295 (68.6%, 64.1 to 72.8) |
| GuardDog any rule | 380 (88.4%, 85.0 to 91.1) |
| Either (Buckthorn flagged or GuardDog threat) | 321 (74.7%, 70.3 to 78.5) |

No scan errors or timeouts for either tool. One Buckthorn flag is on
integrity rules only. The one not_verified (fontcase 0.1.1, `BKT-SKIP-003`)
is not counted as caught.

| Split | n | Buckthorn flagged | GuardDog threat |
|---|---|---|---|
| New family | 424 | 221 (52.1%, 47.4 to 56.8) | 289 (68.2%, 63.6 to 72.4) |
| Seen family | 6 | 4 (66.7%, 30.0 to 90.3) | 6 (100%, 61.0 to 100) |
| OSV first report on or after 2026-11-03 | 38 | 25 (65.8%, 49.9 to 78.8) | 30 (78.9%, 63.7 to 88.9) |
| OSV first report before 2026-11-03 | 392 | 200 (51.0%, 46.1 to 55.9) | 265 (67.6%, 62.8 to 72.0) |
| One archive per package (seeded pick) | 227 | 107 (47.1%, 40.7 to 53.6) | 148 (65.2%, 58.8 to 71.1) |

Where they differ: Buckthorn flagged and GuardDog no threat 26; GuardDog
threat and Buckthorn not flagged 96; both missed 109.

Rules that fired most (archives): `BKT-INSTALL-002` 86, `BKT-INSTALL-001` 84,
`BKT-IMPORT-001` 40, `BKT-IMPORT-002` 36, `BKT-PTH-001` 21, `BKT-EXFIL-001` 18.

The seen-family split is too small to say anything: 6 archives. The family
test finds few links because this wave reuses templates, not files (see the
triage), so "new family" here means new to the tuning data by name and by
exact file, not a new technique.

## Results: benign

| | B1: ranks 1,001 to 3,000 (3,834 files) | B2: random recent (1,889 files) |
|---|---|---|
| **Buckthorn flagged** | **232 (6.1%, 5.3 to 6.9)** | **76 (4.0%, 3.2 to 5.0)** |
| Buckthorn not_verified | 65 (1.7%, 1.3 to 2.2) | 44 (2.3%, 1.7 to 3.1) |
| GuardDog threat | 763 (19.9%, 18.7 to 21.2) | 593 (31.4%, 29.3 to 33.5) |
| GuardDog any rule | 2,659 (69.4%, 67.9 to 70.8) | 1,440 (76.2%, 74.3 to 78.1) |
| Projects with a Buckthorn flag | 176 of 1,999 (8.8%, 7.6 to 10.1) | 54 of 1,000 (5.4%, 4.2 to 7.0) |
| Projects with a GuardDog threat | 493 (24.7%, 22.8 to 26.6) | 350 (35.0%, 32.1 to 38.0) |

- Both strata together: Buckthorn 308 of 5,723 files (5.4%, 4.8 to 6.0),
  not_verified 109 (1.9%, 1.6 to 2.3); GuardDog threat 1,356 (23.7%, 22.6 to
  24.8). On the tuning top 1,000: Buckthorn 6.9%, GuardDog threat 24.2%.
- sdists are noisier than wheels: B1 8.0% against 4.1%, B2 4.8% against 3.3%.
- No Buckthorn errors or timeouts. GuardDog failed on 19 files (13 B1, 6 B2),
  counted as not flagged. 5 Buckthorn flags are on integrity rules only.
- Most frequent Buckthorn rules, B1: `BKT-INSTALL-002` 79, `BKT-IMPORT-002`
  73, `BKT-SKIP-002` 36, `BKT-IMPORT-001` 34. B2: `BKT-SKIP-003` 33,
  `BKT-IMPORT-002` 30, `BKT-INSTALL-002` 22.
- The not_verified files were not triaged.

## Triage: 50 malicious misses

Drawn at random (seed 20261114) from the 205 archives not flagged; all 50 are
`clean`. Read from call locations and a redacted view inside the container
(strings replaced by their length). Per-sample reasons:
`triage-malicious-misses.csv`.

| Why missed | Misses |
|---|---|
| Payload runs only when the user calls it (out of scope) | 39 |
| No payload in the sample (placeholders, a probe) | 7 |
| Payload in a dependency | 2 |
| Payload in native code | 1 |
| In-scope rule gap | 1 |

- **The out-of-scope misses are a few templates seen many times.** Seven
  near-identical "loader" packages whose `fetch(url)` downloads code and
  `exec`s it; eight whose `run(url)` downloads a script and runs it in a child
  Python; four AI-themed packages (5 archives; text to speech, VoxCPM) where
  `harness.run()` fetches native binaries and starts a miner; a trojanised
  pyjstat (5 of the 50) that collects files when `uniquify()` runs during
  normal use.
- **The one in-scope miss:** claudeopusfile 0.1.1. `setup.py` calls
  `compat._ensure_compat()` at install, which runs zlib and base85 decoded
  code through `getattr(builtins, _RUN)`, where `_RUN` is `"exec"` built from
  `chr()` codes into a module-level variable. `BKT-HIDE-001` matches a name
  built inline in the `getattr` call, not one held in a variable.
- zyto ships `Helper.exe` inside its sdist; no rule checks binaries in sdists
  (gap G8 in `../datadog-malicious/RESULTS.md`), but its code is also
  call-only.

So the gap to GuardDog is mostly scope, not rule quality: GuardDog matches a
download-and-exec anywhere in the code, Buckthorn only where it runs early.
39 of 50 is 78% (64.8 to 87.2). Applied to the 205 misses, that is an
estimated 160 call-only payloads.

## Triage: 50 benign flags

Drawn at random (seed 20261113) from the 308 flagged files, 38 from B1 and
12 from B2. Each finding was read with its lines on the Azure VM, long
strings replaced. Per-file notes: `triage-benign-flags.csv`.

- **42 real behaviour:** build tools and compilers at install (pycurl,
  rasterio, uamqp, iai_pme's npm build), git or GPU probes at import
  (optree, quack, bitsandbytes), update checks over the network at import
  (albumentations, autotimm), `.pth` files (pip_system_certs), example and
  test code shipped inside packages (Airflow's example DAGs, pymol). One
  wheel (jabs-behavior-classifier) really does fail 265 of 266 RECORD hashes.
- **8 false alarms,** 16% (8.3 to 28.5). Six are setup.py code pip never
  runs: custom `publish`, `clean`, `test` and `lint` commands, an
  `argv[-1] == "publish"` branch, and a function whose only call is commented
  out. One is a file pip installs but nothing can import (pycasbin ships a
  `node_modules` tree). One is flake8-bugbear's `getattr(builtins, name, type)`
  used for an exception check, reported as high-severity hidden code.
- **None malicious,** B2 included.

## Bugs and gaps found (not fixed)

1. **A builtin name held in a variable** is not followed by `BKT-HIDE-001`:
   `getattr(builtins, _RUN)(...)` with `_RUN` built from `chr()` codes at
   module level. claudeopusfile runs decoded code at install this way and is
   clean.
2. **Every setup.py command counts as install code.** `Command.run` of a
   `publish`, `clean`, `test` or `lint` command, and a setup.py function
   that is never called, are reported as running at install. Five of the 8
   false alarms, plus a sixth gated on `sys.argv`.
3. **Unimportable folders are read as package code** when egg-info
   `top_level.txt` names their root: pycasbin's
   `node_modules/npm/node_modules/node-gyp/gyp/gyp_main.py` has no
   `__init__.py` on its path and a hyphenated folder.
4. **`BKT-HIDE-001` fires on a type lookup:** `getattr(builtins,
   name.removeprefix("builtins."), type)` in flake8-bugbear, high severity.
5. **Known gap seen again:** binaries inside sdists are not checked (zyto
   ships `Helper.exe`).

The main miss is not a bug: payloads that run only when called are outside
what Buckthorn reads.

## Deviations from the protocol

- **The B2 walk crashed once** on a cut-short PyPI JSON response, after
  about 340 files. The script was changed to retry such responses, to record
  a failed fetch as a skip, and to keep the walk's start time and index on a
  restart. The walk was then run again from the start, with a fresh index
  fetch (sha256 `7d3884bd...598a`) and start time 2026-11-12 21:07:35 UTC.
  Files from the crashed walk were set aside and not scanned. B1 files were
  reused; each had passed PyPI's sha256.
- The sha256 check of benign files against the tuning set was run after
  download, against every file in the tuning benign volume, not only during
  download. 0 matches.
- Three B1 projects (mistralai, num2words, lightning) have OSV MAL reports
  for older, compromised versions. The versions scanned (3.7.0, 0.5.14,
  2.6.6) are not in those reports, and the protocol excludes OSV names from
  B2 only, so they stay in B1.
- No malicious archive needed renaming, so that step never ran.
- The malicious scans shared the mini with another agent's container. That
  costs time, not results.

## Files

- `PROTOCOL.md`: the pre-registration.
- `lists/`: candidates with exclusion and family reasons
  (`malicious-candidates.jsonl`), scan lists, benign manifest with sha256 and
  URL per file, skipped projects, the B2 walk record, tuning benign names.
- `results/`: per-sample results, gzipped JSON lines. Buckthorn: verdict, rule
  ids, severities, files and lines. GuardDog: rule hit counts. No matched text.
- `triage-*.csv`: the two hand triages.
- `scripts/`: every step; `summarize.py` makes the tables:

```bash
python3 scripts/summarize.py malicious results/malicious-buckthorn.jsonl.gz \
  results/malicious-guarddog.jsonl.gz lists/malicious-candidates.jsonl
gzip -dc lists/benign-manifest.jsonl.gz > /tmp/m.jsonl
python3 scripts/summarize.py benign results/benign-buckthorn.jsonl.gz \
  results/benign-guarddog.jsonl.gz /tmp/m.jsonl
```
