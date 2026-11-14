# Buckthorn and GuardDog on the same files

GuardDog run 2026-11-06. Buckthorn rerun 2026-11-12 at commit `17cc527`.
On the tuning sets. The comparison on unseen packages is in
`../heldout/RESULTS.md`.

## Setup

- **GuardDog 3.2.0** (DataDog, Apache-2.0), pinned, on the Mac mini in a
  container with `--network none`, `--read-only`, `--cap-drop all` and the
  corpus mounted read-only. Run as a separate program, not a dependency.
- **Same inputs as Buckthorn.** The benign and pypi_malregistry files are read
  as they are; each DataDog sample is rebuilt into an archive by
  `../datadog-malicious/scripts/run_corpus.py`, as for Buckthorn's run.
- **Buckthorn results** are from commit `17cc527`, all three corpora in one
  run on the Mac mini, same container limits: `buckthorn/benign.jsonl.gz`,
  `buckthorn/malreg.jsonl.gz`, `buckthorn/datadog.jsonl.gz`. As before, the 476
  pypi_malregistry wheels stored under `.tar.gz` names were rescanned under
  their right names (`../pypi-malregistry/scripts/rename_scan.py`).
- **What counts.** Buckthorn: verdict `flagged`. GuardDog has two rule levels,
  `threat-*` (its alarms) and `capability-*` (what the code can do); both are
  counted. Buckthorn's `not_verified` also fails a build, so it is shown apart.
- GuardDog was offline, so its metadata rules (typosquatting, maintainer
  email and so on) did not run. Only its source-code rules are compared.
- **Bias.** The DataDog set was mostly found by GuardDog, so it leans to what
  GuardDog detects. pypi_malregistry comes from a different pipeline.

## Results

| Corpus | Files | Buckthorn flagged | GuardDog threat | GuardDog any rule | Either |
|---|---|---|---|---|---|
| Top 1,000 PyPI (benign) | 1,875 | **129** | 453 | 1,437 | 511 |
| pypi_malregistry (malicious) | 12,170 | **11,338** | 10,167 | 11,069 | 11,739 |
| DataDog (malicious) | 2,532 | **2,148** | 2,102 | 2,376 | 2,285 |

Buckthorn `not_verified`: 24 benign, 81 pypi_malregistry, 27 DataDog.
DataDog has 28 empty samples, counted in neither tool. One pypi_malregistry
archive is truncated and could not be read.

Against the 2026-11-06 Buckthorn numbers (build `312d9a2`): 16 benign files
are newly flagged (11 by `BKT-IMPORT-002`) and 5 are now clean; no file
flagged then on either malicious set has lost its flag.

**Where they differ on the malicious sets:**

| | pypi_malregistry | DataDog |
|---|---|---|
| Buckthorn flagged, GuardDog no threat | 1,572 | 183 |
| GuardDog threat, Buckthorn clean | 333 | 114 |
| Both missed (Buckthorn clean, no GuardDog threat) | 417 | 215 |

## What it means

- **Less noise, similar or better catch.** On popular packages GuardDog's
  threat rules fire on about three and a half times as many files as
  Buckthorn flags. On the malicious sets Buckthorn flags more of
  pypi_malregistry and slightly more of DataDog, the set that leans to
  GuardDog.
- **The two catch different things.** Together they flag more than either
  alone, so each misses malware the other finds.
- **Buckthorn's misses that GuardDog catches** are mostly network exfiltration,
  shady links and download-and-run, matched anywhere in the code. Buckthorn
  reports only code that runs at install, start-up or import, so payloads in
  functions nothing calls early are out of its scope (see
  `../datadog-malicious/RESULTS.md`). This is the main gap to look at next.
- GuardDog's capability tags fire on most benign files (1,437 of 1,875), so
  they are context, not alarms.

## Files

- `benign.jsonl`, `malreg.jsonl`, `datadog.jsonl`: per sample, which GuardDog
  rules matched and how often. Matched code is not stored (samples hold live
  webhook URLs).
- `buckthorn/*.jsonl.gz`: Buckthorn's result per sample at `17cc527`.
- `scripts/gd_scan.py` runs GuardDog; `scripts/compare.py` makes the tables:

```bash
python3 scripts/compare.py benign buckthorn/benign.jsonl.gz benign.jsonl
```
