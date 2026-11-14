# pypi_malregistry: second malicious corpus

Run 2026-11-05 and 2026-11-06. A working note from tuning: the counts here
are for triage. The headline numbers are in `../heldout/RESULTS.md`.

## Why this corpus

`SPEC.md` names the Backstabber's Knife Collection as the second corpus. Its
original repository (`cybertier/Backstabbers-Knife-Collection`) now returns
404, and the only copy found is an unofficial mirror whose provenance could
not be checked, so it was not used. `lxyeternal/pypi_malregistry` (the ASE
2023 paper "An Empirical Study of Malicious Code In PyPI Ecosystem") is used
instead. It is a better second corpus in two ways: it stores the **original
archives**, not unpacked trees, and its samples come from a different
detection pipeline than DataDog's (mostly GuardDog). Its README says every
sample was checked by hand.

## What was scanned

- Commit `5f2592d`: 10,606 packages, 12,170 archives (11,934 sdists, 200
  wheels, 36 zips). Cloned into a Podman volume on the Mac mini; scanned in a
  container with `--network none` and the corpus read-only
  (`../datadog-malicious/scripts/scan_files.py`).
- 478 archives would not open: 476 are wheels stored under a `.tar.gz` name,
  2 are truncated. The 476 were rescanned under the right name, chosen by
  their zip magic bytes (`scripts/rename_scan.py`).
- Final build: `312d9a2`. Per-archive results: `results-final.jsonl`.

## Results

| | Archives |
|---|---|
| `flagged` | 11,083 |
| ... of which only by integrity rules | 71 |
| `clean` | 1,003 |
| `not_verified` | 82 |
| Unreadable (truncated) | 2 |

Rules that fired most (archives with at least one): `BKT-INSTALL-002` 7,844,
`BKT-HIDE-001` 1,610, `BKT-INSTALL-001` 1,394, `BKT-IMPORT-001` 1,067,
`BKT-IMPORT-002` 915, `BKT-INSTALL-003` 858, `BKT-HIDE-002` 391.

## What it taught, and the fix

The first pass on this corpus left 2,004 archives clean or flagged only on
integrity. **928 of them are one 2022 campaign** (also present in DataDog as
`python3-flask` and friends). Its setup.py runs pip from install code to pull
in `pypiwin32`, then uses Windows shell automation to plant a browser
extension or rewire Start Menu shortcuts. Most variants build every string
through `getattr(__builtins__, <name assembled from oct/hex/copyright
slices>)`.

Two general rules, now in the scanner:

- `pip.main`, `pip._internal.main` and `pip._internal.cli.main.main` run a
  process (`BKT-*-002`).
- `getattr(builtins or __builtins__, <name assembled in place>)` is hidden
  code (`BKT-HIDE-001`). A first version flagged any non-constant name and
  newly flagged 14 benign files (numpy, pandas, pytest, typing_extensions:
  introspection with a plain variable), so it was narrowed to names built
  inline (concatenation, a call such as `''.join`, an index, an f-string).

Effect: all 928 campaign samples are flagged; on DataDog, 10 more samples of
the same campaign; on the top 1,000 PyPI packages, no new flag.

## The 1,074 still not flagged

From each archive's syntax tree (`scripts/triage_archives.py`), by where any
risky call sits. Representatives of each group were read.

| Where | Archives | What it means |
|---|---|---|
| Only inside functions nothing calls early | 640 | Runs when the user calls it or runs a command. Out of scope for install, import and start-up rules |
| No risky Python calls | 151 | Placeholders, probes, payload in a dependency or outside the sample |
| Calls at module top level | 139 | Mostly calls no rule lists (`ctypes.CDLL`, base64, getpass), with the payload in functions (aiostreams: a full stealer, never called at import) |
| setup.py calls | 57 | Calls no rule lists, or helpers reached by `__import__` with built names |
| Reached through a same-file function | 55 | Calls no rule lists, or code in folders without `__init__.py` |
| Only under `if __name__ == "__main__":` | 28 | Runs as a script only |
| No Python | 4 | |

145 payload files sit in folders without `__init__.py` (namespace-style or
plain script folders, for example dual-use reverse-shell tools), which sdist
package reading does not cover. That limit is in `docs/rules.md`.

## Caveats

- Counts are of archives. Many are versions of one package or one campaign.
- The two corpora overlap (the 2022 campaign is in both); no de-duplication
  was done.
- The corpus is from 2023 and earlier; it says nothing about newer
  techniques.
