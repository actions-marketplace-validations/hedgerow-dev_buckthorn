# Read-all variant on the held-out set: results

Run 2026-11-13. Exploratory,
outside the original protocol. Plan in `VARIANT-read-all.md`, committed as
`b2fcf3e` at 09:07:01 +0100, before any held-out scan with the variant. One
shot: nothing was changed after seeing results.

## Answer first

- **Reading all code catches most of what Buckthorn missed.** 375 of 430
  held-out malicious archives flagged, 87.2% (83.7 to 90.0), against 52.3%
  for the default and 68.6% for GuardDog's threat rules. It loses no
  archive the default caught.
- **Of the 50 triaged misses it now flags 40:** all 39 call-only payloads
  and the one in-scope rule gap. The 10 it still misses have no payload in
  the sample, a payload in a dependency, or a payload in native code.
- **The cost is too high to ship as is.** 2,535 of 5,723 benign files
  flagged, 44.3% (43.0 to 45.6), against 5.4% for the default and 23.7% for
  GuardDog threat. Every one of 30 triaged added flags is real behaviour used
  for a normal reason: a version check, a model download, a CLI running git.
- **Tests, docs and examples are not the problem.** Only 237 of the 2,227
  added benign flags come from those folders alone. Package code is.

My view: reading everything turns Buckthorn into a capability scanner, and
the same rules that are rare at install and import are everywhere at call
time. The catch rate says the payloads are there to find. The rules would
need to look for malicious combinations, not single calls.

## Malicious (430 archives, mini, volume `heldout-malreg`)

| | Variant | Default `c80b090` |
|---|---|---|
| **Flagged** | **375 (87.2%, 83.7 to 90.0)** | 225 (52.3%, 47.6 to 57.0) |
| not_verified | 1 (0.2%, 0.0 to 1.3) | 1 |
| Clean | 54 | 204 |
| Errors, timeouts | 0 | 0 |

- Added 150, lost 0. Rules on the added archives: `BKT-IMPORT-001`
  (network) 130, `BKT-IMPORT-002` (process) 72, `BKT-IMPORT-003` (exec) 28,
  `BKT-IMPORT-008` 15.
- **Against GuardDog threat (295, 68.6%, 64.1 to 72.8):** both 289, variant
  only 86, GuardDog only 6, neither 49. Either: 381 (88.6%, 85.3 to 91.3).
- OSV first report on or after 2026-11-03 (38): variant 34 (89.5%, 75.9 to
  95.8), default 25, GuardDog threat 30.

**The 50 triaged misses:**

| Why the default missed | Now flagged |
|---|---|
| Payload runs only when the user calls it | 39 of 39 |
| In-scope rule gap (claudeopusfile) | 1 of 1 |
| No payload in the sample | 0 of 7 |
| Payload in a dependency | 0 of 2 |
| Payload in native code | 0 of 1 |

## Benign (5,723 files, on an Azure VM)

| | B1: ranks 1,001 to 3,000 (3,834) | B2: random recent (1,889) |
|---|---|---|
| **Variant flagged** | **1,506 (39.3%, 37.7 to 40.8)** | **1,029 (54.5%, 52.2 to 56.7)** |
| Default flagged | 232 (6.1%, 5.3 to 6.9) | 76 (4.0%, 3.2 to 5.0) |
| GuardDog threat | 763 (19.9%, 18.7 to 21.2) | 593 (31.4%, 29.3 to 33.5) |
| Variant not_verified | 40 (1.0%, 0.8 to 1.4) | 19 (1.0%, 0.6 to 1.6) |
| Projects with a variant flag | 911 of 1,999 (45.6%, 43.4 to 47.8) | 580 of 1,000 (58.0%, 54.9 to 61.0) |
| Projects, default | 176 (8.8%, 7.6 to 10.1) | 54 (5.4%, 4.2 to 7.0) |
| sdists, variant | 875 of 1,903 (46.0%, 43.8 to 48.2) | 551 of 909 (60.6%, 57.4 to 63.7) |
| Wheels, variant | 631 of 1,931 (32.7%, 30.6 to 34.8) | 478 of 980 (48.8%, 45.7 to 51.9) |

- Both together: variant 2,535 (44.3%, 43.0 to 45.6), default 308 (5.4%),
  GuardDog threat 1,356 (23.7%, 22.6 to 24.8). Added 2,227, lost 0. No
  errors or timeouts.
- Against GuardDog threat: both 1,076, variant only 1,459, GuardDog only 280,
  neither 2,908.
- Rules on added flags: `BKT-IMPORT-002` 1,381, `BKT-IMPORT-001` 1,373,
  `BKT-IMPORT-003` 561, `BKT-IMPORT-008` (critical) 110, `BKT-IMPORT-004` 62.
- **Location (secondary):** 237 of the 2,227 added flags come only from
  files under `test`, `tests`, `testing`, `doc`, `docs`, `example` or
  `examples`. Leaving those out would still flag about 40% of benign files.

**Triage of 30 added flags** (seed 20261116, `variant-read-all/triage-benign-added.csv`):
30 real behaviour the rule describes, used for a normal reason. 0 false
alarms by file, 0 malicious. Typical: a CLI running git or ffmpeg, a
model or dataset download, a server version check, a test starting a
subprocess. Five of the 30 are flagged only in tests or examples. A few
single lines inside them are weak (`s.getsockname()` counted as network, a
`.zshenv` path added to a protect-list), but each of those files has other
real hits.

## Tuning numbers (before held-out, for context)

| Corpus | Files | Default flagged | Variant flagged |
|---|---|---|---|
| Top 1,000 PyPI (benign) | 1,875 | 129 | 915 |
| pypi_malregistry, no rename | 12,170 | 10,944 | 11,408 |
| DataDog | 2,532 | 2,148 | 2,288 |

No crash, error or timeout on any set, so the code was not changed.

## Bugs and gaps seen (not fixed)

- `socket.getsockname()` counts as network use. It only reads the local
  address (a free-port helper). Seen in torchrl, newrelic and olab_camera;
  it affects the default too, at import.
- Under the variant, files beside `setup.py` read whole are labelled
  `BKT-INSTALL-*` even for functions nothing calls at install, and files
  outside the package say "runs at import". Same severities, so verdicts
  are not affected.

## Deviations from the pre-registration

None.

## Files

- `VARIANT-read-all.md`: the pre-registration.
- `variant-read-all/results/`: per-sample variant results (rule ids,
  severities, files, lines; no matched text) and the comparison output.
- `variant-read-all/compare.py`: the tables. `tuning_counts.py`: the tuning
  counts. `heldout_readall.sh`: the held-out run. `show_lines.py`: prints
  the flagged lines for the triage draw, on the benign host only.
- Variant code: `88fcf87`, switch `BUCKTHORN_READ_ALL=1` in
  `buckthorn/scan.py`. Image `845f8643...ff27f` on the mini and the VM.
