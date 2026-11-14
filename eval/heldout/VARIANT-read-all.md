# Read-all variant on the held-out set: pre-registration

Written and committed before the variant scanned any held-out file. The
commit time of this file is the proof. Exploratory: this is **not part of the
original pre-registration** (`PROTOCOL.md`, `f3a5701`, on the held-out
branch `worktree-agent-a4dc4283e52b7ae9a`). Whatever the outcome, every
number below goes into `VARIANT-read-all-RESULTS.md`.

## Why

The held-out run found Buckthorn `c80b090` flags 225 of 430 unseen malicious
archives (52.3%). In 39 of 50 triaged misses the payload runs only when the
user calls a function, and Buckthorn reads only install, start-up and import
code. Question: what does reading all code buy in catches, and what does it
cost in benign flags?

## The variant

- Code: commit `88fcf87` (tree `0bca09e7175f69fa93d0deb9fdc970dc4b76c0eb`),
  `c80b090` plus the switch `BUCKTHORN_READ_ALL=1` in `buckthorn/scan.py`.
  Default behaviour is unchanged.
- With the switch on:
  - every Python file Buckthorn already reads is read whole, so every
    function body counts as code that runs;
  - an sdist's other Python files (tests, docs, examples, scripts) are read
    too, as import code;
  - files with no `.py` whose `#!` line runs Python are read, and wheel `.py`
    files that do not land in site-packages;
  - wheel test files are no longer lowered to info.
- Same rule ids, same severities. No rule was added or tuned.
- Image source: `git archive --format=tar 88fcf87`, sha256
  `94b4240ae9ff204e3ae11a07422cdf70723a75be3fea7e0ac258cc87e1baa71b`. Built on
  the Mac mini with `~/bkt-run/nt/Containerfile` (the steps of
  `../datadog-malicious/scripts/Containerfile`, source passed as a build
  argument; Python 3.12.16 and packaging 26.3, as in the original image) as
  `localhost/buckthorn-scan:readall-88fcf87-base` (id `535547a9...eacf9`),
  then one layer `ENV BUCKTHORN_READ_ALL=1` as
  `localhost/buckthorn-scan:readall-88fcf87`, id
  `845f8643bdbd7e960272af8c88ecb953e78e897d23df62e9c9a8c8576a6ff27f`. The
  benign host gets this image by `podman save` and `podman load`; its id is
  checked before scanning.

## Tuning numbers before held-out

Run 2026-11-13 on the Mac mini with the variant image, same drivers as
tuning (`scan_files.py`, `run_corpus.py`). No crash, error or timeout, so
nothing was changed. Default numbers are `c80b090`'s (`17cc527` code).

| Corpus | Files | Default flagged | Variant flagged | Variant not_verified |
|---|---|---|---|---|
| Top 1,000 PyPI (benign) | 1,875 | 129 | 915 | 12 |
| pypi_malregistry, no rename | 12,170 | 10,944 | 11,408 | 537 |
| DataDog | 2,532 | 2,148 | 2,288 | 15 |

On the benign set the variant adds 786 flags and loses none. Most added
flags come from `BKT-IMPORT-002` (process, 501 files), `BKT-IMPORT-001`
(network, 426) and `BKT-IMPORT-003` (exec, 283). Benign noise goes from
about 7% to about 49% of files before held-out is touched.

## Held-out files: the same as the original run

- **M:** the 430 archives in `lists/malicious-scan-list.txt` (sha256
  `fd595dfd...a8672`), volume `heldout-malreg` on the Mac mini.
- **B1:** PyPI ranks 1,001 to 3,000. **B2:** 1,000 random recently released
  projects. Files as in `lists/benign-scan-list.txt` and
  `lists/benign-manifest.jsonl.gz` at held-out commit `fa04d31`, from the
  cache on Azure VM `vm-bkt-heldout`.
- Same driver, unchanged: `scripts/scan_heldout.py` (sha256
  `ea50993b...b751f`), 4 workers, 900 s timeout per file, `--network none
  --read-only --cap-drop all --security-opt no-new-privileges`, tmpfs scratch.
  On the mini also `--cpus 3`. Malware on the mini only, benign on Azure only.
- Default and GuardDog results are the original run's, not rerun:
  `results/*-buckthorn.jsonl.gz` and `results/*-guarddog.jsonl.gz` at
  `fa04d31`.

## What will be reported

Counted as in `PROTOCOL.md`: caught means verdict `flagged`; `not_verified`,
errors and timeouts are not caught and are reported apart.

1. **M:** variant flagged, not_verified, clean, error, each with a Wilson 95%
   interval, next to the default (225/430) and GuardDog threat (295/430).
   Files the variant adds and loses against the default. Overlap with
   GuardDog threat (both, variant only, GuardDog only, neither) and "either".
   The same for the OSV-on-or-after-2026-11-03 split.
2. **The 50 triaged misses** (`triage-malicious-misses.csv`): how many the
   variant flags, per miss reason.
3. **B1 and B2, each and together:** the same rates with Wilson intervals,
   per file and per project, sdist and wheel apart, next to the default and
   GuardDog threat; files added and lost.
4. **Secondary (location):** of the benign files the variant adds, how many
   are flagged only by findings in files under a folder named `test`,
   `tests`, `testing`, `doc`, `docs`, `example` or `examples`.
5. **Triage of 30 added benign flags**, drawn with `random.Random(20261116)`
   from the files flagged by the variant and not by the default, B1 and B2
   together (all, if fewer): real behaviour the rule describes (benign
   use), false alarm (not there), or malicious.
6. Errors, timeouts and bugs, reported and not fixed.

`variant-read-all/compare.py` makes items 1 to 4 and the triage draw.

## One shot

The variant runs once on held-out. Nothing in the code, the rules, the
image or this plan changes after seeing any held-out result. A crash or bug
found on held-out is reported, not fixed and rerun.
