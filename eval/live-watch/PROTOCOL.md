# Live watch: counting rules

Written before the run starts and not changed during it. If a rule turns out
wrong, the change and the reason go in a dated note at the end, and both
counts are reported.

## What runs

- **Seven days,** from the start time in `started.txt` on the host.
- **npm: every new version** in the registry's changes feed.
- **PyPI: 1 in 4 new releases, one file each.** A release is in the sample
  when the first byte of sha256(`normalized-name==version`) is divisible by
  4, so the sample is fixed before the run. The file is the sdist, else a
  `-none-any` wheel, else the first wheel by name, from the files the
  release had when first seen. Scanning every PyPI file needs more CPU than
  the mini has (dry run, 2026-11-23: 7.6 CPU-seconds per PyPI file, 1.7 per
  npm file).
- **One Buckthorn version for the whole week:** the source tarball (with its
  sha256) and image named in `started.txt`. Rule bugs found during the week
  become tests, but the fixed code is not deployed until the week ends.
- **Plain `scan` of each file,** the same reading `check` does for a lockfile.
  No diff against the version before.
- **Where:** the Mac mini. Files are fetched on the host and checked against
  the registry's hash (npm sha512, PyPI sha256). They are scanned in a
  `--network none`, read-only container, then deleted. A flagged file is
  kept in a quarantine folder for triage, because
  registries remove malware quickly. Nothing is unpacked on the host,
  installed or run.
- **Skipped and counted as skipped:** files over 50 MB, files whose hash does
  not match, versions gone before we fetched them, and files that still fail
  to fetch after tries 5 and 15 minutes later (a new npm tarball can 404 for
  minutes after it is published).

## Units

- **npm:** one version (one tarball).
- **PyPI:** one sampled release, through its one file.

## What is counted

- **Verdicts:** clean, flagged, not_verified, error, skipped, per ecosystem
  and per day.
- **Flag rate:** flagged / (clean + flagged + not_verified).
- **Lag:** publish time to scan time, median and 95th percentile, to show
  whether the run kept up.

## Triage

Each day, from the previous day's flags:

- every flag with a high finding, or a random 30 of them if there are more
  (seeded with the date), and
- a random 20 of the flags with only medium findings.

Each gets one label:

- **attack:** the code does something harmful at install or load (steals
  secrets, fetches and runs a payload, persists).
- **real behaviour:** the finding is true, but the code is not harmful (a
  real install script, a real network call).
- **rule bug:** the finding is wrong.
- **unclear:** cannot tell from the code.

The noise estimate is (real behaviour + rule bug) / sampled flags, applied to
all flags of that kind.

## Confirmed attack and speed

- **Our triage alone gives a suspected attack, not a confirmed one.**
- **Confirmed** means the registry removed the version or project, or a
  public report names it: an OSV `MAL-` entry, a GitHub advisory, or a
  security vendor's post.
- **Speed:** for each confirmed attack, the time from our flag to the first
  removal or public report. The host re-checks every flagged release each
  hour and logs when it disappears.

## What is published

Nothing during the week. Package names stay on the host and in the private
repo. A suspected attack is reported privately to npm or PyPI security only
after Kenneth approves. After the week: counts, rates and confirmed catches.
