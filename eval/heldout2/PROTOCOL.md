# Held-out test 2: protocol

Written before any call-time combination rule exists. The commit time of
this file is the proof: every malicious sample in this test reached a public
dataset after it, so no rule can have been tuned on it.

Held-out test 1 is spent. This is a new, one-shot test of the call-time
combination rules (and of today's rules, for comparison).

## What is tested

- **Buckthorn, frozen.** One commit, chosen once: the tip of the combination
  rules branch when that work is handed over. Its hash goes into
  `eval/heldout2/FROZEN.md` and is committed before any held-out-2 file is
  fetched or scanned. Nothing in `buckthorn/` changes after that for this test.
- Two modes of that commit on the same files: call-time combination rules on,
  and off (today's rules).
- **GuardDog 3.2.0** on the same files, run as in `eval/guarddog/`: offline,
  so only its source-code rules. `threat-*` rules and any rule are both
  reported.

## Malicious set

- PyPI archives first added to one of these open datasets after this file's
  commit time:
  - pypi_malregistry (`lxyeternal/pypi_malregistry` on GitHub)
  - DataDog `malicious-software-packages-dataset`, `samples/pypi`
- "First added" is the committer date of the dataset commit that first adds
  the file (`git log --diff-filter=A`), not a date in the file name.
- Deduplicated by sha256 of the archive, then by (normalised name, version),
  against every earlier corpus: `bkt-malreg`, `bkt-malcorpus` and
  held-out set 1 (`heldout-malreg`). For those, only names and hashes are
  read, never contents or results.
- DataDog samples are rebuilt into a wheel or sdist by
  `eval/datadog-malicious/scripts/run_corpus.py`, as before. Empty samples
  are left out and counted.
- pypi_malregistry wheels stored under a `.tar.gz` name are scanned as
  stored and again under their right name (`rename_scan.py`), both reported.

## Benign set

Fetched once, on the day of the run, by `fetch_benign.py`'s rule: each
project's newest sdist plus one wheel (pure first, then CPython 3.12
manylinux x86_64), sha256-checked.

- **Popular:** PyPI ranks 3,001 to 5,000 in the first
  `hugovk/top-pypi-packages` 30-day snapshot published after this commit.
- **Recent:** 500 projects from PyPI's simple index, drawn in a shuffled
  order seeded with the first 8 hex digits of this file's commit hash (as an
  integer, Python `random.Random`), keeping each project whose newest release
  was uploaded in the 90 days before the fetch.
- Left out, by name: the top 3,000 of that snapshot, every project in the
  tuning benign set (`bkt-benign`) and in held-out set 1's benign set, and
  every name in either malware dataset.
- A recent project can be malware nobody has reported yet. After scoring,
  every flagged benign file is checked once, 30 days after the fetch, against
  OSV `MAL-` advisories and whether PyPI still serves it. Projects that fail
  that check move out of the benign set for every tool, and are listed.

## Metrics

- Per tool and mode: files flagged out of files scanned, for each set, with
  a Wilson 95% interval. Benign also per project (flagged if any file is).
- Buckthorn `not_verified` is reported apart, and as "flagged or
  not_verified" (both fail a build).
- Archives no tool can open are listed and left out of the rates.

## When it runs

- Counting qualifying malicious archives is allowed at any time. Scanning,
  triaging or reading them is not, until the run.
- The run happens once, when 100 or more malicious archives qualify. If
  that has not happened by 2027-05-13, it runs with what there is, and the
  intervals show the cost.
- One shot. Results are committed as they come out. No rule changes after
  the run count for this test; a later change needs a new held-out set.
- Malware is read only on the Mac mini, in containers with `--network none
  --read-only --cap-drop all --security-opt no-new-privileges`.
