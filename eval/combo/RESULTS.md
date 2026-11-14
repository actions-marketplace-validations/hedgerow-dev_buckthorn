# Call-time combination rules: tuning results

Run 2026-11-13 on the Mac mini, Buckthorn at `7afa40f` with
`BUCKTHORN_CALL_TIME=1`, through the usual drivers (`scan_files.py`,
`run_corpus.py`) in `--network none --read-only --cap-drop all` containers.
Tuning corpora only. Held-out set 1 was not opened. Counts:
`scripts/final_counts.py`.

## The trade-off

Files flagged. "Today" is the same run with the BKT-CALL findings left out,
and it matches the earlier baseline exactly, so install and import rules are
unchanged. Read-all numbers are the read-all experiment's own tuning run
(`BUCKTHORN_READ_ALL=1`), not rerun here.

| Corpus | Files | Today | Read-all | Combination rules |
|---|---|---|---|---|
| Top 1,000 PyPI (benign) | 1,875 | 129 (6.9%) | 915 (48.8%) | **134 (7.1%)** |
| pypi_malregistry | 12,170 | 10,944 (89.9%) | 11,408 (93.7%) | **11,051 (90.8%)** |
| DataDog | 2,532 | 2,148 (84.8%) | 2,288 (90.4%) | **2,190 (86.5%)** |

So the rules keep benign noise close to today's (+5 files, read-all added
786) and get about a quarter of what read-all gains on the malicious sets:
107 of 464 on pypi_malregistry, 42 of 140 on DataDog.

Most of read-all's extra catch is single capabilities in called code (one
network call, one subprocess). Those are exactly what fires on normal
packages, so these rules leave them alone. That part of the gap is not
closable this way.

## Per rule

"Fires on" counts files with the finding. "Alone" counts files that nothing
else flags: not today's rules, no other BKT-CALL rule.

| Rule | Benign fires / alone | pypi_malregistry fires / alone | DataDog fires / alone |
|---|---|---|---|
| BKT-CALL-001 fetch and run | 8 / 4 | 150 / 75 | 32 / 13 |
| BKT-CALL-002 decode and run | 2 / 1 | 62 / 8 | 21 / 9 |
| BKT-CALL-003 start-up location and network | 0 / 0 | 89 / 10 | 10 / 1 |
| BKT-CALL-004 reverse shell | 0 / 0 | 18 / 3 | 5 / 1 |
| BKT-CALL-005 credentials and network | 0 / 0 | 1 / 0 | 17 / 10 |

The 5 new benign files: a client install test in datamodel-code-generator,
IPython's `find_user_code` (fetches a URL and evals), a vendored meson build
script in numpy's sdist, a replay test in PyGithub (base64 then eval), and an
SSH sandbox fixture in strands-agents' integration tests. Four of the five are
tests or build scripts in an sdist.

## What was tried and dropped

Measured in tuning run 2 (`scripts/units.py`, `scripts/analyse_units.py`, an
earlier build of the same units), then left out. Counts are files newly
flagged over today, benign / pypi_malregistry / DataDog:

- **Network plus a subprocess** in one unit: 56 / 158 / 54 (test servers,
  build scripts, CLI tools).
- **Reading the whole environment plus network**: 24 / 25 / 27 (API clients).
- **A credential path only named** (in `os.path.join`) **plus network**:
  7 / 13 / 19 (paramiko, pyzmq, smart_open, an httpx test). BKT-CALL-005
  counts only a path passed to a real read.
- **A detached process command plus network**: 0 / 24 / 11, but every one of
  those was caught by another rule already.
- **Hidden code (BKT-HIDE-001) in tests and scripts**: 1 / 3 / 1, and none
  that no rule here catches on the malicious sets.

## Known gaps

- Two pypi_malregistry archives (large cloud SDK lookalikes) timed out at 900
  seconds in this mode. Call-time mode parses each module a second time; the
  slow part on large packages is the existing import-following.
- Cheap rewrites dodge each rule: a credential path held in a variable before
  `open`, `fd = s.fileno()` before `dup2`, `curl -o x && sh x`, a dropper
  using `NamedTemporaryFile` or writing and running in two functions, calls
  through a variable or across modules. The rules catch plain payloads, not
  evasive ones.
- Test files count here even where the import rules treat them as info.

## Held-out test 2

Pre-registered in `eval/heldout2/PROTOCOL.md` (commit `999817c`, 2026-11-13
11:35 +0100). On 2026-11-14 neither dataset has a commit after that time
(newest: pypi_malregistry 2026-11-11, DataDog 2026-11-05), so 0 malicious
archives qualify. Not run.
