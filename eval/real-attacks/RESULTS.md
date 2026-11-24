# Real supply-chain takeovers: Shai-Hulud and 1,400 other hijacked releases

Run 2026-11-23 with Buckthorn at `d351bf0` (the 0.1.1 code). Unlike the
held-out run, no protocol was committed before this one: the sample lists
below are complete, and every sample fetched was scanned and counted.

## Answer first

- **Shai-Hulud: 790 of the 810 unseen releases are flagged.** Wave 2
  (November 2025) is 428 of 428. Wave 1 (September 2025) is 362 of 382. The 20
  others are early builds of the worm that ship `bundle.js` but have nothing
  that runs it: no install script names it.
- **Against the version before, the diff flags the attack itself.** For the
  747 Shai-Hulud releases with an earlier version on npm, 730 diffs are
  flagged, and every new finding is on the payload (`bundle.js`,
  `setup_bun.js`) or the install script that runs it. The other 17 are the
  same inert early builds.
- **Other takeovers are harder: 339 of 588 unseen releases are flagged.** Most
  misses are attacks that change no install, start-up or import code in the
  package itself (below). One was a real rule gap: `binding.gyp` command
  expansion, in 41 releases. Buckthorn already failed closed on them (not
  verified), and the fix made after this run flags all 41 (below). Those 41
  are tuning data now, not unseen.
- **The 29 hijacked PyPI releases are all flagged,** but they were tuning
  data, so they say less.

## What was scanned

- **Source.** DataDog's `malicious-software-packages-dataset`, commit in
  `lists/dataset-commit.txt`: every `samples/npm/compromised_lib` sample
  (1,448 releases of real packages taken over by an attacker) and every
  `samples/pypi/compromised_lib` sample (29). Each zip was checked against its
  git blob id. Lists are in `lists/`.
- **Shai-Hulud is picked by date and checked by payload.** Wave 1 is the 392
  samples dated 2025-09-14 to 2025-09-16, wave 2 the 448 dated 2025-11-24.
  Every wave 1 sample holds `bundle.js`; every wave 2 sample holds
  `setup_bun.js` and `bun_environment.js`. The dataset does not label them.
- **Unseen.** 50 npm samples were in the npm tuning draw (seed 20261111, see
  `eval/npm-phase1`), listed in `lists/npm-tuning-overlap.txt`. They are
  counted apart. The PyPI samples were all tuning data (`eval/datadog-malicious`).
- **Where.** The Mac mini container host. Each sample is an unpacked tree in an
  encrypted zip, rebuilt into a tarball on tmpfs inside a `--network none`,
  read-only container, scanned, then deleted (`scripts/run_mal.py`,
  `scripts/run_corpus.py`). Nothing was installed or run.
- **Diff.** For each npm sample, the highest earlier stable version was
  fetched from registry.npmjs.org and checked against its sha512
  (`scripts/fetch_prev.py`), then `buckthorn diff` logic ran offline
  (`scripts/diff_mal.py`). 93 unseen samples have no earlier version, or it
  could not be fetched or failed its hash; they have no diff.

## Results

Scan (unseen samples):

| | Releases | Flagged | Clean | Not verified |
|---|---|---|---|---|
| Shai-Hulud wave 2 | 428 | 428 | 0 | 0 |
| Shai-Hulud wave 1 | 382 | 362 | 19 | 1 |
| Other npm takeovers | 588 | 339 | 203 | 45 |

One other sample had no `package.json` to read. Tuning-set samples: 45 of 50
npm flagged, 29 of 29 PyPI flagged.

Diff against the version before (unseen, with an earlier version):

| | Diffed | Flagged | Clean | Not verified |
|---|---|---|---|---|
| Shai-Hulud wave 2 | 388 | 388 | 0 | 0 |
| Shai-Hulud wave 1 | 359 | 342 | 17 | 0 |
| Other npm takeovers | 557 | 279 | 225 | 53 |

## What the other misses are

For each of the 278 unseen diff misses, `scripts/changed.py` and
`scripts/manifest_diff.py` listed which files and `package.json` fields
changed from the version before (names only).

| Count | What changed | Campaigns | Meaning |
|---|---|---|---|
| 111 | Only a new registry dependency (`easy-day-js`) | 2026-06-17 | The payload is in the dependency, not this package. A lockfile check scans that dependency too; whether it is flagged was not measured here. |
| 67 | A new git or URL dependency (`@tanstack/setup` and others) | 2026-05 | `check package-lock.json` reports a git source as not verified, so the build fails closed. `scan` and `diff` of the package alone say nothing. |
| 41 | `binding.gyp` with `<!(...)` command expansion | 2026-06 | **A rule gap, fixed after this run.** npm runs node-gyp at install when `binding.gyp` is present, and gyp runs the command (`node index.js`). These were not verified, not clean, so a default build already failed. |
| 59 | Code in the package itself | 2024-12 to 2025-09 | Not triaged yet: load-time code a rule should catch, or code that only runs when called. |

## After the fix: gyp commands

The attack added a `binding.gyp` whose only job is `<!(node index.js >
/dev/null 2>&1 && echo stub.c)`. Buckthorn now reads the commands in a
package's `.gyp` and `.gypi` files when a native build runs, as install
commands: one that runs a file of the package is `BKT-NPM-SCRIPT-001`
(medium), and that file is read as install code.

The 608 other npm samples were scanned and diffed again with the fix
(`results/gyp/`, same container setup). On the 588 unseen:

| | Flagged before | Flagged after | Changed |
|---|---|---|---|
| Scan | 339 | 376 | 37 not verified to flagged |
| Diff | 279 | 320 | 41 not verified to flagged |

All 41 `binding.gyp` releases are flagged in the diff, each with the medium
finding on `binding.gyp`. No other verdict changed: nothing clean became
flagged and nothing flagged became clean. The fix was written knowing these
samples, so these are tuning numbers, not a held-out result.

## Limits

- **No protocol was committed first.** The lists are complete, so nothing was
  picked after seeing a result, but the run was not pre-registered.
- **Benign noise on unseen npm packages is not measured.** On the top 1,000 npm
  packages it was tuned on, 12 were flagged (`eval/npm-phase3/NOTE.md`).
- **Rebuilt tarballs.** The files are the attacker's, the archive is not the
  one npm served.
- **The PyPI flags are not traced to the payload.** There is no diff for them,
  so a flag may be on the package's normal code.
