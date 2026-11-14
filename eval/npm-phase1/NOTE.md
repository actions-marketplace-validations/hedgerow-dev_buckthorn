# npm phase 1: what package.json alone catches

A working note. Counts are from one run each, on 2026-11-11,
image `buckthorn-scan:npm-2` built from commit 0f6120b. Small samples: read
them as a shape, not a rate.

## Short version

- **Install scripts carry most of this sample.** 118 of 200 malicious
  samples are flagged from package.json alone, every one by
  `BKT-NPM-SCRIPT-001`.
- **Misses are code at require time, binaries, and dependencies.** 79 are
  `not_verified` (code not read yet), 3 are `clean`.
- **Benign noise is real install scripts.** 22 of 86 well-known packages are
  flagged, all by `BKT-NPM-SCRIPT-001` medium on a script that does run.

## Malicious: 200 DataDog npm samples

Seeded random draw (`scripts/fetch_mal.py`, seed 20261111) from dataset
commit 9c24607: 50 of 1,448 `compromised_lib` and 150 of 25,267
`malicious_intent`. Each zip was fetched from GitHub and checked against its
git blob id. The dataset stores unpacked trees, so each sample was rebuilt as
a `package/` tarball on tmpfs in a `--network none` container with no Node.
Results keep rule ids, severities, paths and script names only.

| | compromised_lib (50) | malicious_intent (150) |
|---|---|---|
| flagged | 42 | 76 |
| not_verified | 8 | 71 |
| clean | 0 | 3 |

What fired (samples with the rule above info):

- `BKT-NPM-SCRIPT-001`: 42 and 76. By script: compromised_lib 25
  `preinstall`, 17 `postinstall`; malicious_intent 55 `preinstall`, 25
  `postinstall`, 2 `install` (a sample can have more than one).
- `BKT-NPM-INSTALL-001` (a URL or download tool in the script): 0 and 16.
- `BKT-EXFIL-001`: 1, in a sample that also ships Python build files and so
  was read both ways (`BKT-SKIP-001`); not split by which reading found it.
- `BKT-NPM-BIN-001` and `BKT-NPM-META-001`: 0. META cannot be measured here:
  the tarball names were built from the dataset's own name and version.

What was missed (82):

- **73 with JavaScript, no install script** (8 compromised_lib, 65
  malicious_intent): payload presumably runs at `require` or from a `bin`.
  Phase 2 and 3 territory.
- **6 with only binaries** (`.exe`, `.node`, files with no extension) and
  `os`/`cpu` fields, the platform-package shape. A JS reader will not help;
  `BKT-BIN-002`-style checks might.
- **3 clean**: package.json only, no install script, no dependencies. Nothing
  in them runs. Placeholder or spam shape; not checked further.
- 49 of the 74 malicious_intent misses declare dependencies, 4 of them by URL
  or git. A malicious dependency is not followed in phase 1.

Coverage notes: 3 samples hit the 64 MB member limit (`BKT-SKIP-002`), so
they were read both ways with `BKT-SKIP-001`. Every sample had a
`BKT-SKIP-003` for unread code except package.json-only ones.

Correction while running: the first driver missed 30 samples stored under
`var/folders/.../package/`; the driver was fixed and all 200 re-run. The
counts above are from that re-run.

## Benign: 86 well-known npm packages

Latest version of each on 2026-11-11, fetched from `registry.npmjs.org` in a
separate container, sha512 integrity checked, nothing unpacked
(`scripts/fetch_benign_npm.py` has the list: native and install-script
packages such as esbuild, sharp, bcrypt, node-sass, plus common ones such as
lodash, react, express). All 86 fetched and passed integrity.

- **22 flagged, 64 not_verified, 0 clean.** not_verified is expected: the
  JavaScript is not read yet.
- All 22 flags are `BKT-NPM-SCRIPT-001` medium on a real install script:
  esbuild, node-sass, cpu-features, ssh2, re2, argon2, node-pty, keytar,
  deasync, @swc/core, core-js, puppeteer, cypress, es5-ext, @parcel/watcher,
  nx, @sentry/cli, @prisma/engines, lefthook, @scarf/scarf, yarn, pnpm.
- Info only (native build): bcrypt, sqlite3, canvas, bufferutil,
  utf-8-validate, leveldown, lmdb, msgpackr-extract. A first run (image
  `npm-1`) flagged 26; sqlite3, canvas (`prebuild-install -r napi`), lmdb and
  msgpackr-extract (`node-gyp-build-optional-packages`) moved to info after a
  small pattern change.
- No `BKT-NPM-BIN-001`, `BKT-NPM-META-001`, `BKT-NPM-INSTALL-001` or EXFIL
  hits. `npm` itself (bins npm, npx) is not flagged.
- 3 registry tarballs have a top folder other than `package/` (cpu-features,
  ssh2, @types/node). They are read as npm because any single top folder
  with a package.json counts.

## What this says

- package.json alone separates "runs at install" from "does not", and that
  covers a large share of this sample. It cannot tell a malicious
  `postinstall` from esbuild's: both are medium. That is the decision
  `npm approve-scripts` asks for, not a verdict.
- The next gain is require-time JavaScript (65 + 8 misses with JS here).
- Binary-only platform packages need their own check.
