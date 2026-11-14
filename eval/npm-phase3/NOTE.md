# npm phase 3: rules on the JavaScript that runs on its own

A working note. Counts are from single runs on 2026-11-12
(final code: commit 87e7563, image `buckthorn-scan:npm3-3`). Small samples:
read them as a shape, not a rate.

## Short version

- **Benign top 1,000: 977 clean, 12 flagged, 11 not_verified.** With phase
  2's code it was 0 clean, 3 flagged, 997 not_verified: any file beside
  package.json made a package not_verified, so the verdict said little.
- **All 12 benign flags were triaged as real behaviour** (listed per group
  below). Rule bugs found on the way were fixed, each with a test.
- **Malicious 200: 141 flagged (phase 1: 118).** compromised_lib 45 of 50,
  malicious_intent 96 of 150. The 23 new catches come from the load rules
  (17) and hidden code (6).
- **The cost: 47 malicious samples are `clean`**: 44 that phase 1 called
  not_verified, and the 3 it already called clean. Most never run anything on their own (spam,
  bin-only CLIs, payloads in functions the user must call). That is the
  "runs on its own" model working as designed, and its main residual risk.

## What counts as running

- **Install:** what `preinstall`, `install` and `postinstall` run: `node
  FILE`, `node -e`, preloads, files run by path or interpreter, `npm run`
  chains, and the `prebuild.test` file node-gyp-build requires. That file
  is read whole, as setup.py is; local files it loads are read at top level
  plus the functions it calls in them.
- **Load:** entry files (`main`, every `exports` target, else `index.js`)
  and the local files they load: top level, IIFEs, functions called by name
  (by scope), `o.m()`, constructors for `new`, callbacks to timers,
  promises, array and string methods and `addEventListener`, bundler module
  tables (esbuild `__commonJS`, webpack `__webpack_modules__`, bootstrap
  arguments), and functions other files call through exports.
- **Not read, and not blocking `clean`:** bin commands, files nothing loads,
  methods reached other ways, code that runs only when the user calls an
  export.
- **Fails closed (`BKT-SKIP-003`):** a running file that does not tokenize
  or is past a limit; a load named at run time or not shipped; a native
  addon (an entry, loaded, built from a shipped binding.gyp, or loaded by
  node-gyp-build at install); files that differ only in case; a type-less
  `.js` with HTML-like comments that also reads as a module; work caps
  (re-read budget, 256 bindings per name, `npm run` depth 32).

## How it was run

- **Benign:** npm-high-impact 1.13.0 `lib/top.js`, first 1,000 names (the
  same sha256 as phase 2). Latest version of each from registry.npmjs.org,
  sha512 integrity checked (1,000 of 1,000), kept in a scratch folder on the
  VM for the runs, never unpacked, never run. An Azure VM
  (Standard_D4s_v5, Ubuntu 24.04, no Node or npm), created for this run
  and deleted afterwards with its NIC, NSG, public IP and disk. Scripts: `fetch_top.py`, `scan_top.py`,
  `agg_top.py`, `reach_top.py`.
- **Malicious:** the 200 DataDog samples phase 1 used (50
  compromised_lib, 150 malicious_intent), in podman volume `bkt-npm-mal` on
  the mini. Images built from `git archive` of each commit (`npm3-1` to
  `npm3-3`), run with `--network none --read-only --cap-drop all
  --security-opt no-new-privileges`, samples rebuilt as tarballs on tmpfs,
  nothing run. Results keep rule ids, severities, paths and lines only.
  Scripts: `run_mal.py`, `agg_mal.py`, `why_mal.py`; `inspect_mal.py` and
  `line_mal.py` print structure only (strings masked, URLs and IPs
  redacted).
- **Reach check** (run before the review fixes): 945 of the 1,000 benign
  packages ship JavaScript; only 1 of them (`@openai/codex`, bin only) has
  nothing read. 16,231 of 25,021 shipped files are read as running.

## Rule group 1: INSTALL on the JavaScript install scripts run

Benign flags kept (real behaviour):

- esbuild `install.js`: `https.get` (falls back to downloading its binary
  from the registry) and `execFileSync`/`execSync` (checks the binary,
  falls back to `npm install`).
- pnpm `install.js`: `spawnSync`.

Fixed: esbuild's `const env = {...process.env, ...}` handed to `execSync`
read as a whole-environment read, which with the download made a critical.
A copy made for a child process no longer counts.

Malicious: every sample this group fires on was already flagged in phase 1
by `BKT-NPM-SCRIPT-001`; it adds what the script does. compromised_lib 41
samples (`INSTALL-002` in 32, `001` in 13, `003`, `004` and `008` in 9
each). malicious_intent 51 samples (`002` in 24, `008` in 9, `003` in 3,
`005` in 1; `001` in 62 counting package.json commands).

## Rule group 2: IMPORT on the code that runs at load

Benign flags kept (real behaviour):

- `IMPORT-002`: esbuild `lib/main.js` spawns its service at load when it is
  an internal worker thread; rollup `dist/native.js` spawns `node -p` for
  the process report header (musl detection); `@tailwindcss/oxide` runs
  `ldd --version` (musl detection); ts-node's exported `dist/bin.js` runs
  its CLI at load.
- `IMPORT-003`: core-js builds a `require` call with `Function`; bluebird
  generates code with `Function` and calls `eval` in `toFastProperties`;
  uglify-js runs its own source files with `Function`; rollup's
  `loadConfigFile` (reached because `exports` maps `./dist/*`).
- `IMPORT-006` (info): debug, jest-util, loose-envify, vitest.

Fixed: vite's `.npmrc` in a config deny list (a string in an object
literal is data); `@emnapi/runtime`'s `new Function()` feature test;
`@colors/colors`' `'X' in process.env` read as iteration; `export {}` at
the end of a file raised an error; bundled-dependency lookup was slow.

Malicious: compromised_lib 0; malicious_intent 21 samples, 17 of them new
(phase 1 not_verified).

## Rule group 3: HIDE

Benign flags kept (real by the rule's definition):

- es-module-lexer's `(0, eval)(s)` on import string literals, bundled in
  tsx (2 files), vite and `@vitest/mocker`: indirect eval of data.
- `@pkgr/core`: `require('u' + 'rl')`, a module name split up (to hide it
  from bundlers).

Fixed: `require('process')` read as hidden (6 packages: jiti, yaml,
jest-util, `@opentelemetry/resources`, google-logging-utils);
`globalThis[Symbol.for(...)]` through a local or renamed `Symbol` (jest);
`new globalThis.Function` read as indirect eval (typebox).

Malicious: compromised_lib 3 samples, all new; malicious_intent 4, 3 new.

## Rule group 4: EXFIL on JavaScript strings

No benign flags. Malicious: malicious_intent 7 samples (6 with install
rules too); none new, all already flagged in phase 1.

## Per-file coverage (replacing phase 1's blanket note)

The 11 benign not_verified: native addon packages and their loaders
(`@rollup/rollup-linux-x64-*`, `lightningcss` and its platform packages,
`sharp` and `@img/sharp-*`, `@tailwindcss/oxide-linux-x64-*`), and
prettier (modules loaded by a name built at run time).

Fixed on the way: type declarations reached through the package's own
name (`@smithy/core`, `@aws-sdk/core`, vitest, `@hookform/resolvers`);
TypeScript under a custom condition (zod, `@tanstack/*`); a `style`
condition's CSS (tailwindcss); an exported `.so` (`@img/sharp-libvips`).

## Final verdicts

| | clean | flagged | not_verified |
|---|---|---|---|
| Benign top 1,000, phase 2 code | 0 | 3 | 997 |
| Benign top 1,000, phase 3 | 977 | 12 | 11 |
| compromised_lib (50), phase 1 | 0 | 42 | 8 |
| compromised_lib (50), phase 3 | 3 | 45 | 2 |
| malicious_intent (150), phase 1 | 3 | 76 | 71 |
| malicious_intent (150), phase 3 | 44 | 96 | 10 |

Phase 1 to phase 3, malicious: 118 stayed flagged, 23 moved from
not_verified to flagged, 44 from not_verified to clean, 12 stayed
not_verified, 3 stayed clean. The benign "phase 2 code" row is from the
first run of this phase (install rules in, blanket note still on); its
flagged set is the same 3 install-script packages.

## Malicious misses, by why

Each sample not flagged, with every JavaScript file also read whole
(`why_mal.py`):

| Why | compromised_lib | malicious_intent |
|---|---|---|
| Flaggable code only in files nothing loads | 1 clean | 14 clean |
| Flaggable code only in functions run when called | 1 not_verified | 9 clean |
| Flaggable code only in bin commands | | 3 clean, 1 not_verified |
| Code runs, nothing these rules flag | 2 clean, 1 not_verified | 10 clean, 4 not_verified |
| Nothing runs, nothing flaggable | | 4 clean |
| No JavaScript (binaries, package.json only) | | 4 clean, 5 not_verified |

- All 14 malicious_intent "files nothing loads" are the IndonesianFoods
  spam shape: a Next.js app with an `auto.js` publisher and no entry or
  install script. Nothing runs on its own.
- The compromised_lib one names its install script `postInstall`; npm
  runs only `postinstall`, so its 3.7 MB bundle never runs at install.
- "Functions run when called" includes a Solana SDK whose network and
  environment reads run when its API is used, and an obfuscated stealer
  whose `eval` of a network response runs when its exported factory is
  called.
- "Code runs, nothing flagged" includes payload-free placeholders and
  libraries whose malicious part is in a dependency or not visible to
  these rules.

## Found in review and fixed

- /code-review: more call forms followed (alias, `(f)()`, `o.m()`,
  constructors, template tags, string callbacks, `addEventListener`); a
  regex after `for (x of` read as division let a fake comment hide code;
  `import.meta` and top-level `await` make a `.js` a module; names matched
  in any case; the entry read whatever its extension; inline `node -e`
  with network and environment crashed the scan; `npm run` recursion and
  fan-out; an exports pattern regex that backtracked; quadratic walks;
  a missing local `.node` was dropped silently.
- /security-review: a nested `package.json` `main` that Node never reads;
  other Node module triggers hiding code behind `<!--`; `node-gyp-build`
  at install loading package code unread. All three were reproduced by
  scanning and are fixed with tests.
- Malicious triage: `x =` at the end of a file raised an error (1 sample).

## Residual risks

- **Code that runs only when called** (exported functions, methods, CLI
  bins) is not read, so a package that steals on first use is `clean`.
  That is 14 samples here (11 clean, 3 not_verified for other reasons).
- **Following is heuristic.** Computed calls (`table[k]()`) beyond the
  bundler shapes, functions passed through variables or other modules'
  helpers, and class fields are not followed.
- **The tokenizer guesses regex or division** from the previous token. A
  wrong guess can still hide code; tree-sitter remains the phase 5 option.
- **node-pre-gyp and prebuild-install** fetch a binary at install that a
  later load runs. The load is a coverage note only when it names a local
  `.node`.
- **Fixed after this run:** es-module-lexer's `(0, eval)(s)` made vite, tsx
  and `@vitest/mocker` HIDE-001 high. `(0, eval)` is now read as plain
  `eval`: hidden only when its code is decoded, and exec when it runs.
- **Hostile input:** linear-time fixes cover the shapes review found; there
  is no overall time budget per file.
- Prettier takes about 21 s to scan on one core of a D4s_v5.
