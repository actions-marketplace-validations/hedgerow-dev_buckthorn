# npm phase 2: the tokenizer on the benign top 1,000

Internal. Not for publication. One run on 2026-11-12, repeated once after
review fixes with the same counts. Code from this branch (`buckthorn/js.py`).

## Short version

- **25,015 of 25,022 JavaScript files tokenize.** The 7 that do not are all
  React JSX source in one package, and they fail closed as designed.
- **No limit was hit.** Largest file 1.8 MB (limit 5 MB), most tokens 439,639
  (limit 2,000,000), deepest brackets 89 (limit 1,000).
- **About 2.7 MB/s** on one core of a Standard_D4s_v5. The slowest file took
  0.83 s.
- **Verdicts unchanged:** no package with JavaScript came out clean.

## How it was run

- List: `npm-high-impact` 1.13.0 `lib/top.js` (MIT), first 1,000 names in its
  order (most downloaded first). sha256 of the list file:
  `bbc16e783283f23d38559a1322d93af27b8a7a884b1fa9c5a1dd84e810684f0c`.
- Latest version of each from `registry.npmjs.org`, sha512 `integrity`
  checked, held in a scratch file only while `read_archive` read it into
  memory, then deleted. Nothing unpacked, nothing run; the VM had no Node or
  npm.
- Machine: Azure VM `vm-heldout2` (Standard_D4s_v5, Ubuntu 24.04, Python
  3.12), which was idle (load 0.14, no user
  processes). Work went in `~/bkt-npm-phase2`, deleted afterwards. No Azure
  resources were created or changed.
- `scripts/run_top.py` tokenizes every `.js`, `.mjs` and `.cjs` the way
  `buckthorn scan` does (`.mjs` as a module, `.cjs` as a script, `.js` as
  either), and runs `scan_artifact` on the whole tarball. Results keep paths,
  sizes, counts and times only. `scripts/agg_top.py` summarises.

## Results

- Packages: 1,000 fetched, 1,000 passed integrity. 945 ship JavaScript.
- Files: 25,022 (22,031 `.js`, 2,010 `.cjs`, 981 `.mjs`).
- Tokenized: 25,015. Failed: 7, all `unterminated-regex`, all in
  `istanbul-reports` 3.2.0 under `lib/html-spa/src/`: `fileBreadcrumbs.js`,
  `filterToggle.js`, `flattenToggle.js`, `index.js`, `summaryHeader.js`,
  `summaryTableHeader.js`, `summaryTableLine.js`. Each one holds JSX closing
  tags and imports React. The 2 files in that folder with no JSX tokenize.
- No `html-comment` failures: no `.js` file in the set uses `<!--` or a
  line-start `-->` outside strings, regexes, templates and comments.
- Sizes: median file 784 bytes, p99 78,618, max 1,814,568 (prettier).
  JavaScript per package: median 10,447 bytes, max 12,590,709 (webpack, 846
  files). Most files in one package: 3,729.
- Time: median 0.3 ms per file, p99 33 ms, max 0.83 s (`jiti`
  `dist/babel.cjs`, 1.5 MB). All 143 MB of tokenized JavaScript took 53 s.
  Whole-package `scan_artifact`: median 0.01 s, max 4.1 s.
- Findings: 919 packages have coverage notes only, 81 have other rules (the
  phase 1 package.json rules). None is clean while shipping JavaScript. The
  scan's per-file notes (7) match the direct tokenizer failures (7).

## Limits, and why

- 5 MB per file (as for a Python file), 2,000,000 tokens, 1,000 brackets
  deep, 32 MB of JavaScript per package (new after review, so one tarball
  cannot make a scan tokenize its full 512 MB). The benign set is far below
  each.
- Each limit is a `BKT-SKIP-003`. So is any tokenizer error, text that is not
  UTF-8, and `<!--` or a line-start `-->` in a `.js` file: Node may run a
  `.js` as a script (a comment) or a module (code), so neither reading is
  trusted.

## What to fix or know before phase 3

- **JSX** is not read. Fine for published `.js`; revisit only if `.jsx`
  files are ever scanned.
- **Module or script for a `.js` file** is undecided on purpose. Phase 3
  should use the nearest `package.json` `"type"` and Node's syntax detection
  (a `.js` with top-level `import` or `export` runs as a module), and only
  then relax the `html-comment` fail-closed.
- **Regex or division is a heuristic.** It follows the previous token, the
  bracket that `)` and `}` close (an `if (...)` or a block ends a statement,
  a function expression's body does not), and pending `?` for a `:`. Known
  gaps: a class expression's `}` and a ternary branch `{...}` followed by a
  slash. A wrong guess can hide code inside a fake regex or string. Phase 3
  should treat an odd token stream (a regex where a call is expected, a
  file that only tokenizes one way) as a reason to fail closed, and the
  tree-sitter decision in phase 5 should look at misses from this.
- **Depth is a plain bracket count.** Top level is depth 0, but phase 3 must
  tell a function body from an `if` block or an IIFE itself, for example from
  the tokens before each `{`.
- **`calls()` is a helper, not a rule.** It finds `f()`, `a.b()`,
  `a["b"]()`, `require("x").y()`. It does not see indirect calls such as
  `(0, eval)(s)`, `f()()`, or a callee held in a variable. Phase 3 needs those
  for HIDE rules.
- Names, strings and template text are decoded (`eval` is `eval`), so
  rules can match values, not spellings.
