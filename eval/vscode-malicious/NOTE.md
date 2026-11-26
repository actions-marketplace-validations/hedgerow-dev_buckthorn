# VS Code extensions: the DataDog malicious samples

A working note, run 2026-11-25 with Buckthorn at `22ebb62`. A single run on
the samples we built against nothing else: read it as a shape, not a rate.

## What was scanned

- **Corpus:** `DataDog/malicious-software-packages-dataset` at `72c723be`,
  `samples/ide_extensions`: 122 `.vsix` files (as shipped, not rebuilt).
- **Where:** the Mac mini, in a `--network none`, read-only container. Nothing
  was unpacked on the host or run.

## Result

| Verdict | Samples |
|---|---|
| flagged | 32 |
| not_verified | 32 |
| clean | 58 |

Flags: a process at activation (21), network at activation (12), `eval` of
unread code (4), a Discord webhook (2), an uninstall script (1).
not_verified: mostly an `activate` the reader could not find (27).

## Why 58 came out clean

- **29: the code is there, but outside activation.** Reading every file
  finds network or process calls, but in command handlers, class methods or
  webviews, which activation reading does not reach.
- **23: nothing found even reading every file.** Seen in excerpts:
  `promisify(exec)` (the alias is not followed), a shipped `.bat` the
  extension runs, `javascript-obfuscator` output, and template code with no
  payload at all (an impersonation, malicious by name only).
- **6: no code runs.** Themes and an extension pack.

## Run 2: reading every file (tried, reverted)

Every JavaScript file read whole as code that runs when used, with network,
processes and reading the environment as notes and only credentials,
persistence, hidden code and the credentials-and-network pair as flags.

- **Malicious:** 39 flagged, 27 not_verified, 56 clean (from 32, 32, 58).
  Of the 7 new flags, 5 were `BKT-NPM-HIDE-001` on library code (bn.js,
  vue.js, a language server, webview bundles): flagged for the wrong reason.
- **Benign (8 popular extensions):** with the environment-and-network pair as
  critical, 5 of 8 flagged; with credentials only, GitLens still flagged
  (`.ssh` for commit signing) and Vim as before.

Network and processes are what extensions do, so reading more code without
a sharper signal moves little. The patch was not kept.

## Run 3: targeted checks

Added: `util.promisify(exec)` followed as `exec`, `javascript-obfuscator`
output anywhere (`BKT-VSX-HIDE-002`), and a shipped shell script the code
names (`BKT-VSX-RUN-001`), medium only for an extension that is otherwise a
theme. A `package.json` past the archive limit is a gap, not `META-001`.

| | Flagged | Not verified | Clean |
|---|---|---|---|
| Malicious, run 1 | 32 | 32 | 58 |
| Malicious, run 3 | 50 | 23 | 49 |
| Top 100 Open VSX, run 3 | 10 | 21 | 69 |

- **The top 100:** Open VSX search by download count on 2026-11-25, each
  `.vsix` kept only if its sha256 matched the registry's, scanned on the
  laptop (benign, nothing unpacked or run).
- **Benign flags (10):** real activation behaviour (a fetch, a process,
  `.ssh` for remote work, `Function` in a debugger), `eval('require')` in
  three webpack bundles and Vim's eval-mode bundle (`BKT-NPM-HIDE-001`), and
  one uninstall script.
- **Benign not_verified (21):** mostly a single JavaScript file too large for
  the tokenizer (11), and the 32 MB read limit (2).
- **Shipped scripts:** before the theme rule, 13 of the top 100 were flagged
  for one (language tools running their own scripts), so for anything but a
  theme it is a note.
