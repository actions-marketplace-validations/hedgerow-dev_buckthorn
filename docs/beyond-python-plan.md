# Buckthorn beyond Python: plan

Status: draft for review, 2026-11-11. Planning only, no code changed.

## Answer

- **Next ecosystem: npm.** It has by far the most real malware, the largest labelled corpus we can run offline, and most of Buckthorn's machinery carries over (tarball reading, lockfile fetch-and-hash, verdicts, exfil patterns, diff).
- **Then VS Code extensions**, which reuse the JavaScript reader built for npm.
- **One tool, per-ecosystem modules, no new runtime dependency.** Read JavaScript with a small stdlib tokenizer of our own; keep tree-sitter as a fallback decided by data.
- **Main shift for npm:** package managers now block install scripts by default, so the value is in **require-time code** and in answering "should I approve this script?".

## 1. Which ecosystem next

OSV malicious-package reports are from the OpenSSF stats file (all.csv, updated 2026-11-11) [1]. "Recent" is Dec 2025 to Oct 2026.

| Ecosystem | What runs on its own | OSV MAL reports, total / recent | Labelled corpus | Others covering it | Carry-over |
|---|---|---|---|---|---|
| **npm** | `preinstall`/`install`/`postinstall`, implicit `node-gyp rebuild` [2]; module top level at `require`; `bin` shims | 223,197 / 14,577 | DataDog: 48,600 npm names [3] | GuardDog, Socket, Veracode (Phylum) [4], OSV-Scanner (known only) | High |
| VS Code ext. | extension JS on activation events such as `*` or `onStartupFinished` [5] | 21 / 7 (incl. Open VSX) | DataDog: 103 [3] | GuardDog | High once JS reader exists |
| RubyGems | `extconf.rb` at `gem install`; `require` top level | 4,316 / 3,402 (bursty) | small | GuardDog | Medium, needs a Ruby reader |
| GitHub Actions | action code in CI with secrets | not an OSV MAL ecosystem | none found | GuardDog; zizmor (workflow config) | Medium for JS actions |
| crates.io | `build.rs`, proc macros at build [6] | 23 / 18 | none found | GuardDog | Low, needs a Rust reader |
| NuGet | MSBuild `.props`/`.targets` at build | 782 / 36 | none found | few | Low |
| Go | nothing: "neither fetching nor building code will let that code execute" [7] | 20 / 10 | none found | GuardDog | Low value |
| Maven/Gradle | build plugins, annotation processors | 2 / 0 | none found | few | Low |

Notes that change the reading:

- **npm counts include spam.** The Nov 2025 spike (142,163 reports) matches the IndonesianFoods token-farming flood, over 150,000 packages per Amazon Inspector [8]. Quiet months still dwarf PyPI (Oct 2026: 1,093 npm, 180 PyPI [1]).
- **Real attacks:** Shai-Hulud worm, 500+ packages, CISA alert 2025-09-23 [9]; chalk/debug takeover, 18 packages, payload in package code, not an install hook [10].
- **Install scripts are now opt-in:** npm 12 (released 2026-07-08) skips dependency install scripts, `node-gyp` and git `prepare` unless approved [11]; so do pnpm 10 [12], Bun [13] and current Yarn [14]. Older npm in CI still runs them.
- **So the gap is require-time code**, which no package manager blocks, plus the `npm approve-scripts` decision. That is Buckthorn's import-time model.
- **Competitors:** GuardDog flags any install script [15]; Socket and Veracode are commercial; OSV-Scanner and `npm audit` match known advisories only. Buckthorn's edge: offline, fail-closed, hash-checked, says what runs and when.

## 2. Architecture

- **One tool, one package.** `buckthorn scan pkg-1.2.3.tgz` detects an npm tarball (a `package/package.json`, no `PKG-INFO`). New files: `buckthorn/npm.py` (reader and rules) and `buckthorn/js.py` (tokenizer). No plugin framework or base class; revisit at the third ecosystem.
- **Shared, unchanged:** `Finding` and `verdict()`; `read_archive` limits; reports, allowlist, receipts; `fetch_url` with a per-ecosystem host allowlist (`registry.npmjs.org` for npm); MCP server; Action.
- **Rule ids:** Python ids stay as they are (stable within a major version). Ecosystem rules get `BKT-NPM-<GROUP>-NNN`. Ids whose meaning is identical are reused: `BKT-SKIP-*`, `BKT-LOCK-*`, `BKT-EXFIL-*`, `BKT-BIN-002`. Allowlist entries gain an optional `ecosystem` key, since a name can exist on both registries.
- **Reading JavaScript:**

| Option | Licence | Maintenance (PyPI, checked 2026-11-11) | Verdict |
|---|---|---|---|
| Own tokenizer (stdlib) | MIT (ours) | ours | **Start here.** Tokens plus brace depth give top level, calls and string literals. No new dependency. |
| tree-sitter 0.26.1 + tree-sitter-javascript 0.25.0 | MIT, MIT | active (2026-11-09; 2025-09-01) | **Fallback.** Full modern grammar, but two native-code deps parsing hostile input in-process. Only as an optional extra, only if phase 5 shows tokenizer scope errors cause misses. |
| esprima (Python port) 4.0.1 | BSD | last release 2018-08-24 | No: stale. |
| pyjsparser 2.7.1 | MIT | last release 2019-04-21 | No: ES5.1. |
| calmjs.parse 1.3.4 | MIT | 2025-11-08 | No: "only ES5 support", needs `ply`. |

- **Tokenizer hard parts:** regex vs division, nested template literals, unicode escapes. Any tokenizer error or size limit is `BKT-SKIP-003`, so it fails closed.

## 3. npm: first rule set

What runs on its own, and how to read it:

| Rule | Severity | Reads |
|---|---|---|
| BKT-NPM-SCRIPT-001 | medium | `preinstall`/`install`/`postinstall` in the tarball's own `package.json`. `binding.gyp` with no script, or a bare known build command (`node-gyp rebuild`, `prebuild-install`), is info. |
| BKT-NPM-INSTALL-001..008 | as Python | Same meanings as `BKT-INSTALL-*`, on the script command (`curl`, `wget`, a URL) and on the whole JS file it runs (`node x.js`) plus local files that file `require`s. |
| BKT-NPM-IMPORT-001..008 | as Python | Top-level code of entry files (`main`, every `exports` target, else `index.js`) and of local files they `require` at top level, including IIFEs. |
| BKT-NPM-HIDE-001/002 | high/low | `eval`, `Function`, `vm.run*` or `require` of decoded data (`Buffer.from(.., 'base64')`, `atob`, `fromCharCode`, hex); long high-entropy literals into a decoder. |
| BKT-NPM-BIN-001 | high | A `bin` named `node`, `npm`, `npx`, `git`, `ssh`, `sh`, unless the package is that tool. |
| BKT-EXFIL-001/002 | medium | Reused on JS string literals. |
| BKT-NPM-META-001 | medium | `package.json` name or version differs from the tarball's pin. |
| BKT-NPM-META-002 | high | Registry manifest and tarball `package.json` disagree on install scripts ("manifest confusion" [16]). Network modes only. |

Diff mode needs no new rule: a new `BKT-NPM-SCRIPT-001` between versions is the Shai-Hulud shape.

Lockfiles, in order (all pin npm's sha512 `integrity`, checked before reading; sha1-only pins are `BKT-LOCK-002`):

1. `package-lock.json` v2/v3 and `npm-shrinkwrap.json`: stdlib `json`. Platform packages (`os`/`cpu`) follow the "this machine" default; `--all-files` reads all.
2. `yarn.lock` v1: small line parser.
3. `pnpm-lock.yaml` v9: line reader for the `packages:` shape only; anything else is `BKT-LOCK-002`. Avoids a YAML dependency.
4. Later: Yarn Berry (its `checksum` is believed to hash Yarn's own zip, not the tarball: verify before supporting) and `bun.lock`.

Evaluation corpora:

- **Malicious:** DataDog `malicious-software-packages-dataset`, `samples/npm`, Apache-2.0, encrypted zips [3]. Report `compromised_lib` (takeovers, the hard case) apart from `malicious_intent`, and spam with no code apart again. Biased towards what GuardDog finds, as for PyPI.
- **Labels only:** OpenSSF `malicious-packages` OSV reports, Apache-2.0 [1]. No code; npm replaces removed packages with security placeholders.
- **On request:** Backstabber's Knife Collection, 174 packages 2015 to 2019, about 63% npm, research terms [17].
- **Benign:** the top 1,000 from `npm-high-impact` (MIT list, v1.13.0) [18], fetched from `registry.npmjs.org` with integrity checked. It includes the hard benign cases (esbuild, sharp and other packages with install scripts).
- **Comparison:** GuardDog on the same files, as in `eval/guarddog/`.

Running them safely (an isolated container host only, never a workstation):

- Fetch step: a container that can reach only GitHub or `registry.npmjs.org`, writing into a podman volume. Nothing is unpacked there.
- Scan step: reuse `eval/datadog-malicious/scripts/Containerfile`: `--network none --read-only --cap-drop all --security-opt no-new-privileges`, non-root, corpus volume read-only, zips opened to tmpfs inside.
- The image has **no Node or npm**, so nothing can be run by accident. Results store rule ids and lines, never matched strings (live webhooks).

## 4. Phased plan

Phase 0, decide:

1. The maintainer approves this plan and the `BKT-NPM-` namespace -> verify: SPEC open question 3 marked decided, prefix listed in `docs/rules.md`.

Phase 1, `package.json` only (no JS reading):

2. Detect npm tarballs in `scan` -> verify: hand-made `.tgz` fixtures classify as npm, sdist fixtures unchanged, full test suite green.
3. SCRIPT-001, BIN-001, META-001, INSTALL-001 on script commands -> verify: one firing and one benign fixture per rule.
4. Dry run on 200 DataDog npm samples on the container host -> verify: a short note of what package.json alone catches and misses, no published numbers.

Phase 2, tokenizer:

5. `js.py` tokenizer -> verify: tests for regex vs division, nested templates, comments, escapes, minified input; whole benign top 1,000 tokenizes, every failure is `BKT-SKIP-003`.

Phase 3, code rules:

6. INSTALL on script files, then IMPORT, then HIDE, then EXFIL on JS strings, one group per change -> verify: fixtures per rule, benign flags triaged after each group.

Phase 4, lockfiles:

7. `package-lock.json` -> verify: real lockfiles check end to end; a tampered `integrity` gives `BKT-LOCK-001`; a redirect off `registry.npmjs.org` is refused.
8. `yarn.lock` v1, then `pnpm-lock.yaml` -> verify: same tests per format.

Phase 5, evaluation:

9. Benign, DataDog and GuardDog runs -> verify: `eval/npm-*/RESULTS.md` in the same shape as Python, internal until reviewed. Then decide on tree-sitter from the miss triage.

Phase 6, surfaces:

10. `diff`, MCP `check_release` with an `ecosystem` argument, Action accepts `package-lock.json` -> verify: extended MCP round-trip and CLI tests.

## Risks

- **Install-script value shrinks** as npm 12 spreads: lead with require-time rules.
- **JS is harder to read:** bundles, minified `dist/`, dynamic `require`. Large bundles may raise `not_verified` noise; measure in phase 5 before tuning.
- **Corpus bias and spam** flatter results: report takeovers and spam separately.
- **Benign noise** from native builds: info for known build commands, plus the allowlist.
- **Hostile input to the tokenizer:** size limits, no backtracking regexes, fail closed.
- **Scope creep:** one ecosystem at a time; VS Code extensions only after npm phase 5.

## Sources

1. OpenSSF malicious-packages, stats `all.csv` (2026-11-11): https://ossf.github.io/malicious-packages/stats
2. npm scripts docs: https://docs.npmjs.com/cli/v11/using-npm/scripts
3. DataDog dataset and `samples/*/manifest.json` (fetched 2026-11-11): https://github.com/DataDog/malicious-software-packages-dataset
4. Veracode acquires Phylum assets, 2025-01-06: https://www.veracode.com/press-release/veracode-acquires-phylum-inc-technology-to-transform-software-supply-chain-security/
5. VS Code activation events: https://code.visualstudio.com/api/references/activation-events
6. Cargo build scripts: https://doc.rust-lang.org/cargo/reference/build-scripts.html
7. Go blog, supply chain: https://go.dev/blog/supply-chain
8. BleepingComputer, IndonesianFoods: https://www.bleepingcomputer.com/news/security/new-indonesianfoods-spammer-floods-npm-with-150-000-packages/
9. CISA alert: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
10. Semgrep on chalk/debug: https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack
11. GitHub changelog, npm v12: https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/ ; release date from registry.npmjs.org/npm
12. Socket, pnpm 10: https://socket.dev/blog/pnpm-10-0-0-blocks-lifecycle-scripts-by-default
13. Bun lifecycle docs: https://bun.sh/docs/install/lifecycle
14. Yarn `enableScripts`: https://yarnpkg.com/configuration/yarnrc#enableScripts
15. GuardDog README: https://github.com/DataDog/guarddog
16. Socket, manifest confusion: https://socket.dev/blog/manifest-confusion
17. Ohm et al., Backstabber's Knife Collection, DIMVA 2020: https://arxiv.org/abs/2005.09535
18. npm-high-impact: https://github.com/wooorm/npm-high-impact
