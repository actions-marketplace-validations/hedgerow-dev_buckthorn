<!-- mcp-name: io.github.hedgerow-dev/buckthorn -->

<div align="center">

# Buckthorn

**See what a package runs before you install it.**

Static checks for Python, npm and NuGet packages, MCP configs and Hugging Face remote code.<br>
Nothing is installed, imported or run.

![License MIT](https://img.shields.io/badge/license-MIT-013D5A?style=flat-square&labelColor=013D5A)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-013D5A?style=flat-square&labelColor=013D5A)
![Status 0.1 preview](https://img.shields.io/badge/status-0.1_preview-708C69?style=flat-square&labelColor=013D5A)
![Code it runs: none](https://img.shields.io/badge/code_it_runs-none-F4A25B?style=flat-square&labelColor=013D5A)

</div>

```console
$ buckthorn scan colourful_logs-1.4.2-py3-none-any.whl
colourful_logs-1.4.2-py3-none-any.whl: flagged
  high     BKT-HIDE-001     colourful_logs/__init__.py:2  exec of data decoded by base64.b64decode
  medium   BKT-PTH-001      colourful_logs-1.4.2.pth:1  .pth line runs code at every Python start

1 scanned: 1 flagged
```

A package can run code the moment you install it, every time Python starts,
or as soon as you import it. Buckthorn reads that code first, straight from
the wheel, sdist or npm tarball, and tells you what it does.

## What it is for

**A quiet CI gate.** `buckthorn check uv.lock` reads every pinned file before
anything is installed. On packages it had never seen, it raised about a
quarter of GuardDog's false alarms ([numbers below](#how-well-it-works)).

**Upgrades.** `buckthorn diff requests==2.32.3 requests==2.32.4` shows only
what the new version adds. If a maintainer account is taken over, the new
code is in that diff.

**Your agent's MCP config** (preview). An agent starts every server in
`.mcp.json` with your credentials, and `uvx some-server` pulls whatever was
released that day, dependencies included. `buckthorn check .mcp.json` reads
that install set.

## Install

Needs Python 3.11 or newer.

```bash
pipx install buckthorn      # or: pip install buckthorn
uvx buckthorn --help        # or run it without installing
```

```bash
buckthorn scan pkg-1.2.0-py3-none-any.whl          # one wheel or sdist
buckthorn scan ./dist                              # a folder of them
buckthorn scan left-pad-1.3.0.tgz                  # an npm tarball (preview)
buckthorn scan newtonsoft.json.13.0.4.nupkg        # a NuGet package (preview)
buckthorn check uv.lock                            # every pinned dependency
buckthorn check package-lock.json                  # the same for npm (preview)
buckthorn check packages.lock.json                 # the same for NuGet (preview)
buckthorn check .mcp.json                          # an agent's MCP servers (preview)
buckthorn diff requests==2.32.3 requests==2.32.4   # only what an upgrade adds
buckthorn scan --format json ./dist                # machine-readable
```

- `check` reads `requirements.txt` with hashes, `uv.lock` and `poetry.lock`,
  and `package-lock.json`, `packages.lock.json` and `packages.config`
  (preview).
- For Python, `check` and `diff` fetch from PyPI over https only (pypi.org
  and files.pythonhosted.org), and check each file's sha256 before reading
  it. npm and NuGet are below.
- By default `check` reads the file this machine would install for each
  package. `--all-files` reads every platform's.

## What the verdict means

| Verdict | Meaning |
|---|---|
| `clean` | Nothing flagged in what runs at install, at start-up or at import. Code that only runs when you call it is not read, so `clean` is not "safe". |
| `flagged` | At least one finding above info. Read it, then fix or accept it. |
| `not_verified` | Something could not be read. Never reported as clean. |

Exit codes: 0 clean, 1 flagged or not_verified (`--allow-not-verified` lets
not_verified pass), 2 a usage or input error.

## In CI

The GitHub Action checks a lockfile before anything is installed. It fails
the build on a finding and writes SARIF for code scanning:

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload

steps:
  - uses: actions/checkout@v4
  - uses: hedgerow-dev/buckthorn@v0.3.0
    with:
      lockfile: uv.lock
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: buckthorn.sarif
```

- **Python version.** The check reads the files pip would pick for your
  project's Python: the repository's `.python-version`, or 3.12 when there is
  none. Set `python-version` if your project installs with another one.
- **Pin by SHA.** Tags are shown here for reading. For a security check, pin
  each action to a commit SHA instead, as `action.yml` does for its own steps.
- **All inputs**, including `allowlist` and signed receipts, are in
  [action.yml](https://github.com/hedgerow-dev/buckthorn/blob/main/action.yml).

**The first run.** A real lockfile often has a package or two that does one
of these things on purpose, like setuptools' `.pth` file. Accept what is
there today once, then only new behaviour fails the build:

```bash
buckthorn check uv.lock --write-allowlist buckthorn-allow.json
```

Read the file before you commit it, and pass it as the action's `allowlist`.
Each entry is pinned to the version it was found in, so an upgrade that keeps
the same behaviour shows up again for review.

**Pre-commit.** The hook runs whenever `uv.lock`, `poetry.lock` or a
`requirements*.txt` changes:

```yaml
repos:
  - repo: https://github.com/hedgerow-dev/buckthorn
    rev: v0.3.0
    hooks:
      - id: buckthorn-check
```

## How well it works

We tested it on packages it had never seen, with the plan committed before
the first scan
([PROTOCOL.md](https://github.com/hedgerow-dev/buckthorn/blob/main/eval/heldout/PROTOCOL.md)).
That run used commit `c80b090`, from before the last fixes in 0.1.0.

| On unseen packages | Buckthorn | GuardDog 3.2.0 |
|---|---|---|
| Malicious archives flagged (430) | 52.3% | 68.6% |
| Benign files flagged (5,723) | 5.4% | 23.7% |

- **Quiet on real projects.** Per project, Buckthorn flagged 8.8% of PyPI's
  ranks 1,001 to 3,000 and 5.4% of recently updated projects. So expect a
  flag or two on a real lockfile the first time; `--write-allowlist` is for
  that.
- **It misses more malware than GuardDog.** Most of what it misses runs only
  when you call a function, like a downloader behind `fetch(url)`. Of 50
  misses we looked at, only one was install, start-up or import code a rule
  should have caught. In our view it works best next to a feed of known
  malware, such as OSV's malicious-packages data, and a broader scanner.
- **Real npm takeovers (preview).** On Shai-Hulud it flagged 790 of 810
  hijacked releases it had never seen, and `diff` against the version before
  points at the payload itself. On 588 other npm takeovers it flagged 339:
  most misses add a malicious dependency rather than change the package.
  The run found one gap (`binding.gyp` commands), now fixed: 376 with the fix.
  Details in
  [eval/real-attacks/RESULTS.md](https://github.com/hedgerow-dev/buckthorn/blob/main/eval/real-attacks/RESULTS.md).
- **Tuning data is not the headline.** On the corpora we tuned on, it flags
  about 90% of pypi_malregistry and 85% of DataDog's malicious PyPI samples.
  The rules were written against that data, so those numbers say less.

The full write-up is in
[eval/heldout/RESULTS.md](https://github.com/hedgerow-dev/buckthorn/blob/main/eval/heldout/RESULTS.md).

`BUCKTHORN_CALL_TIME=1` also reads code that only runs when called, and flags
five combinations, such as fetching code and running it. It is off by
default, because it has not been tested on unseen data yet.

## Also in preview

### An agent's MCP config

An agent starts every MCP server in its config as soon as it loads it, with
your credentials, and nobody looks at what `uvx some-server` pulls in that
day. Point `check` at the config:

```bash
buckthorn check .mcp.json                      # Claude Code
buckthorn check .vscode/mcp.json               # VS Code
buckthorn check ~/.cursor/mcp.json             # Cursor (Windsurf and Claude Desktop too)
```

- For each server launched with `uvx`, `uv run --with` or `pipx run`, it
  fetches the PyPI release that would run and scans it, then every package
  that `uvx` or `pipx` would install with it.
- Dependencies come from the release's static metadata (`Requires-Dist`),
  never from installing or building the package.
- A dependency with no exact version pin is counted in the summary: the
  newest match was checked, and a later release is what the next start
  installs. Servers with no version pinned are counted too.
- npm and Docker servers are reported as not checked yet.
- Values from `env`, arguments and URLs are never printed.

### npm packages

`scan` reads npm tarballs too: the `.tgz` the registry serves, or what
`npm pack` writes.

```bash
npm pack left-pad@1.3.0 && buckthorn scan left-pad-1.3.0.tgz
```

It reads the scripts in `package.json`, the JavaScript that `preinstall`,
`install` and `postinstall` run, and the code that runs when the package is
loaded.

`check` reads `package-lock.json` and `npm-shrinkwrap.json` (lockfile
version 2 or 3). Each tarball is fetched from registry.npmjs.org only and
checked against its sha512 `integrity` before it is read. An entry with no
`resolved` URL is fetched from there by name and version. Git, local and
other-registry sources are reported as not checked. The Action and the
pre-commit hook take these files too.

npm support is newer than the
Python side: it was tuned on the top 1,000 npm packages and 200 malicious
ones, and has not been tested on unseen packages. The rules are the
`BKT-NPM-*` ones in
[docs/rules.md](https://github.com/hedgerow-dev/buckthorn/blob/main/docs/rules.md#npm).

### NuGet packages

`scan` reads `.nupkg` files: the `.nuspec`, the PowerShell scripts Visual
Studio runs from `tools/`, and the MSBuild files NuGet imports into every
build (`build/`, `buildTransitive/` and the package files they import).

```bash
buckthorn scan newtonsoft.json.13.0.4.nupkg
```

A command, download or inline task code at build is flagged. Analyzers and
task assemblies are compiled code the build runs, and they are not read, so a
package that ships them is `not_verified`. On the top 1,000 NuGet packages it
gave 903 clean, 8 flagged and 89 not_verified, most of those analyzers
([eval/nuget-noise/NOTE.md](https://github.com/hedgerow-dev/buckthorn/blob/main/eval/nuget-noise/NOTE.md)).
It has not been tested on malicious NuGet packages yet.

`check` reads `packages.lock.json` and `packages.config`. Each package is
fetched from api.nuget.org only. A `packages.lock.json` entry is checked
against its `contentHash` before it is read. `packages.config` pins no hash,
so what nuget.org serves is scanned, with a note. The rules are the
`BKT-NUGET-*` ones in
[docs/rules.md](https://github.com/hedgerow-dev/buckthorn/blob/main/docs/rules.md#nuget).

### Model repos with remote code

`trust_remote_code=True` runs the model repo's own Python when you load it.
Buckthorn reads that code first: the files `auto_map` names, what they import,
and the methods transformers calls while loading (`__init__`, `post_init`,
`_init_weights` and the rest). This part is new, and we have not published
an evaluation on real repos yet.

```bash
buckthorn hf org/name@<commit>     # fetch config and code only, never weights
buckthorn hf org/name              # reads main today, tells you its commit
buckthorn scan ./my-model          # a downloaded repo or a Hub cache snapshot
```

`hf` talks to huggingface.co only, fetches by commit and checks each file
against the Hub's blob id. Pin that commit in `from_pretrained(revision=...)`,
since a verdict for one commit says nothing about the next. `forward` and
`generate` run only when you call them, so they are not read. Rules are in
[docs/rules.md](https://github.com/hedgerow-dev/buckthorn/blob/main/docs/rules.md#hugging-face-remote-code); how this could plug
into Hayward is in [docs/hf-remote-code.md](https://github.com/hedgerow-dev/buckthorn/blob/main/docs/hf-remote-code.md).

## Reference

<details>
<summary><b>Accepting a finding</b></summary>

<br>

Some real packages do what Buckthorn looks for on purpose: setuptools and
coverage.py install `.pth` files that run at start-up. Once you have looked
at one, record it in an allowlist and pass `--allowlist allow.json`:

```json
{
  "allow": [
    {
      "rule": "BKT-PTH-001",
      "package": "setuptools",
      "file": "distutils-precedence.pth",
      "reason": "setuptools' distutils shim; reviewed 2026-11-03"
    }
  ]
}
```

`rule`, `package` and `reason` are required. `file` is a glob, matched with
the version folder taken out (`*/setup.py` matches `pkg-2.0/setup.py`), and
`version` pins the entry to one release. Allowed findings leave the verdict
but stay in the JSON report with their reason. Coverage gaps (`BKT-SKIP-*`,
`BKT-LOCK-002`) cannot be allowed: they mean something was not read.

For an npm tarball, `package` is the name in the file name. The registry
names `@scope/pkg` as `pkg-1.0.0.tgz`, so an entry for `pkg` also covers
another scope's `pkg`. Pin `version` to keep it narrow.

</details>

<details>
<summary><b>Output formats</b></summary>

<br>

`--format text` (default), `json`, or `sarif` for GitHub code scanning.

The JSON report carries a `schema_version`. It goes up when a key changes
meaning or is removed. New keys can appear in any release.

</details>

<details>
<summary><b>Scan receipts</b></summary>

<br>

`--receipt FILE` also writes an unsigned in-toto statement: each artifact's
sha256 and what Buckthorn found in it, taken before `--allowlist`. It has the
same shape as Hayward's receipts. It is analysis evidence, not a safety
certificate. In GitHub Actions, set the action's `receipt` and `attest:
"true"` inputs to have GitHub sign it with Sigstore.

</details>

<details>
<summary><b>For coding agents (MCP server)</b></summary>

<br>

```bash
pip install "buckthorn[mcp]"
buckthorn mcp
```

A stdio MCP server with three read-only tools, all returning the same JSON as
`--format json`:

- `scan_path`: a wheel, sdist or folder of them, no network.
- `check_release`: a PyPI `name` and `version`. The file this machine would
  install, fetched and hash-checked as `check` does.
- `check_mcp_config`: the text of an MCP config, checked as `check` does.

</details>

Every rule is listed in
[docs/rules.md](https://github.com/hedgerow-dev/buckthorn/blob/main/docs/rules.md),
and the design is in
[SPEC.md](https://github.com/hedgerow-dev/buckthorn/blob/main/SPEC.md).

---

Buckthorn is MIT licensed and part of [Hedgerow](https://hedgerow.dev), next
to [Hayward](https://github.com/hedgerow-dev/hayward) for model files.
