# Buckthorn

A static checker for open-source Python and npm packages: before a dependency is
installed or upgraded, it says whether the package runs code at install, at
interpreter start or at import, hides its code, ships unexpected binaries, or
reaches for credentials. It never installs, imports or runs what it reads.

A second module next to [Hayward](https://github.com/hedgerow-dev/hayward),
which does the same for model files.

Status: early. Needs Python 3.11 or newer.

```bash
pipx install buckthorn      # or: pip install buckthorn
uvx buckthorn --help        # or run it without installing
```

```bash
buckthorn scan pkg-1.2.0-py3-none-any.whl      # one wheel or sdist
buckthorn scan ./dist                          # a folder of them
buckthorn scan left-pad-1.3.0.tgz              # an npm tarball
buckthorn check uv.lock                        # every pinned dependency
buckthorn diff requests==2.32.3 requests==2.32.4   # only what an upgrade adds
buckthorn scan --format json ./dist            # machine-readable
```

`check` and `diff` fetch from PyPI over https only (pypi.org and
files.pythonhosted.org) and check each file's sha256 before reading it.
`check` reads `requirements.txt` with hashes, `uv.lock` and `poetry.lock`.
By default it checks the file this machine would install for each package;
`--all-files` checks every platform's.

Each artifact gets one verdict:

- `clean`: everything was read and nothing was flagged.
- `flagged`: at least one finding above info.
- `not_verified`: something could not be read. Never reported as clean.

Exit codes: 0 clean, 1 flagged or not_verified (`--allow-not-verified` lets
not_verified pass), 2 a usage or input error.

## How well it works

We tested it on packages it had never seen, with the plan committed before
the first scan
([PROTOCOL.md](https://github.com/hedgerow-dev/buckthorn/blob/main/eval/heldout/PROTOCOL.md)).
That run used commit `c80b090`, from before the last fixes in 0.1.0.

| | Buckthorn | GuardDog 3.2.0 |
|---|---|---|
| Malicious archives flagged (430) | 52.3% | 68.6% |
| Benign files flagged (5,723) | 5.4% | 23.7% |

So Buckthorn misses more malware than GuardDog, and raises about a quarter
of its false alarms. Most of what it misses runs only when you call a
function, like a downloader behind `fetch(url)`. Buckthorn reads what runs at
install, at start-up and at import. Of 50 misses we looked at, only one was
code of that kind a rule should have caught. In our view it works best next
to a broader scanner.

On the corpora we tuned on, it flags about 90% of pypi_malregistry and 85% of
DataDog's malicious PyPI samples. Those are not the headline numbers, since
the rules were written against that data. The full write-up is in
[eval/heldout/RESULTS.md](https://github.com/hedgerow-dev/buckthorn/blob/main/eval/heldout/RESULTS.md).

`BUCKTHORN_CALL_TIME=1` also reads code that only runs when called, and flags
five combinations, such as fetching code and running it. It is off by
default, because it has not been tested on unseen data yet.

## Check an agent's MCP config

An agent starts every MCP server in its config as soon as it loads it, with
your credentials, and nobody looks at what `uvx some-server` pulls in that
day. Point `check` at the config:

```bash
buckthorn check .mcp.json                      # Claude Code
buckthorn check .vscode/mcp.json               # VS Code
buckthorn check ~/.cursor/mcp.json             # Cursor (Windsurf and Claude Desktop too)
```

For each server launched with `uvx`, `uv run --with` or `pipx run`, it fetches
the PyPI release that would run and scans it. Only the server package is
read, not its dependencies. Servers with no version pinned are counted in
the summary, since the next release runs at the next start. npm and Docker
servers are reported as not checked yet. Values from `env`, arguments and
URLs are never printed.

Rules are listed in
[docs/rules.md](https://github.com/hedgerow-dev/buckthorn/blob/main/docs/rules.md).
The design is in [SPEC.md](https://github.com/hedgerow-dev/buckthorn/blob/main/SPEC.md).

## npm packages

`scan` reads npm tarballs too: the `.tgz` the registry serves, or what
`npm pack` writes.

```bash
npm pack left-pad@1.3.0 && buckthorn scan left-pad-1.3.0.tgz
```

It reads the scripts in `package.json`, the JavaScript that `preinstall`,
`install` and `postinstall` run, and the code that runs when the package is
loaded. `package-lock.json` is not read yet. npm support is newer than the
Python side: it was tuned on the top 1,000 npm packages and 200 malicious
ones, and has not been tested on unseen packages. The rules are the
`BKT-NPM-*` ones in
[docs/rules.md](https://github.com/hedgerow-dev/buckthorn/blob/main/docs/rules.md#npm).

## In CI and pre-commit

The GitHub Action checks a lockfile before anything is installed. It fails
the build on a finding and writes SARIF for code scanning:

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload

steps:
  - uses: actions/checkout@v4
  - uses: hedgerow-dev/buckthorn@v0.1.0
    with:
      lockfile: uv.lock
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: buckthorn.sarif
```

All inputs, including `allowlist` and signed receipts, are in
[action.yml](https://github.com/hedgerow-dev/buckthorn/blob/main/action.yml).
Tags are shown for reading. For a security check, pin each action to a
commit SHA instead, as `action.yml` does for its own steps.

As a pre-commit hook, it runs whenever `uv.lock`, `poetry.lock` or a
`requirements*.txt` changes:

```yaml
repos:
  - repo: https://github.com/hedgerow-dev/buckthorn
    rev: v0.1.0
    hooks:
      - id: buckthorn-check
```

## Model repos with remote code

`trust_remote_code=True` runs the model repo's own Python when you load it.
Buckthorn reads that code first: the files `auto_map` names, what they import,
and the methods transformers calls while loading (`__init__`, `post_init`,
`_init_weights` and the rest).

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

## Accepting a finding

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

## Output formats

`--format text` (default), `json`, or `sarif` for GitHub code scanning.

## Scan receipts

`--receipt FILE` also writes an unsigned in-toto statement: each artifact's
sha256 and what Buckthorn found in it, taken before `--allowlist`. It has the
same shape as Hayward's receipts. It is analysis evidence, not a safety
certificate. In GitHub Actions, set the action's `receipt` and `attest:
"true"` inputs to have GitHub sign it with Sigstore.

## For coding agents (MCP)

```bash
pip install "buckthorn[mcp]"
buckthorn mcp
```

A stdio MCP server with three read-only tools: `scan_path` (a wheel, sdist or
folder of them, no network), `check_release` (a PyPI `name` and `version`:
the file this machine would install, fetched and hash-checked as `check`
does) and `check_mcp_config` (the text of an MCP config, checked as `check`
does). All return the same JSON as `--format json`.
