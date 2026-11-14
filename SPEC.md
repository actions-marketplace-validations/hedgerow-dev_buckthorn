# Buckthorn: spec

Status: draft.

## The one-line version

Before a Python dependency is installed or upgraded, say whether it does
something a library has no business doing: run code at install, run code at
interpreter start, fetch and run remote code, hide its code, or reach for
credentials. Static only. Nothing is installed, imported or run.

## Why

Hayward reads model files without loading them. The same idea fits open-source
libraries: most malicious packages do not need a vulnerability, they only need
`pip install` or `import`. Known CVE scanners (pip-audit, OSV) answer "is this
version known-bad". Buckthorn answers "what will this package do to my machine",
including for a version nobody has reported yet.

There is also a direct link back to Hayward. The ShadowPickle "overwritten
module" attack (arXiv:2607.17503) defeats every pickle scanner by planting a
`.pth` file that swaps `collections` at interpreter start. That file arrives
through a dependency. Buckthorn is where it gets caught.

## Scope

**In (v1):** Python packages from PyPI: wheels, sdists, a lockfile or
requirements file, and an installed environment.

**Out:**
- Model files (that is Hayward).
- Known-vulnerability lookup (pip-audit and OSV already do it; Buckthorn can link
  to them, not repeat them).
- License compliance.
- Reputation scores built on data we cannot show (download counts, author age
  as a verdict). These may appear as context, never as the reason for a verdict.
- npm and other ecosystems. Revisit after v1 (see open questions).

## Inputs

| Input | Example | How it is read |
|---|---|---|
| Wheel | `pkg-1.2.0-py3-none-any.whl` | zip, read in memory with Hayward's archive limits |
| Sdist | `pkg-1.2.0.tar.gz` | tar, read with the same limits, never extracted to disk unsafely |
| Lockfile | `uv.lock`, `poetry.lock`, `requirements.txt` with hashes | each pinned artifact is fetched from PyPI by URL and checked against its hash before reading. By default only the file this machine would install (lockfiles pin every platform's wheels: one real project pins 31 GB); `--all-files` for all |
| MCP config | `.mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` | each server's launch command is read; a PyPI package it installs (`uvx`, `uv run --with`, `pipx run`) is fetched and hash-checked like a lockfile pin. See `docs/rules.md` |
| Environment | a venv or `site-packages` | files read in place; `RECORD` used as the inventory |
| Upgrade | `pkg==1.2.0` to `pkg==1.3.0` | both versions read, findings reported as a diff |

## What it checks

Rule ids use the `BKT-` prefix and follow Hayward's rule: public, stable within
a major version, documented in `docs/rules.md`.

### 1. Code that runs at install

- `setup.py` that does more than call `setup()`: network calls, `subprocess`,
  `exec`/`eval`, writes outside the build tree, reads of credential paths.
- A custom build backend that lives in the sdist itself.
- An sdist-only release of a package that normally ships wheels (install-time
  code where there was none before).

### 2. Code that runs at interpreter start

- `.pth` files with an `import` line (they execute on every Python start).
- `.pth` lines that touch `sys.modules`, `builtins`, or import hooks
  (the ShadowPickle shape).
- `sitecustomize.py` / `usercustomize.py` shipped in a package.
- Console scripts that shadow common commands (`python`, `pip`, `git`, `ssh`).

### 3. Code that runs at import

Read with `ast`, never imported. Flag top-level code (module body, not inside a
function) that:

- opens network connections or downloads,
- runs `subprocess`, `os.system`, `exec`, `eval`, `compile`,
- reads secrets: environment variables in bulk, `~/.ssh`, `~/.aws`,
  `~/.config/gcloud`, browser profiles, `.git-credentials`,
- writes to shell profiles, cron, launch agents, or other startup locations.

A combination (reads secrets **and** sends to the network) is a higher
severity than either alone.

### 4. Hidden code

- `exec`/`eval` of data decoded at run time (base64, zlib, marshal, rot13,
  bytes reversed, XOR loops).
- Distributions that ship only `.pyc` or marshalled code for modules that
  should be source.
- Long high-entropy string literals feeding a decoder.

### 5. Unexpected binaries

- Native code (`.so`, `.pyd`, `.dll`, `.dylib`) in a wheel tagged pure Python.
- Executables (ELF, Mach-O, PE) not referenced as extension modules.
- Reuses Hayward's embedded-executable detection.

### 6. Package integrity

- Wheel `RECORD` hashes that do not match the files, or files missing from it.
- Name or version in metadata that does not match the file name.
- A lockfile artifact whose hash does not match what was downloaded.

### 7. What changed in an upgrade (diff mode)

The highest-signal, lowest-noise view: a new install hook, a new `.pth`, a new
network call at import, a new binary, between two versions of the same package.
Most real takeovers show up here first. Diff mode reports only what is new.

## Verdicts

Same model as Hayward, so tools that read one read the other:

- `clean`: everything was read and nothing was flagged.
- `flagged`: at least one finding above INFO.
- `not_verified`: something could not be read (a limit hit, an archive that
  would not open, an artifact that could not be fetched). Never reported as
  clean. Fail closed.

## Reuse from Hayward

Decided 2026-11-03: not yet. Hayward's verdict logic only knows its own
`MFV-` coverage rules and has no supply-chain category, so milestone 1 keeps
its own small `Finding` with the same field and verdict names. Revisit when
the report formats are needed.

Buckthorn depends on the `hayward` package for the parts that are not about model
files:

- `Finding`, severities, coverage rules and `file_verdicts`
- report formats (text, JSON, SARIF, HTML)
- policy, baseline and allowlist files
- signed scan receipts (in-toto), so a CI job can prove what it checked
- archive reading limits and embedded-executable detection

New code is the package readers (wheel, sdist, lockfiles, `RECORD`) and the
`BKT-` rules. If the shared part grows, it can move into a small common core
later; not before it is needed.

## Interfaces

```bash
buckthorn scan pkg-1.2.0-py3-none-any.whl      # one artifact
buckthorn scan ./dist                          # a folder of artifacts
buckthorn check uv.lock                        # every pinned dependency
buckthorn env .venv                            # an installed environment
buckthorn diff requests==2.32.3 requests==2.32.4
```

Plus, after the CLI is stable: a pre-commit hook, a GitHub Action that runs
`buckthorn check` on lockfile changes, and an MCP tool like Hayward's.

Exit codes follow Hayward: 0 clean, 1 flagged, 2 error, and `not_verified`
treated as flagged unless the caller opts out.

## Safety rules for the tool itself

- Never install, import, build or execute anything it reads. No `pip install`,
  no `setup.py egg_info`, no build backend calls.
- Archive limits on members, sizes and nesting (reuse Hayward's), with a hit
  reported as `not_verified`.
- File names from archives are data: no path joins that can leave a temp
  folder.
- Network only to fetch artifacts named in the input, from PyPI's file host,
  checked against a hash before reading. Decided 2026-11-03: also PyPI's JSON
  API (pypi.org), only to find which file a pinned hash belongs to when the
  lockfile gives no URL (requirements.txt, poetry.lock), and to find the
  newest release of an MCP server package a config does not pin. https only;
  redirects to any other host are refused.

## Milestones

Each one ships on its own, with tests first.

1. **Artifact scan.** `buckthorn scan` for wheels and sdists, rule groups 1, 2, 5
   and 6. Done when each rule has a fixture that fires and a benign fixture that
   does not.
2. **Import-time and hidden code.** Rule groups 3 and 4 on the AST. Done when
   the false-positive check below passes on the benign corpus.
3. **Lockfiles and diff.** `buckthorn check` and `buckthorn diff`. Done when an
   upgrade that adds a `.pth` or install hook is reported and nothing else is.
4. **Environment and CI.** `buckthorn env`, the pre-commit hook, the GitHub
   Action, signed receipts.

## How we know it works

- **Malicious corpus:** public datasets of real malicious PyPI packages, for
  example DataDog's `malicious-software-packages-dataset` and the Backstabber's
  Knife Collection. Read only inside an isolated container with no network.
- **Benign corpus:** the most-installed PyPI packages, scanned the same way.
  Every flag on it is triaged and either fixed or documented.
- No accuracy numbers are published until both corpora are run and the results
  are reviewed.

## Open questions

1. **License.** Decided 2026-11-06: MIT, like Hayward and Rowan.
2. **Packaging.** A separate `buckthorn` package that depends on `hayward`
   (the working assumption), or a shared core both depend on from the start?
3. **npm next?** Decided 2026-11-11: yes, npm is the next ecosystem, in this
   tool, with new rule ids under `BKT-NPM-*`. Plan: `docs/beyond-python-plan.md`.
4. **Service.** Should hayward-verify also publish signed Buckthorn verdicts for
   popular packages, like it does for models?
