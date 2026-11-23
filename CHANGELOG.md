# Changelog

## Unreleased

- `check` reads `package-lock.json` and `npm-shrinkwrap.json` (preview). Each
  tarball is fetched from registry.npmjs.org and checked against its sha512
  integrity before it is read. The Action and the pre-commit hook take them.

## 0.1.1

- A shorter Action description, so the Action can be listed on the GitHub
  Marketplace. No change to what Buckthorn checks.

## 0.1.0

The first release.

- `scan` reads wheels, sdists and npm tarballs (preview), or folders of them,
  without installing, importing or running anything.
- `check` reads `requirements.txt` with hashes, `uv.lock`, `poetry.lock` and
  agent MCP configs. It fetches each pinned file from PyPI and checks its
  sha256 before reading it.
- `diff` shows only what an upgrade adds. `env` checks an installed
  environment. `hf` reads a Hugging Face repo's remote code (preview).
- Output as text, JSON or SARIF, with optional in-toto scan receipts.
- `--write-allowlist` accepts what a first run finds, so CI starts green.
- A GitHub Action, a pre-commit hook and an MCP server (`buckthorn[mcp]`).
- `BUCKTHORN_CALL_TIME=1` turns on five rules for code that only runs when
  called. Off by default.

How well it works, and where it falls short, is in the README.
