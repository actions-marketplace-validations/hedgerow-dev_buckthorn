# Changelog

## 0.1.0

The first release.

- `scan` reads wheels, sdists and npm tarballs, or folders of them, without
  installing, importing or running anything.
- `check` reads `requirements.txt` with hashes, `uv.lock`, `poetry.lock` and
  agent MCP configs. It fetches each pinned file from PyPI and checks its
  sha256 before reading it.
- `diff` shows only what an upgrade adds. `env` checks an installed
  environment. `hf` reads a Hugging Face repo's remote code.
- Output as text, JSON or SARIF, with optional in-toto scan receipts.
- A GitHub Action, a pre-commit hook and an MCP server (`buckthorn[mcp]`).
- `BUCKTHORN_CALL_TIME=1` turns on five rules for code that only runs when
  called. Off by default.

How well it works, and where it falls short, is in the README.
