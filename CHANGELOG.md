# Changelog

## Unreleased

- `check` reads NuGet's `packages.lock.json` and `packages.config` (preview).
  Each package is fetched from nuget.org. A `packages.lock.json` entry is
  checked against its `contentHash` before it is read, computed as NuGet
  does for a signed package. `packages.config` pins no hash, so what
  nuget.org serves is scanned, with a note (`BKT-LOCK-004`). The Action and
  the pre-commit hook take both.
- A link in an MSBuild `Error`, `Warning` or `Message` no longer makes a
  command built from properties count as fetching (`BKT-NUGET-BUILD-002`).
  Native AOT's `Microsoft.DotNet.ILCompiler` and `Sentry` drop from high to
  medium: they still run commands at build.

## 0.3.0

- `scan` reads NuGet packages (`.nupkg`, preview): the `.nuspec`, the
  PowerShell scripts Visual Studio runs from `tools/`, and the MSBuild files
  NuGet imports into every build (`Exec`, `DownloadFile`, inline task code,
  and the package files they import), and MSBuild SDK packages
  (`Sdk/Sdk.props`). Analyzers, task assemblies and swapped build tools are
  compiled code that runs at build and is not read, so a package that ships
  them is `not_verified`. New rules: `BKT-NUGET-*`.
- A run on the top 1,000 NuGet packages is in `eval/nuget-noise/NOTE.md`.

## 0.2.0

- `check` reads `package-lock.json` and `npm-shrinkwrap.json` (preview). Each
  tarball is fetched from registry.npmjs.org and checked against its sha512
  integrity before it is read. The Action and the pre-commit hook take them.
- npm: the commands a `.gyp` or `.gypi` file runs (`<!(cmd)`) are read as
  install commands. One that runs a file of the package is flagged, and that
  file is read as install code. A real takeover hid its payload this way.
- npm: a `binding.gyp` in another folder that an install script builds
  (`node-gyp rebuild -C sub`), or named in another case (`Binding.gyp`), is
  no longer missed. Both scanned clean before.
- A run on 1,477 real hijacked releases (Shai-Hulud and others) is in
  `eval/real-attacks/RESULTS.md`.

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
