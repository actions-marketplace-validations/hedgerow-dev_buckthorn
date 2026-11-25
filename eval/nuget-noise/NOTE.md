# NuGet: noise on the top 1,000 packages

A working note, run 2026-11-24. Single runs on benign packages: read them as a
shape, not a rate. No malicious NuGet packages were scanned.

## Short version

- **Final code: 903 clean, 8 flagged, 89 not_verified.** The first cut of
  NuGet support (5b46494) was 897 clean, 47 flagged, 56 not_verified.
- **All 8 flags are real build behaviour:** a command at build (Sentry's
  upload, ChromeDriver's `chmod`, `func --version`, the API description
  tool, the container tools), inline task code (Shouldly), a props file that
  writes a file (Verify), and EntityFramework's `init.ps1`.
- **Most not_verified are analyzers (63),** compiled code the compiler runs
  at every build. The rest: task assemblies (17), imports built from
  properties (4), the archive limit (4), one import of a file not shipped.
  Each fails closed by design.

## What changed between runs

The same 1,000 files were scanned three times.

| Run | Code | Clean | Flagged | Not verified |
|---|---|---|---|---|
| 1 | 5b46494 | 897 | 47 | 56 |
| 2 | + bypass fixes, `install.ps1` as a note | 809 | 8 | 183 |
| 3 | + unimported MSBuild files as a note | 903 | 8 | 89 |

- **Run 1:** 40 of the 47 flags were only `tools/install.ps1` or
  `uninstall.ps1` being there: every AWS SDK package, the Roslyn analyzer
  packages, jQuery, StyleCop. Visual Studio runs them only for
  `packages.config` projects, and these were routine setup (39 distinct
  scripts). They are now an info note: medium again when they decode,
  compile or start code (`iex`, `FromBase64String`, `-EncodedCommand`,
  `Start-Process`, `Add-Type`), high when they fetch. `init.ps1` stays
  medium. A fourth scan with that last change gave the same 903, 8 and 89.
- **Run 2:** flags fell to 8, but 34 packages that had been flagged were
  also analyzer packages, so they became not_verified. A new rule made any
  MSBuild file that no import names a gap, and 96 packages hit it, almost all
  .NET workload manifests (`Microsoft.NET.Sdk.*.Manifest`).
- **Run 3:** that rule is now a note (`BKT-NUGET-BUILD-004`). A property
  built from other properties could point a build at such a file, but that
  property, in a file that is read, is a gap already.

## Gaps this leaves

- **Workload manifests:** `dotnet workload install` makes the SDK import a
  manifest's `WorkloadManifest.targets`. That path is not modelled; those
  files are a note.
- **Analyzer packages always fail closed.** A project that uses analyzers
  needs to accept that verdict or review them another way.

## How it was run

- **List:** nuget.org search with no query, stable only, the first 3,000
  results (the most it pages to), sorted by total downloads, top 1,000 kept
  (`lists_top1000.jsonl`). Latest stable version of each.
- **Fetch:** each `.nupkg` from nuget.org's flat container, kept only if its
  sha512 matched the catalog's `packageHash` (1,000 of 1,000). Never
  unpacked, never run (`scripts/fetch_top.py`).
- **Where:** an Azure VM (Standard_D4s_v5, Ubuntu 24.04, no .NET), created
  for this run. Scanned with `eval/npm-phase3/scripts/scan_top.py`.
- **Results:** `results/run1.jsonl` to `run3.jsonl`: verdict and non-info
  findings (plus coverage gaps) per package, messages cut to 200 characters.
