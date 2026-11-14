# Held-out evaluation: protocol

Written and committed 2026-11-12, before any held-out sample was fetched or
scanned. The commit time of this file is the pre-registration. Whatever the
outcome, every number named under "What will be reported" goes into
`RESULTS.md`.

## Why

Buckthorn's rules were tuned from 2026-11-03 to 2026-11-12 against three
corpora (DataDog `samples/pypi`, pypi_malregistry, the PyPI top 1,000) and,
for one fix (`1b3995a`), a sample of 100 MCP server packages from the MCP
registry. Numbers on those sets are optimistic. This run measures the frozen
code on samples none of that tuning saw.

## Frozen code

- Code under test: main at `c80b090` (tree `f5daf10452a9b93aa991b2e2acc45ffd861dd4da`).
- Image source: `git archive --format=tar c80b090`, sha256
  `dfb3dd7f24b5f764e3b73764ca5da09c5878906d4a7901e5652a8f7d4515c28d`.
- Image: built with `../datadog-malicious/scripts/Containerfile`
  (python:3.12-slim) on the Mac mini as
  `localhost/buckthorn-scan:heldout-c80b090`, image id
  `0c551ce988fc0229829f98727628d0e0276b88d7b2082a031ac563eac65d7f33`. The
  benign host gets this same image by `podman save` and `podman load`; its id
  is checked before scanning.
- GuardDog 3.2.0: the existing `localhost/guarddog:3.2.0` image on the mini,
  id `166c1e8947d94862f495048d7e188b96f6fa4e232d97859667d1e7e0d0083a2e`, moved
  the same way to the benign host.
- No rule change may be informed by held-out results. Bugs found are
  reported in `RESULTS.md`, not fixed in this run.

## Tuning data (what held-out samples must not overlap)

| Corpus | Snapshot | Date |
|---|---|---|
| DataDog malicious-software-packages-dataset, `samples/pypi` | `9c24607` (shallow clone) | committed 2026-11-03 08:37 UTC |
| pypi_malregistry | `5f2592d` | committed 2026-09-03 04:42 UTC |
| PyPI top 1,000 (hugovk `top-pypi-packages-30-days`) | list `last_update` 2026-11-01 06:41 | fetched 2026-11-05 |
| Top 100 subset of the same list (`bkt-benign/top100`) | | used in the G2/G6 rescans |
| MCP registry sample: 100 PyPI packages launched by `uvx` | `~/bkt-run/mcp/registry-pypi.json` | 2026-11-11 |

## What was looked at before writing this

Metadata only, no sample content and no scan:

- DataDog upstream: commits after `9c24607` are `acb33fe` (2026-11-04) and
  `72c723b` (2026-11-05). The GitHub compare shows one changed file (a
  manifest) and **no new sample**.
- pypi_malregistry upstream: commit `76e8530` (2026-11-11 03:40 UTC, README
  "Add 413 new malicious packages") adds **431 archives** (366 `.tar.gz`, 65
  `.whl`) in 228 package folders. `b85fe77` changes only the README.
- OSV MAL reports (`ossf/malicious-packages` at `4a3365f`, 2026-11-12) for
  those 228 names, by earliest `published`: 205 between 2026-09-03 and
  2026-11-02, 22 on or after 2026-11-03, 1 before 2026-09-03.
- No other openly licensed dataset with downloadable PyPI malware added after
  2026-11-03 was found (searched: DataDog, pypi_malregistry, QUT-DV25 holds
  traces not code, MalwareBench and Backstabber's Knife Collection are gated
  or gone). OSV MAL reports carry no code and PyPI removes it.

## Malicious held-out set (M)

**Source.** pypi_malregistry, the 431 archives added by `76e8530` (data
freeze `b85fe77`). Fetched by a blobless clone with sparse checkout of
exactly those paths into a Podman volume `heldout-malreg` on the mini. The
fetch writes archive files only: nothing is unpacked or run.

**Why this counts as held out.** Every archive was added to its dataset
after the snapshot of that dataset used in tuning, and all but one package
name was first reported (OSV) after the pypi_malregistry snapshot. A strict "first reported after
2026-11-03" set is only 22 package names, too few to be the headline, so it
is reported as a secondary split. DataDog added nothing, so it contributes
no samples. A later rerun of this same image on samples added to either
dataset after this date is the planned extension (see the end).

**Exclusions, in order** (each excluded sample is listed with its reason):

1. Archive sha256 equal to the sha256 of any tuning artifact: pypi_malregistry
   archives, DataDog rebuilt archives (as recorded in the tuning results),
   top-1,000 benign files.
2. (normalised name, version) present in a tuning corpus. Name normalised by
   PEP 503 (`[-_.]+` to `-`, lower case). Version as the dataset's folder
   name, lower case, with a leading `v` removed. Tuning pairs come from the
   folder layout (pypi_malregistry `name/version/`, DataDog
   `category/name/version/`) and the benign file names.
3. Exact duplicates inside M (same sha256): the first by sorted path is kept.

**Format.** An archive whose bytes do not match its extension (a zip stored
under a `.tar.gz` name) is copied, inside the scan container, to a correctly
named file, as `../pypi-malregistry/scripts/rename_scan.py` did in tuning.
Both tools read the renamed copy.

**Families.** A held-out sample is in a **seen family** if any of these holds
against the tuning malicious corpora (DataDog and pypi_malregistry):

- F1. Same normalised name as a tuning sample.
- F2. Same name after stripping trailing digits and separators
  (`aiosendletter2` to `aiosendletter`), when the stripped name has at least
  4 characters.
- F3. Levenshtein distance 1 from a tuning sample's normalised name, both
  names at least 6 characters long (typosquat variants of a seen name).
- F4. Shares a file with a tuning sample: identical sha256 of a `.py` file of
  at least 512 bytes, ignoring any such hash that also occurs in the top-1,000
  benign corpus (shared library code). File hashes are computed inside
  `--network none` containers; only hashes leave them.

Otherwise it is a **new family**. Held-out samples are also grouped among
themselves by F1 to F4 (connected components) to count distinct families.

## Benign held-out sets

Fetched and scanned on an Azure VM only.

**B1: PyPI ranks 1,001 to 3,000.** Rows 1,001 to 3,000 (1-based) of hugovk's
`top-pypi-packages-30-days.min.json`, the same source as the top 1,000,
fetched 2026-11-12 from `hugovk.dev` (the old `github.io` URL now
redirects): `last_update` 2026-11-01 06:41:05, sha256
`3e958a64ebe1de0b6a4ab4c6b465d481f350fd1dfa926c639add36eb34dabc1e`. The
same snapshot as tuning's list, so these ranks do not overlap the top 1,000.

**B2: random recently released projects.** Universe: every project on the
PyPI simple index (PEP 691 JSON), fetched once and stored with its sha256.
Shuffled with `random.Random(20261112)`. Walk the shuffled list and query
`https://pypi.org/pypi/<name>/json`; a project is taken when any file of any
release was uploaded in the 30 days before the walk started (UTC, recorded),
until 1,000 are taken. Skipped, with counts kept: projects in rows 1 to 3,000
of the list above (so B1 and B2 do not overlap), projects with any OSV MAL
report for PyPI (withdrawn reports excepted), projects with no fetchable file.

**Both.** Excluded: any project in a tuning benign set (top 1,000, top 100,
the MCP registry sample of 100), by normalised name, and any file whose sha256
is a tuning file's. For each project, the latest release (`info.version` at
fetch time): its sdist (first listed), plus the one wheel this scan image
would install, chosen by `pip._vendor.packaging.tags.sys_tags()` in the image
(CPython 3.12, linux x86_64, glibc 2.41), the first-ranked compatible tag
winning. A project may give 0, 1 or 2 files. Every file is checked against
PyPI's sha256. Request rate is kept to a few per second.

B2 is presumed benign, not known benign: it is new, unreviewed code. Before
results are written, OSV is checked again; a B2 project reported since is
moved out and listed. A B2 flag that triage finds to be malicious behaviour
is reported as such, not as a false alarm.

## Running

- **Malicious: Mac mini only,** inside `podman run --network none --read-only
  --cap-drop all --security-opt no-new-privileges`, corpus volume mounted
  read-only, a tmpfs for scratch. Nothing is unpacked to the host, nothing is
  copied to the MacBook, nothing is installed or run.
- **Benign: Azure only,** same container flags.
- Buckthorn: `buckthorn scan --format json FILE` per file, 4 workers, 900 s
  timeout per file (as `../datadog-malicious/scripts/scan_files.py`).
- GuardDog: `guarddog pypi scan FILE --output-format json` per file, 4
  workers, 900 s timeout, offline, so its metadata rules do not run (as
  `../guarddog/scripts/gd_scan.py`, `files` mode).
- **Stored results: rule ids, severities, file names and line numbers only.**
  Finding messages and matched text are dropped (samples hold live webhook
  URLs). Results are gzipped JSON lines under `results/`.

## What counts

- **Buckthorn detection:** verdict `flagged`. `not_verified` is never counted
  as caught; it is reported as its own rate. Errors and timeouts count as not
  caught and are reported. Samples flagged only by integrity rules
  (`BKT-REC-*`, `BKT-META-001`) count as flagged and are also counted apart.
- **GuardDog:** "threat" = at least one `threat-*` rule; "any rule" = at least
  one rule of either level. Errors count as not caught.
- **Benign flag rate:** files flagged / files scanned, per stratum; also
  projects with at least one flagged file / projects.

## What will be reported

Whatever the outcome:

1. Counts at each step: candidates, each exclusion, final M; B1 and B2
   projects and files, each skip reason.
2. M: Buckthorn flagged, clean, not_verified, error, each as a rate with a
   Wilson 95% interval; the same for GuardDog threat and any rule; "either"
   (Buckthorn flagged or GuardDog threat). Split by new family and seen
   family; by OSV first report on or after 2026-11-03 versus earlier; and
   one archive per held-out package (picked with `random.Random(20261115)`)
   so many versions of one package do not dominate.
3. B1 and B2: the same rates for Buckthorn and both GuardDog levels, per file
   and per project, with Wilson 95% intervals.
4. Triage of 50 benign Buckthorn flags drawn at random from B1 and B2
   together (`random.Random(20261113)`; all, if fewer): real behaviour the rule
   describes, false alarm (the behaviour is not there, or not at that time),
   or malicious.
5. Triage of 50 malicious misses (verdict not `flagged`) drawn at random
   (`random.Random(20261114)`; all, if fewer), with the reason: payload only in
   code run later (out of scope), no payload in the sample, in-scope behaviour
   no rule matches (rule gap), file not read (coverage), not_verified, error.
   Done from call names and their locations extracted in the container
   (`../pypi-malregistry/scripts/triage_archives.py`), with hand reading
   inside the container where needed; no sample text is stored.
6. Bugs found, not fixed.
7. Every deviation from this protocol, with the reason.

## Not in this run

- **npm.** Buckthorn at `c80b090` does not read npm packages (that work is on
  another branch), so an npm track would measure nothing here.
- **Planned extension.** Rerun this image, unchanged, on samples added to
  DataDog `samples/pypi` after `72c723b` and to pypi_malregistry after
  `b85fe77`, once enough accumulate, using this protocol.
