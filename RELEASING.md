# Releasing

Releases go to PyPI from `.github/workflows/release.yml` when a GitHub release
is published. It uses PyPI Trusted Publishing, so no API token is stored
anywhere.

## One-time setup

On pypi.org, under Account settings, Publishing, add a pending publisher:

- PyPI project name: `buckthorn`
- Owner: `hedgerow-dev`
- Repository name: `buckthorn`
- Workflow name: `release.yml`
- Environment name: `pypi`

On GitHub, under Settings, Environments, create `pypi`. Optional but
recommended: add yourself as a required reviewer, so every upload waits for a
click.

The repository is private today. Make it public before the first release, or
the project links on PyPI and in this README lead nowhere.

## Each release

1. Set `version` in `pyproject.toml`, merge to `main`, and wait for CI.
2. Under Actions, Release, use "Run workflow" on `main`. It builds and tests
   on Linux, Windows and macOS without publishing. CI only runs Linux, so this
   is the first time Windows and macOS see the change.
3. On GitHub, draft a new release with a new tag `vX.Y.Z` on `main`. The tag
   must match the version, or the workflow stops.
4. Publish the release. The workflow builds once, tests that wheel on Linux
   (Python 3.11 and 3.14), Windows and macOS (3.13), then uploads it.
5. Check https://pypi.org/p/buckthorn and try `uvx buckthorn --version`.

A failed upload can be retried with "Re-run failed jobs" on the workflow run.
A version number cannot be reused on PyPI, even after a delete.
