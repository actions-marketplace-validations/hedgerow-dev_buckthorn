import zipfile

from conftest import record_hash

from buckthorn.findings import verdict
from buckthorn.scan import scan_wheel

GOOD = {"pkg/__init__.py": "x = 1\n"}


def _rules(findings):
    return sorted(f.rule_id for f in findings)


def _record(*rows: str) -> dict[str, str]:
    return {"pkg-1.0.dist-info/RECORD": "\n".join(rows + ("pkg-1.0.dist-info/RECORD,,",)) + "\n"}


META = "pkg-1.0.dist-info/METADATA," + record_hash(b"Name: pkg\nVersion: 1.0\n") + ","
INIT = "pkg/__init__.py," + record_hash(b"x = 1\n") + ",6"


def test_well_formed_wheel_is_clean(make_wheel):
    findings = scan_wheel(make_wheel(GOOD))
    assert findings == []
    assert verdict(findings) == "clean"


def test_hash_mismatch_fires(make_wheel):
    members = GOOD | _record("pkg/__init__.py," + record_hash(b"x = 2\n") + ",6", META)
    findings = scan_wheel(make_wheel(members))
    assert _rules(findings) == ["BKT-REC-001"]
    assert findings[0].file_path == "pkg/__init__.py"


def test_file_missing_from_record_fires(make_wheel):
    members = GOOD | {"pkg/extra.py": "y = 1\n"} | _record(INIT, META)
    findings = scan_wheel(make_wheel(members))
    assert _rules(findings) == ["BKT-REC-002"]
    assert findings[0].file_path == "pkg/extra.py"


def test_listed_without_a_hash_counts_as_missing(make_wheel):
    members = GOOD | _record("pkg/__init__.py,,", META)
    assert _rules(scan_wheel(make_wheel(members))) == ["BKT-REC-002"]


def test_weak_hash_counts_as_missing(make_wheel):
    members = GOOD | _record("pkg/__init__.py,md5=abc,6", META)
    assert _rules(scan_wheel(make_wheel(members))) == ["BKT-REC-002"]


def test_no_record_at_all_fires(make_wheel):
    findings = scan_wheel(make_wheel(GOOD, record=False))
    assert _rules(findings) == ["BKT-REC-002"]


def test_second_copy_of_a_member_must_match_too(tmp_path, make_wheel):
    import warnings

    path = make_wheel(GOOD)
    with warnings.catch_warnings(), zipfile.ZipFile(path, "a") as zf:
        warnings.simplefilter("ignore")
        zf.writestr("pkg/__init__.py", "import os\n")
    assert _rules(scan_wheel(path)) == ["BKT-REC-001"]


def test_metadata_name_mismatch_fires(make_wheel):
    members = GOOD | {"pkg-1.0.dist-info/METADATA": "Name: requests\nVersion: 1.0\n"}
    assert _rules(scan_wheel(make_wheel(members))) == ["BKT-META-001"]


def test_metadata_version_mismatch_fires(make_wheel):
    members = GOOD | {"pkg-1.0.dist-info/METADATA": "Name: pkg\nVersion: 2.0\n"}
    assert _rules(scan_wheel(make_wheel(members))) == ["BKT-META-001"]


def test_name_normalisation_is_not_a_mismatch(make_wheel):
    members = {"my_pkg-1.0.dist-info/METADATA": "Name: My.Pkg\nVersion: 1.0\n"}
    assert scan_wheel(make_wheel(members, "my_pkg-1.0-py3-none-any.whl")) == []


def test_missing_metadata_fires(make_wheel):
    path = make_wheel(GOOD)
    # Rewrite the wheel without its METADATA.
    with zipfile.ZipFile(path) as zf:
        kept = {
            i.filename: zf.read(i) for i in zf.infolist() if not i.filename.endswith("METADATA")
        }
    with zipfile.ZipFile(path, "w") as zf:
        for member, data in kept.items():
            zf.writestr(member, data)
    assert "BKT-META-001" in _rules(scan_wheel(path))


def test_two_dist_info_folders_fire(make_wheel):
    members = GOOD | {"other-1.0.dist-info/METADATA": "Name: other\nVersion: 1.0\n"}
    assert _rules(scan_wheel(make_wheel(members))) == ["BKT-META-001"]


def test_integrity_is_skipped_when_the_read_was_cut_short(make_wheel, monkeypatch):
    from buckthorn import scan

    monkeypatch.setattr(scan, "MAX_MEMBERS", 1)
    assert _rules(scan_wheel(make_wheel(GOOD))) == ["BKT-SKIP-002"]
