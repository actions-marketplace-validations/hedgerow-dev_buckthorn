import zipfile

import pytest

from buckthorn import scan
from buckthorn.findings import verdict


@pytest.fixture
def make_wheel(tmp_path):
    """A bare zip with only the given members: the reader tests count bytes and members."""

    def _make(members):
        path = tmp_path / "pkg-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            for member, data in members.items():
                zf.writestr(member, data)
        return path

    return _make


def test_reads_members_without_extracting(make_wheel, tmp_path):
    path = make_wheel({"pkg/__init__.py": "x = 1\n"})
    members, findings = scan.read_archive(path)
    assert members == [("pkg/__init__.py", b"x = 1\n")]
    assert findings == []
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_not_a_zip_is_not_verified(tmp_path):
    path = tmp_path / "bad-1.0-py3-none-any.whl"
    path.write_bytes(b"not a zip")
    members, findings = scan.read_archive(path)
    assert members == []
    assert [f.rule_id for f in findings] == ["BKT-SKIP-001"]
    assert verdict(findings) == "not_verified"


def test_too_many_members_is_not_verified(make_wheel, monkeypatch):
    monkeypatch.setattr(scan, "MAX_MEMBERS", 2)
    path = make_wheel({f"pkg/m{i}.py": "" for i in range(3)})
    _, findings = scan.read_archive(path)
    assert [f.rule_id for f in findings] == ["BKT-SKIP-002"]


def test_member_over_size_cap_is_not_verified(make_wheel, monkeypatch):
    # The cap is checked against bytes actually read, not the size the header claims.
    monkeypatch.setattr(scan, "MAX_MEMBER_BYTES", 10)
    path = make_wheel({"pkg/big.py": "x" * 11})
    _, findings = scan.read_archive(path)
    assert [f.rule_id for f in findings] == ["BKT-SKIP-002"]


def test_total_size_cap_is_not_verified(make_wheel, monkeypatch):
    monkeypatch.setattr(scan, "MAX_TOTAL_BYTES", 10)
    path = make_wheel({"pkg/a.py": "x" * 6, "pkg/b.py": "x" * 6})
    _, findings = scan.read_archive(path)
    assert [f.rule_id for f in findings] == ["BKT-SKIP-002"]
