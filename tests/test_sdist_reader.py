import io
import tarfile

import pytest

from buckthorn import scan
from buckthorn.findings import verdict


def _tar(path, members, mode="w:gz"):
    with tarfile.open(path, mode) as tf:
        for name, data in members.items():
            if isinstance(data, str):
                data = data.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


@pytest.mark.parametrize(
    ("suffix", "mode"), [(".tar.gz", "w:gz"), (".tar.bz2", "w:bz2"), (".tar", "w")]
)
def test_reads_tar_members_in_memory(tmp_path, suffix, mode):
    path = _tar(tmp_path / f"pkg-1.0{suffix}", {"pkg-1.0/setup.py": "x = 1\n"}, mode)
    members, findings = scan.read_archive(path)
    assert members == [("pkg-1.0/setup.py", b"x = 1\n")]
    assert findings == []
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_zip_sdist_is_read_as_zip(tmp_path):
    import zipfile

    path = tmp_path / "pkg-1.0.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("pkg-1.0/setup.py", "x = 1\n")
    assert scan.read_archive(path)[0] == [("pkg-1.0/setup.py", b"x = 1\n")]


def test_corrupt_tar_is_not_verified(tmp_path):
    path = tmp_path / "pkg-1.0.tar.gz"
    path.write_bytes(b"\x1f\x8b" + b"garbage" * 10)
    members, findings = scan.read_archive(path)
    assert verdict(findings) == "not_verified"


def test_tar_member_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "MAX_MEMBERS", 2)
    path = _tar(tmp_path / "pkg-1.0.tar.gz", {f"pkg-1.0/m{i}": "" for i in range(3)})
    assert [f.rule_id for f in scan.read_archive(path)[1]] == ["BKT-SKIP-002"]


def test_tar_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "MAX_MEMBER_BYTES", 10)
    path = _tar(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/big": "x" * 11})
    assert [f.rule_id for f in scan.read_archive(path)[1]] == ["BKT-SKIP-002"]


def test_links_are_not_followed_and_not_verified(tmp_path):
    path = tmp_path / "pkg-1.0.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("pkg-1.0/setup.py")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    members, findings = scan.read_archive(path)
    assert members == []
    assert [f.rule_id for f in findings] == ["BKT-SKIP-004"]
    assert verdict(findings) == "not_verified"


def test_unknown_extension_is_not_verified(tmp_path):
    path = tmp_path / "pkg-1.0.rar"
    path.write_bytes(b"x")
    assert [f.rule_id for f in scan.read_archive(path)[1]] == ["BKT-SKIP-001"]
