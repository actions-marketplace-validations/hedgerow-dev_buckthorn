import base64
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest


def record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@pytest.fixture
def make_wheel(tmp_path: Path):
    """Write a wheel holding the given {member name: text or bytes}.

    Adds a matching METADATA and a correct RECORD unless the test passes its
    own, so rule tests see an otherwise well-formed wheel.
    """

    def _make(
        members: dict[str, str | bytes],
        name: str = "pkg-1.0-py3-none-any.whl",
        record: bool = True,
    ) -> Path:
        dist, version = name.split("-")[:2]
        dist_info = f"{dist}-{version}.dist-info"
        files = {k: v.encode() if isinstance(v, str) else v for k, v in members.items()}
        files.setdefault(f"{dist_info}/METADATA", f"Name: {dist}\nVersion: {version}\n".encode())
        if record and f"{dist_info}/RECORD" not in files:
            lines = [f"{member},{record_hash(data)},{len(data)}" for member, data in files.items()]
            files[f"{dist_info}/RECORD"] = (
                "\n".join(lines + [f"{dist_info}/RECORD,,"]) + "\n"
            ).encode()
        path = tmp_path / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for member, data in files.items():
                if "\\" in member:  # zipfile turns \ into / on Windows: keep the name as given
                    info = zipfile.ZipInfo(member)
                    info.filename = member
                    zf.writestr(info, data, zipfile.ZIP_DEFLATED)
                else:
                    zf.writestr(member, data)
        return path

    return _make


@pytest.fixture
def make_sdist(tmp_path: Path):
    """Write pkg-1.0.tar.gz with the given members under pkg-1.0/, plus a matching PKG-INFO."""

    def _make(members: dict[str, str | bytes], name: str = "pkg-1.0.tar.gz") -> Path:
        top = name.removesuffix(".tar.gz")
        dist, version = top.rsplit("-", 1)
        files = {f"{top}/{k}": v.encode() if isinstance(v, str) else v for k, v in members.items()}
        files.setdefault(f"{top}/PKG-INFO", f"Name: {dist}\nVersion: {version}\n".encode())
        path = tmp_path / name
        with tarfile.open(path, "w:gz") as tf:
            for member, data in files.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return path

    return _make


def pytest_collection_modifyitems(items):
    """A test id is set as PYTEST_CURRENT_TEST, and Windows caps that at 32,767 characters.
    Long ids also flood every traceback. Give big parameters an `ids=`."""
    long = [item.nodeid[:100] for item in items if len(item.nodeid) > 2000]
    if long:
        raise pytest.UsageError(f"test ids too long, give them ids=: {long}")
