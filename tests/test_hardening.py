"""Inputs built to crash the scanner or hang it: each must end quickly with a result."""

import io
import os
import tarfile
import time

import pytest

from buckthorn.cli import main
from buckthorn.code import PIPE_TO_SHELL
from buckthorn.env import scan_env
from buckthorn.findings import verdict
from buckthorn.npm import _BUILD_COMMAND
from buckthorn.scan import scan_sdist, scan_wheel

DEEP_TOML = "a = " + "[" * 5000 + "]" * 5000 + "\n"


def _quick(fn, *args):
    start = time.monotonic()
    result = fn(*args)
    assert time.monotonic() - start < 1
    return result


def test_build_command_regex_is_not_exponential():
    assert _quick(_BUILD_COMMAND.fullmatch, "node-gyp rebuild" + " --a" * 40 + " !") is None
    assert _BUILD_COMMAND.fullmatch("node-gyp rebuild --release -j 4")


def test_pipe_to_shell_regex_is_not_quadratic():
    assert _quick(PIPE_TO_SHELL.search, "curl " * 30000) is None
    assert PIPE_TO_SHELL.search("curl -s https://x | sudo bash")
    assert PIPE_TO_SHELL.search("curl a | grep b | sh")


def _sdist(path, members):
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(f"pkg-1.0/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def test_deeply_nested_pyproject_is_a_coverage_gap(tmp_path):
    members = {
        "PKG-INFO": b"Name: pkg\nVersion: 1.0\n",
        "pyproject.toml": DEEP_TOML.encode(),
        "setup.py": b"from setuptools import setup\nsetup()\n",
    }
    findings = scan_sdist(_sdist(tmp_path / "pkg-1.0.tar.gz", members))
    assert verdict(findings) != "clean"


@pytest.mark.parametrize(
    "name, text",
    [("uv.lock", DEEP_TOML), ("poetry.lock", DEEP_TOML), ("mcp.json", "[" * 100000)],
    ids=["uv", "poetry", "mcp"],
)
def test_deeply_nested_lock_or_config_is_bad_input(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    assert main(["check", str(path)]) == 2


def test_wheel_record_with_a_huge_field_is_flagged(make_wheel):
    record = "pkg/__init__.py," + "x" * 200_000 + ",0\n"
    path = make_wheel({"pkg/__init__.py": "", "pkg-1.0.dist-info/RECORD": record})
    assert verdict(scan_wheel(path)) == "flagged"


def test_installed_record_with_a_huge_field_is_a_coverage_gap(tmp_path):
    (tmp_path / "pyvenv.cfg").write_text("home = /usr/bin\n")
    dist_info = tmp_path / "lib" / "python3.13" / "site-packages" / "pkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text("Name: pkg\nVersion: 1.0\n")
    (dist_info / "RECORD").write_text("pkg/__init__.py," + "x" * 200_000 + ",0\n")
    rules = {f.rule_id for result in scan_env(tmp_path) for f in result.findings}
    assert "BKT-SKIP-005" in rules


@pytest.mark.parametrize("nofollow", [True, False], ids=["O_NOFOLLOW", "no-O_NOFOLLOW"])
@pytest.mark.parametrize("flag", ["--output", "--receipt", "--write-allowlist"])
def test_reports_are_not_written_through_a_symlink(
    make_wheel, tmp_path, monkeypatch, flag, nofollow
):
    if not nofollow:  # Windows has no O_NOFOLLOW
        monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    victim = tmp_path / "victim.sh"
    victim.write_text("echo hi\n")
    link = tmp_path / "report.out"
    link.symlink_to(victim)
    assert main(["scan", flag, str(link), str(make_wheel({"pkg/__init__.py": ""}))]) == 2
    assert victim.read_text() == "echo hi\n"


def test_reports_are_still_written_to_a_plain_path(make_wheel, tmp_path):
    out = tmp_path / "report.sarif"
    out.write_text("old")
    assert main(["scan", "--format", "sarif", "--output", str(out), str(make_wheel({}))]) == 0
    assert out.read_text().startswith("{")
