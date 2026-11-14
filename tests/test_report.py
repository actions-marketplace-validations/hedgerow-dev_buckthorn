import json

import pytest

from buckthorn.cli import main

SHADOW = "import sys; sys.modules['collections'] = None\n"


def _allowlist(tmp_path, entries):
    path = tmp_path / "allow.json"
    path.write_text(json.dumps({"allow": entries}))
    return path


@pytest.fixture
def setuptools_like(make_wheel):
    return make_wheel(
        {"distutils-precedence.pth": "import os; os.environ.get('X')\n"},
        "setuptools-80.0-py3-none-any.whl",
    )


def test_allowlisted_finding_no_longer_fails(tmp_path, setuptools_like, capsys):
    allow = _allowlist(
        tmp_path,
        [
            {
                "rule": "BKT-PTH-001",
                "package": "setuptools",
                "file": "distutils-precedence.pth",
                "reason": "setuptools' distutils shim",
            }
        ],
    )
    assert main(["scan", str(setuptools_like)]) == 1
    capsys.readouterr()
    assert main(["scan", "--allowlist", str(allow), str(setuptools_like)]) == 0
    out = capsys.readouterr().out
    assert "BKT-PTH-001" not in out
    assert "1 finding allowed by the allowlist" in out


def test_json_lists_what_was_allowed_and_why(tmp_path, setuptools_like, capsys):
    allow = _allowlist(
        tmp_path, [{"rule": "BKT-PTH-001", "package": "setuptools", "reason": "shim"}]
    )
    main(["scan", "--format", "json", "--allowlist", str(allow), str(setuptools_like)])
    (artifact,) = json.loads(capsys.readouterr().out)["artifacts"]
    assert artifact["findings"] == []
    assert artifact["allowed"][0]["rule_id"] == "BKT-PTH-001"
    assert artifact["allowed"][0]["reason"] == "shim"


@pytest.mark.parametrize(
    "entry",
    [
        {"rule": "BKT-PTH-002", "package": "setuptools", "reason": "x"},  # other rule
        {"rule": "BKT-PTH-001", "package": "other", "reason": "x"},  # other package
        {"rule": "BKT-PTH-001", "package": "setuptools", "file": "x.pth", "reason": "x"},
        {"rule": "BKT-PTH-001", "package": "setuptools", "version": "79.0", "reason": "x"},
    ],
)
def test_entries_that_do_not_match_do_not_allow(tmp_path, setuptools_like, entry):
    assert (
        main(["scan", "--allowlist", str(_allowlist(tmp_path, [entry])), str(setuptools_like)]) == 1
    )


def test_package_names_are_normalised(tmp_path, make_wheel):
    wheel = make_wheel({"x.pth": "import os\n"}, "my_pkg-1.0-py3-none-any.whl")
    allow = _allowlist(tmp_path, [{"rule": "BKT-PTH-001", "package": "My.Pkg", "reason": "ok"}])
    assert main(["scan", "--allowlist", str(allow), str(wheel)]) == 0


def test_file_patterns_and_version_folders(tmp_path, make_sdist):
    sdist = make_sdist({"setup.py": "import os\nos.system('make')\n"}, "pkg-2.0.tar.gz")
    allow = _allowlist(
        tmp_path,
        [{"rule": "BKT-INSTALL-002", "package": "pkg", "file": "*/setup.py", "reason": "builds C"}],
    )
    assert main(["scan", "--allowlist", str(allow), str(sdist)]) == 0


@pytest.mark.parametrize(
    "entry",
    [
        {"rule": "BKT-PTH-001", "package": "setuptools"},  # no reason
        {"rule": "BKT-PTH-001", "package": "setuptools", "reason": "  "},
        {"package": "setuptools", "reason": "x"},  # no rule
        {"rule": "BKT-PTH-001", "reason": "x"},  # no package
    ],
)
def test_bad_allowlist_entries_are_an_error(tmp_path, setuptools_like, entry, capsys):
    assert (
        main(["scan", "--allowlist", str(_allowlist(tmp_path, [entry])), str(setuptools_like)]) == 2
    )
    assert "allowlist" in capsys.readouterr().err


def test_coverage_gaps_cannot_be_allowlisted(tmp_path, capsys):
    bad = tmp_path / "pkg-1.0-py3-none-any.whl"
    bad.write_bytes(b"nope")
    allow = _allowlist(tmp_path, [{"rule": "BKT-SKIP-001", "package": "pkg", "reason": "x"}])
    assert main(["scan", "--allowlist", str(allow), str(bad)]) == 2


def test_sarif_output(make_wheel, capsys):
    wheel = make_wheel({"pkg.pth": SHADOW})
    assert main(["scan", "--format", "sarif", str(wheel)]) == 1
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    (run,) = sarif["runs"]
    assert run["tool"]["driver"]["name"] == "buckthorn"
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["BKT-PTH-002"]
    (result,) = run["results"]
    assert result["ruleId"] == "BKT-PTH-002"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(wheel)
    assert "pkg.pth" in result["message"]["text"]


def test_sarif_leaves_out_info_notes(make_wheel, capsys):
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
    main(["scan", "--format", "sarif", str(make_wheel({"pkg/helper": elf}))])
    assert json.loads(capsys.readouterr().out)["runs"][0]["results"] == []


def test_output_writes_the_report_to_a_file(tmp_path, make_wheel, capsys):
    out = tmp_path / "report.sarif"
    assert (
        main(
            [
                "scan",
                "--format",
                "sarif",
                "--output",
                str(out),
                str(make_wheel({"pkg.pth": SHADOW})),
            ]
        )
        == 1
    )
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert str(out) in capsys.readouterr().out


def test_precommit_hook_files_pattern_matches_what_check_reads():
    import re
    from pathlib import Path

    text = (Path(__file__).parent.parent / ".pre-commit-hooks.yaml").read_text()
    pattern = re.search(r"files: '([^']+)'", text)[1]
    for name in [
        "uv.lock",
        "poetry.lock",
        "requirements.txt",
        "requirements-dev.txt",
        "sub/uv.lock",
    ]:
        assert re.search(pattern, name), name
    for name in ["Pipfile.lock", "requirements.in.bak", "notes.txt", "uv.lock.orig"]:
        assert not re.search(pattern, name), name
