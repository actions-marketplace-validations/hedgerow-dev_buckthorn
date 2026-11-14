import hashlib
import json

from buckthorn.cli import main

SHADOW = "import sys; sys.modules['collections'] = None\n"


def test_clean_wheel_exits_0(make_wheel, capsys):
    path = make_wheel({"pkg/__init__.py": "x = 1\n"})
    assert main(["scan", str(path)]) == 0
    assert "clean" in capsys.readouterr().out


def test_flagged_wheel_exits_1_and_says_why(make_wheel, capsys):
    path = make_wheel({"pkg.pth": SHADOW})
    assert main(["scan", str(path)]) == 1
    out = capsys.readouterr().out
    assert "flagged" in out
    assert "BKT-PTH-002" in out
    assert "pkg.pth" in out


def test_not_verified_exits_1_unless_allowed(tmp_path, capsys):
    path = tmp_path / "bad-1.0-py3-none-any.whl"
    path.write_bytes(b"nope")
    assert main(["scan", str(path)]) == 1
    assert "not_verified" in capsys.readouterr().out
    assert main(["scan", "--allow-not-verified", str(path)]) == 0


def test_missing_path_exits_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope.whl")]) == 2
    assert "nope.whl" in capsys.readouterr().err


def test_folder_scans_every_artifact_in_it(make_wheel, make_sdist, tmp_path, capsys):
    make_wheel({"pkg.pth": SHADOW})
    make_sdist({"setup.py": "from setuptools import setup\nsetup()\n"})
    (tmp_path / "notes.txt").write_text("not an artifact")
    assert main(["scan", "--format", "json", str(tmp_path)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert [(a["path"].rsplit("/", 1)[-1], a["verdict"]) for a in report["artifacts"]] == [
        ("pkg-1.0-py3-none-any.whl", "flagged"),
        ("pkg-1.0.tar.gz", "clean"),
    ]


def test_json_report_shape(make_wheel, capsys):
    path = make_wheel({"pkg.pth": SHADOW})
    main(["scan", "--format", "json", str(path)])
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "buckthorn"
    assert report["verdict"] == "flagged"
    (artifact,) = report["artifacts"]
    assert artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert artifact["findings"][0]["rule_id"] == "BKT-PTH-002"


def test_empty_folder_is_an_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == 2


def test_text_output_shows_the_first_line_of_a_code_finding(make_sdist, capsys):
    path = make_sdist({"setup.py": "import os\n\nos.system('x')\n"})
    main(["scan", str(path)])
    assert "pkg-1.0/setup.py:3" in capsys.readouterr().out


def test_text_hides_info_notes_but_counts_them(make_wheel, capsys):
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
    main(["scan", str(make_wheel({"pkg/helper": elf}))])
    out = capsys.readouterr().out
    assert "BKT-BIN-003" not in out
    assert "1 info note hidden" in out


def test_text_always_shows_coverage_gaps(tmp_path, capsys):
    path = tmp_path / "bad-1.0-py3-none-any.whl"
    path.write_bytes(b"nope")
    main(["scan", str(path)])
    assert "BKT-SKIP-001" in capsys.readouterr().out


def test_check_command_scans_a_lockfile(tmp_path, make_wheel, monkeypatch, capsys):
    from buckthorn import lock

    data = make_wheel({"pkg.pth": SHADOW}).read_bytes()
    url = "https://files.pythonhosted.org/packages/aa/pkg-1.0-py3-none-any.whl"
    sha = hashlib.sha256(data).hexdigest()
    index = {"urls": [{"filename": url.rsplit("/", 1)[1], "url": url, "digests": {"sha256": sha}}]}
    responses = {url: data, "https://pypi.org/pypi/pkg/1.0/json": json.dumps(index).encode()}
    monkeypatch.setattr(lock, "fetch_url", lambda u, n: responses[u])
    req = tmp_path / "requirements.txt"
    req.write_text(f"pkg==1.0 --hash=sha256:{sha}\n")
    assert main(["check", str(req)]) == 1
    captured = capsys.readouterr()
    assert "pkg-1.0-py3-none-any.whl: flagged" in captured.out
    assert "pkg-1.0-py3-none-any.whl" in captured.err  # progress


def test_check_rejects_an_unknown_lockfile(tmp_path, capsys):
    path = tmp_path / "Pipfile.lock"
    path.write_text("{}")
    assert main(["check", str(path)]) == 2


def test_check_takes_several_lockfiles_and_sarif_points_at_each(tmp_path, capsys):
    a = tmp_path / "a" / "requirements.txt"
    b = tmp_path / "b" / "requirements.txt"
    for path in (a, b):
        path.parent.mkdir()
        path.write_text("unpinned>=1\n")
    assert main(["check", "--format", "sarif", str(a), str(b)]) == 1
    run = json.loads(capsys.readouterr().out)["runs"][0]
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
    ]
    assert uris == [str(a), str(b)]


def test_text_report_survives_a_console_that_cannot_encode_a_name(make_wheel, monkeypatch):
    # Windows consoles and pipes often use cp1252: a package's own file name
    # must not crash the report.
    import io
    import sys

    path = make_wheel({"文件.pth": SHADOW})
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    assert main(["scan", str(path)]) == 1
    out.flush()
    assert b"BKT-PTH" in out.buffer.getvalue()
