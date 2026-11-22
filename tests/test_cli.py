import hashlib
import json
import os

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
    assert [(os.path.basename(a["path"]), a["verdict"]) for a in report["artifacts"]] == [
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


def test_write_allowlist_accepts_todays_findings_pinned_to_the_version(make_wheel, tmp_path):
    path = make_wheel({"pkg.pth": SHADOW})
    baseline = tmp_path / "allow.json"
    assert main(["scan", "--write-allowlist", str(baseline), str(path)]) == 0
    entries = json.loads(baseline.read_text(encoding="utf-8"))["allow"]
    assert [(e["rule"], e["package"], e["version"], e["file"]) for e in entries] == [
        ("BKT-PTH-002", "pkg", "1.0", "pkg.pth")
    ]
    assert all(e["reason"] for e in entries)
    assert main(["scan", "--allowlist", str(baseline), str(path)]) == 0
    newer = make_wheel({"pkg.pth": SHADOW}, name="pkg-1.1-py3-none-any.whl")
    assert main(["scan", "--allowlist", str(baseline), str(newer)]) == 1


def test_write_allowlist_keeps_reviewed_entries_and_never_accepts_a_coverage_gap(
    make_wheel, tmp_path
):
    reviewed = {"rule": "BKT-PTH-001", "package": "other", "reason": "reviewed by hand"}
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"allow": [reviewed]}), encoding="utf-8")
    broken = tmp_path / "bad-1.0-py3-none-any.whl"
    broken.write_bytes(b"nope")
    flagged = make_wheel({"pkg.pth": SHADOW})
    args = ["scan", "--allowlist", str(allow), "--write-allowlist", str(allow)]
    assert main([*args, str(flagged), str(broken)]) == 1  # not_verified still fails
    entries = json.loads(allow.read_text(encoding="utf-8"))["allow"]
    assert entries[0] == reviewed
    assert {e["rule"] for e in entries[1:]} == {"BKT-PTH-002"}


def test_text_report_says_what_clean_covers(make_wheel, capsys):
    assert main(["scan", str(make_wheel({"pkg/__init__.py": "x = 1\n"}))]) == 0
    assert "only runs when you call it is not read" in capsys.readouterr().out


def test_write_allowlist_escapes_glob_characters_in_file_names(make_wheel, tmp_path):
    path = make_wheel({"[x].pth": SHADOW, "*.pth": SHADOW})
    baseline = tmp_path / "allow.json"
    main(["scan", "--write-allowlist", str(baseline), str(path)])
    files = sorted(e["file"] for e in json.loads(baseline.read_text(encoding="utf-8"))["allow"])
    assert files == ["[*].pth", "[[]x].pth"]
    assert main(["scan", "--allowlist", str(baseline), str(path)]) == 0
    other = make_wheel({"[x].pth": SHADOW, "evil.pth": SHADOW})
    assert main(["scan", "--allowlist", str(baseline), str(other)]) == 1
