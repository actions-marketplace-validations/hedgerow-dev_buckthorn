import hashlib
import json

from buckthorn.cli import main

SHADOW = "import sys; sys.modules['collections'] = None\n"


def test_receipt_records_each_artifact_by_hash(tmp_path, make_wheel, make_sdist, capsys):
    wheel = make_wheel({"pkg.pth": SHADOW})
    sdist = make_sdist({"setup.py": "from setuptools import setup\nsetup()\n"})
    receipt = tmp_path / "receipt.intoto.json"
    assert main(["scan", "--receipt", str(receipt), str(wheel), str(sdist)]) == 1
    statement = json.loads(receipt.read_text())
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://hedgerow.dev/buckthorn/scan-receipt/v1"
    assert statement["subject"] == [
        {"name": wheel.name, "digest": {"sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}},
        {"name": sdist.name, "digest": {"sha256": hashlib.sha256(sdist.read_bytes()).hexdigest()}},
    ]
    predicate = statement["predicate"]
    assert predicate["scanner"]["name"] == "buckthorn"
    assert predicate["artifacts"][wheel.name] == {
        "verdict": "flagged",
        "rules": ["BKT-PTH-002"],
        "coverage_gaps": [],
    }
    assert predicate["artifacts"][sdist.name]["verdict"] == "clean"
    assert "not a safety certificate" in predicate["note"]


def test_receipt_is_taken_before_the_allowlist(tmp_path, make_wheel):
    wheel = make_wheel({"pkg.pth": SHADOW})
    allow = tmp_path / "allow.json"
    allow.write_text(
        json.dumps({"allow": [{"rule": "BKT-PTH-002", "package": "pkg", "reason": "x"}]})
    )
    receipt = tmp_path / "r.json"
    assert main(["scan", "--allowlist", str(allow), "--receipt", str(receipt), str(wheel)]) == 0
    predicate = json.loads(receipt.read_text())["predicate"]
    assert predicate["artifacts"][wheel.name]["rules"] == ["BKT-PTH-002"]


def test_receipt_records_coverage_gaps(tmp_path):
    bad = tmp_path / "bad-1.0-py3-none-any.whl"
    bad.write_bytes(b"nope")
    receipt = tmp_path / "r.json"
    main(["scan", "--receipt", str(receipt), str(bad)])
    entry = json.loads(receipt.read_text())["predicate"]["artifacts"][bad.name]
    assert entry == {"verdict": "not_verified", "rules": [], "coverage_gaps": ["BKT-SKIP-001"]}


def test_results_without_an_artifact_hash_are_not_subjects(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("unpinned>=1\n")
    receipt = tmp_path / "r.json"
    main(["check", "--receipt", str(receipt), str(req)])
    statement = json.loads(receipt.read_text())
    assert statement["subject"] == []
    assert statement["predicate"]["artifacts"] == {}


def test_receipt_is_refused_for_diff_and_env(tmp_path, make_wheel, capsys):
    old = make_wheel({"a.py": ""}, "pkg-1.0-py3-none-any.whl")
    new = make_wheel({"a.py": ""}, "pkg-1.1-py3-none-any.whl")
    receipt = tmp_path / "r.json"
    assert main(["diff", "--receipt", str(receipt), str(old), str(new)]) == 2
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "x-1.0.dist-info").mkdir()
    assert main(["env", "--receipt", str(receipt), str(site)]) == 2
    assert not receipt.exists()


def test_pins_never_downloaded_are_not_subjects(tmp_path, monkeypatch):
    from buckthorn import lock

    def offline(url, max_bytes):
        raise lock.FetchError("offline")

    monkeypatch.setattr(lock, "fetch_url", offline)
    path = tmp_path / "uv.lock"
    url = "https://files.pythonhosted.org/packages/aa/pkg-1.0-py3-none-any.whl"
    path.write_text(
        'version = 1\n[[package]]\nname = "pkg"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        f'wheels = [{{ url = "{url}", hash = "sha256:{"a" * 64}" }}]\n'
    )
    receipt = tmp_path / "r.json"
    main(["check", "--receipt", str(receipt), str(path)])
    assert json.loads(receipt.read_text())["subject"] == []


def test_two_artifacts_with_one_name_are_refused(tmp_path, make_wheel):
    first = make_wheel({"a.py": "x = 1\n"})
    other = tmp_path / "b"
    other.mkdir()
    second = other / first.name
    second.write_bytes(make_wheel({"a.py": "x = 2\n"}, "other-1.0-py3-none-any.whl").read_bytes())
    receipt = tmp_path / "r.json"
    assert main(["scan", "--receipt", str(receipt), str(first), str(second)]) == 2
    assert not receipt.exists()
