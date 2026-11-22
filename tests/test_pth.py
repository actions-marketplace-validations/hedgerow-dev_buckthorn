import os

import pytest

from buckthorn.findings import verdict
from buckthorn.scan import scan_sdist, scan_wheel

SHADOW = "import sys, _evil; sys.modules['collections'] = _evil\n"
# Shape of setuptools' distutils-precedence.pth: imports, but swaps nothing itself.
PLAIN_IMPORT = "import os; os.environ.get('X') == '1' and __import__('_shim').install()\n"


def _rules(findings):
    return sorted(f.rule_id for f in findings)


def test_path_only_pth_is_clean(make_wheel):
    path = make_wheel({"pkg.pth": "/opt/extra\n# comment\n"})
    assert scan_wheel(path) == []


def test_pth_import_line_fires(make_wheel):
    findings = scan_wheel(make_wheel({"pkg.pth": PLAIN_IMPORT}))
    assert _rules(findings) == ["BKT-PTH-001"]
    assert verdict(findings) == "flagged"


def test_pth_swapping_modules_fires_high(make_wheel):
    findings = scan_wheel(make_wheel({"pkg.pth": SHADOW}))
    assert _rules(findings) == ["BKT-PTH-002"]
    assert findings[0].severity.value == "high"


def test_pth_in_data_purelib_counts(make_wheel):
    findings = scan_wheel(make_wheel({"pkg-1.0.data/purelib/x.pth": SHADOW}))
    assert _rules(findings) == ["BKT-PTH-002"]


def test_pth_inside_a_package_folder_is_not_run_by_site(make_wheel):
    # site.py only processes .pth files at the top of site-packages.
    assert scan_wheel(make_wheel({"pkg/data/x.pth": SHADOW})) == []


def test_tab_after_import_still_runs(make_wheel):
    findings = scan_wheel(make_wheel({"pkg.pth": "import\tos\n"}))
    assert _rules(findings) == ["BKT-PTH-001"]


def test_unreadable_wheel_is_not_verified(tmp_path):
    path = tmp_path / "bad-1.0-py3-none-any.whl"
    path.write_bytes(b"nope")
    assert verdict(scan_wheel(path)) == "not_verified"


def test_every_copy_of_a_duplicated_member_is_checked(tmp_path):
    import warnings
    import zipfile

    path = tmp_path / "pkg-1.0-py3-none-any.whl"
    with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as zf:
        warnings.simplefilter("ignore")  # zipfile warns on duplicate names
        zf.writestr("pkg.pth", SHADOW)
        zf.writestr("pkg.pth", "/opt/extra\n")
    assert "BKT-PTH-002" in _rules(scan_wheel(path))


def test_dotted_paths_that_land_at_the_top_still_count(make_wheel):
    path = make_wheel({"./a.pth": SHADOW, "pkg/../b.pth": SHADOW, "pkg\\c.pth": "/x\n"})
    findings = scan_wheel(path)
    assert sorted(f.file_path for f in findings) == ["./a.pth", "pkg/../b.pth"]


def test_backslash_names_read_the_same_on_windows(make_wheel, monkeypatch):
    """zipfile turns \\ into / when os.sep is \\. pip on Linux keeps it, so read the raw name."""
    path = make_wheel({"pkg\\x.pth": SHADOW})
    linux = [(f.rule_id, f.file_path) for f in scan_wheel(path)]
    monkeypatch.setattr(os, "sep", "\\")
    assert [(f.rule_id, f.file_path) for f in scan_wheel(path)] == linux
    assert ("BKT-PTH-002", "pkg\\x.pth") in linux


# An sdist's setup.py, build backend or their config can put any file it ships at
# the top of site-packages, where its import lines run on every start.
TELEMETRY_SETUP = """\
import os, shutil, site
from setuptools import setup
from setuptools.command.install import install

class _Install(install):
    def run(self):
        install.run(self)
        sp = self.install_lib or site.getsitepackages()[0]
        shutil.copy2(os.path.join(os.path.dirname(__file__), "telemetry.pth"), sp)

setup(name="pkg", version="1.0", cmdclass={"install": _Install})
"""
BARE_SETUP = "from setuptools import setup\nsetup()\n"


def _sdist_pth(make_sdist, members):
    findings = scan_sdist(make_sdist(members))
    return [f for f in findings if f.rule_id.startswith("BKT-PTH-")]


@pytest.mark.parametrize(
    "setup_py",
    [
        "from setuptools import setup\nsetup(data_files=[('', ['telemetry.pth'])])\n",
        "import sysconfig\nfrom setuptools import setup\n"
        "setup(data_files=[(sysconfig.get_paths()['purelib'], ['telemetry.pth'])])\n",
        TELEMETRY_SETUP,
    ],
    ids=["data_files_prefix", "data_files_purelib", "copy_in_install_command"],
)
def test_sdist_pth_installed_by_setup_py_fires(make_sdist, setup_py):
    members = {"setup.py": setup_py, "telemetry.pth": "import _telemetry_init\n"}
    findings = _sdist_pth(make_sdist, members)
    assert _rules(findings) == ["BKT-PTH-001"]
    assert findings[0].file_path == "pkg-1.0/telemetry.pth"
    assert verdict(findings) == "flagged"


def test_sdist_pth_swapping_builtins_fires_high(make_sdist):
    line = "import builtins, _p; builtins.open = _p.open\n"
    findings = _sdist_pth(make_sdist, {"setup.py": TELEMETRY_SETUP, "telemetry.pth": line})
    assert _rules(findings) == ["BKT-PTH-002"]
    assert findings[0].severity.value == "high"


def test_sdist_pth_named_in_pyproject_data_files_fires(make_sdist):
    toml = (
        '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
        '[tool.setuptools.data-files]\n"." = ["pkg/evil.pth"]\n'
    )
    findings = _sdist_pth(make_sdist, {"pyproject.toml": toml, "pkg/evil.pth": SHADOW})
    assert _rules(findings) == ["BKT-PTH-002"]


def test_sdist_path_only_pth_is_clean(make_sdist):
    setup_py = "from setuptools import setup\nsetup(data_files=[('', ['paths.pth'])])\n"
    assert scan_sdist(make_sdist({"setup.py": setup_py, "paths.pth": "/opt/extra\n"})) == []


def test_sdist_pth_shipped_but_not_named_is_still_checked(make_sdist):
    # A name built at run time, glob('*') or os.listdir can install it unnamed.
    findings = _sdist_pth(make_sdist, {"setup.py": BARE_SETUP, "pkg/x.pth": PLAIN_IMPORT})
    assert _rules(findings) == ["BKT-PTH-001"]


def test_sdist_pth_test_fixture_is_not_checked(make_sdist):
    members = {
        "setup.py": BARE_SETUP,
        "tests/data/site-packages/x.pth": PLAIN_IMPORT,
        "pkg/tests/x.pth": PLAIN_IMPORT,
    }
    assert _sdist_pth(make_sdist, members) == []


@pytest.mark.parametrize(
    ("config", "text"),
    [
        ("setup.py", "import glob, setuptools\nsetuptools.setup(data_files=glob.glob('*/*.pth'))"),
        ("setup.cfg", "[options.data_files]\n. = tests/x.pth\n"),
        ("pyproject.toml", '[tool.hatch.build.targets.wheel.force-include]\n"tests/x.pth" = "a"'),
    ],
)
def test_sdist_pth_in_a_test_folder_counts_when_install_mentions_pth(make_sdist, config, text):
    findings = _sdist_pth(make_sdist, {config: text, "tests/x.pth": PLAIN_IMPORT})
    assert _rules(findings) == ["BKT-PTH-001"]


def test_sdist_install_code_writing_a_pth_line_fires(make_sdist):
    setup_py = (
        "import os, site\nfrom setuptools import setup\n"
        "sp = site.getsitepackages()[0]\n"
        "with open(os.path.join(sp, 'x.pth'), 'w') as f:\n"
        '    f.write(\'import sys; sys.modules["json"] = __import__("_evil")\\n\')\n'
        "setup()\n"
    )
    findings = _sdist_pth(make_sdist, {"setup.py": setup_py})
    assert _rules(findings) == ["BKT-PTH-002"]
    assert findings[0].file_path == "pkg-1.0/setup.py"
    assert findings[0].metadata == {"line": 5}


def test_sdist_install_code_writing_a_pth_line_from_an_f_string_fires(make_sdist):
    setup_py = "mod = '_evil'\nopen('x.pth', 'w').write(f'import {mod}')\n" + BARE_SETUP
    assert _rules(_sdist_pth(make_sdist, {"setup.py": setup_py})) == ["BKT-PTH-001"]


def test_sdist_code_handed_to_python_c_is_not_a_pth_line(make_sdist):
    # poetry-core 2.5.0's wheel builder: it names .pth, and runs snippets with -c.
    setup_py = (
        "import subprocess, sys\npth = 'x.pth'\n"
        "subprocess.check_output([sys.executable, '-c', '''\nimport sysconfig\n'''])\n"
        "subprocess.check_output((sys.executable, '-c', f'''\nimport {pth}\n'''))\n" + BARE_SETUP
    )
    assert _sdist_pth(make_sdist, {"setup.py": setup_py}) == []


def test_sdist_c_outside_a_process_call_still_reads_as_a_pth_line(make_sdist):
    setup_py = "line = ('-c', 'import _evil')[1]\nopen('x.pth', 'w').write(line)\n" + BARE_SETUP
    assert _rules(_sdist_pth(make_sdist, {"setup.py": setup_py})) == ["BKT-PTH-001"]


def test_sdist_pth_line_written_inside_a_c_argument_still_counts(make_sdist):
    setup_py = (
        "import subprocess, sys\n"
        "subprocess.run([sys.executable, '-c', (open('x.pth', 'w').write('import _e'), '')[1]])\n"
        + BARE_SETUP
    )
    assert _rules(_sdist_pth(make_sdist, {"setup.py": setup_py})) == ["BKT-PTH-001"]


def test_sdist_import_strings_without_a_pth_mention_are_not_pth_lines(make_sdist):
    setup_py = "exec('import os')\n" + BARE_SETUP
    assert _sdist_pth(make_sdist, {"setup.py": setup_py}) == []


def test_sdist_pth_mentioned_only_in_a_local_install_module_counts(make_sdist):
    members = {
        "setup.py": "from setuptools import setup\nfrom _build import Install\n" + BARE_SETUP,
        "_build.py": "PTH = 'tests/x.pth'\nclass Install:\n    pass\n",
        "tests/x.pth": PLAIN_IMPORT,
    }
    assert _rules(_sdist_pth(make_sdist, members)) == ["BKT-PTH-001"]
