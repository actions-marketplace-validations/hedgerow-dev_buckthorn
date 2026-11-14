"""Find what a Python file would do if it ran, by reading its syntax tree.

The source is parsed with `ast` and never imported, compiled to bytecode or
run. Calls are matched by the dotted name they resolve to through the file's
own imports, so `import subprocess as sp; sp.run()` is still subprocess.run.
"""

from __future__ import annotations

import ast
import base64
import binascii
import contextlib
import math
import re
import sys
import warnings
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    # network, process, exec, secrets, environ, persistence: what the code does.
    # hidden: exec of decoded data. encoded: a long encoded blob fed to a decoder.
    # discord, telegram: a messenger channel with its secret in a string constant.
    # exec_file: exec of a named local file, detail is its path, for the caller to read.
    kind: str
    line: int
    detail: str


_NETWORK_CALLS = frozenset(
    {
        "socket.create_connection",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib.urlopen",
        "urllib.urlretrieve",
        "urllib2.urlopen",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.options",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.request",
        "httpx.stream",
        "urllib3.request",
        "aiohttp.request",
        "ftplib.FTP",
        "ftplib.FTP_TLS",
        "smtplib.SMTP",
        "smtplib.SMTP_SSL",
        "telnetlib.Telnet",
        "websocket.create_connection",
        "websockets.connect",
    }
)

# Client objects: building one connects nothing (dill makes a socket at import,
# sentry_sdk and posthog build HTTP clients). A call on one, such as
# Session().get or PoolManager().request, is the network access.
_CLIENTS = frozenset(
    {
        "socket.socket",
        "requests.Session",
        "requests.session",
        "httpx.Client",
        "httpx.AsyncClient",
        "urllib3.PoolManager",
        "urllib3.ProxyManager",
        "aiohttp.ClientSession",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "paramiko.SSHClient",
        "pycurl.Curl",
        # build_opener(...).open(url) fetches as urlopen does.
        "urllib.request.build_opener",
        "urllib2.build_opener",
    }
)
# Calls that open a file for reading, for `with open(p) as f: exec(f.read())`.
_OPENERS = frozenset({"open", "io.open", "codecs.open"})
# Calls on a client object that set it up or tear it down, not use it.
_CLIENT_SETUP = frozenset(
    {"close", "mount", "settimeout", "setsockopt", "setblocking", "bind", "add_handler"}
)

_PROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.startfile",
        "os.posix_spawn",
        "os.posix_spawnp",
        "pty.spawn",
        "commands.getoutput",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        # pip run from install code installs whatever it is told to.
        "pip.main",
        "pip._internal.main",
        "pip._internal.cli.main.main",
    }
)
_PROCESS_PREFIXES = ("os.exec", "os.spawn")

# In a command line handed to a process call: a download tool or a URL.
FETCHING_COMMAND = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|certutil|bitsadmin)\b|https?://",
    re.IGNORECASE,
)

# A shell command that downloads code and runs it: curl ... | sh, $(curl ...), irm ... | iex.
_DOWNLOAD = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)"
PIPE_TO_SHELL = re.compile(
    rf"\b{_DOWNLOAD}\b[^\n;&]*\|\s*(?:sudo\s+)?"
    r"(?:sh|bash|zsh|dash|ksh|python[0-9.]*|node|perl|ruby|iex|invoke-expression)\b"
    rf"|\$\(\s*{_DOWNLOAD}\b|<\(\s*{_DOWNLOAD}\b|`\s*{_DOWNLOAD}\b|\biex\s*\(\s*{_DOWNLOAD}\b",
    re.IGNORECASE,
)

_EXEC_CALLS = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "execfile",
        "builtins.exec",
        "builtins.eval",
        "builtins.compile",
    }
)

# Calls that turn data back into code-shaped text or bytes.
_DECODERS = frozenset(
    {
        "base64.b64decode",
        "base64.b32decode",
        "base64.b16decode",
        "base64.a85decode",
        "base64.b85decode",
        "base64.urlsafe_b64decode",
        "base64.decodebytes",
        "base64.decodestring",
        "binascii.unhexlify",
        "binascii.a2b_base64",
        "binascii.a2b_hex",
        "zlib.decompress",
        "gzip.decompress",
        "bz2.decompress",
        "lzma.decompress",
        "marshal.loads",
        "codecs.decode",
        "bytes.fromhex",
        "bytearray.fromhex",
    }
)
# Names that, fetched with getattr by string, are a way round reading as exec.
_HIDDEN_NAMES = frozenset({"exec", "eval", "compile", "system", "popen", "__import__"})
# Builtins that build a string from literals: "".join(map(chr, codes)).
_BUILDERS = frozenset(
    {"chr", "ord", "str", "bytes", "bytearray", "map", "reversed", "list", "tuple", "int"}
)
# Modules whose functions only build or decode strings: operator.add("ex", "ec").
_STRING_MODULES = frozenset(
    {"operator", "functools", "itertools", "string", "codecs", "base64", "binascii", "zlib"}
)
# str methods whose result is the string itself, trimmed or recased.
_TRIMS = frozenset(
    {"removeprefix", "removesuffix", "strip", "lstrip", "rstrip", "lower", "upper", "casefold"}
)
_ENCODED_MIN_LENGTH = 512
_ENCODED_ALPHABET = re.compile(r"^[A-Za-z0-9+/=_\-\r\n]+$")
_ENCODED_MIN_ENTROPY = 3.5  # bits per character; base64 of random bytes is about 6, hex 4

# Kinds only call-time combinations use. analyse() leaves them out.
_CALL_ONLY = frozenset({"decode", "names_persistence", "runs_written", "fetch_run", "redirect"})
# Calls that load a module or native library from a file path: running a file.
_LOADERS = frozenset(
    {
        "ctypes.CDLL",
        "ctypes.WinDLL",
        "ctypes.PyDLL",
        "ctypes.cdll.LoadLibrary",
        "ctypes.windll.LoadLibrary",
        "importlib.util.spec_from_file_location",
        "importlib.machinery.SourceFileLoader",
        "imp.load_source",
        "imp.load_dynamic",
        "imp.load_compiled",
        "runpy.run_path",
    }
)
# Calls that write a file to the path in their second argument.
_COPIES = frozenset(
    {
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.move",
        "urllib.request.urlretrieve",
        "urllib.urlretrieve",
    }
)

_ENVIRON_BULK_CALLS = frozenset(
    {
        "os.environ.copy",
        "os.environ.items",
        "os.environ.keys",
        "os.environ.values",
    }
)

# Paths only count when passed to a call: a module that names ~/.aws/config
# in a constant and opens it inside a function is not reading it at import.
_SECRET_PATH = re.compile(
    r"(?:^|[/\\~])\.(?:ssh|aws|gnupg|kube|docker|netrc|git-credentials|pypirc|npmrc)(?:[/\\]|$)"
    r"|\.config[/\\]gcloud"
    r"|(?:^|[/\\])(?:id_rsa|id_ed25519|id_ecdsa|Login Data|logins\.json|key4\.db|wallet\.dat)"
    r"(?:$|[/\\.])"
)
# Calls that only build or test a path. A credential path inside nothing but
# these is a path, not a read: botocore builds ~/.aws/... at import, opens it later.
_PATH_BUILDERS = frozenset(
    {
        "os.path.join",
        "os.path.expanduser",
        "os.path.expandvars",
        "os.path.abspath",
        "os.path.normpath",
        "os.path.realpath",
        "os.path.dirname",
        "os.path.exists",
        "os.path.isfile",
        "os.path.isdir",
        "os.fspath",
        "str",
        "pathlib.Path",
        "pathlib.PurePath",
        "pathlib.Path.home",
        # A default value or a pattern names a path without opening it.
        "os.environ.get",
        "os.getenv",
        "re.compile",
        "re.match",
        "re.search",
        "re.fullmatch",
        # A collection only holds the path: SKIP = frozenset({"LaunchAgents", ...}).
        "set",
        "frozenset",
        "tuple",
        "list",
        "dict",
        # Path methods, recorded by method name: Path("~/.ssh/config").expanduser().
        ".expanduser",
        ".resolve",
        ".absolute",
        ".joinpath",
        ".exists",
        ".is_file",
        ".is_dir",
        ".with_name",
        ".with_suffix",
        ".as_posix",
    }
)
_PERSISTENCE_PATH = re.compile(
    r"(?:^|[/\\~])\.(?:bashrc|bash_profile|zshrc|zprofile|zshenv|profile)$"
    r"|LaunchAgents|LaunchDaemons|/etc/cron|/var/spool/cron|(?:^|\s)crontab(?:\s|$)"
    r"|systemd[/\\]user|\.config[/\\]autostart"
    r"|Start Menu\\Programs\\Startup|CurrentVersion\\Run",
    re.IGNORECASE,
)
# A live messenger channel in a string constant: whoever holds it can post to it,
# so shipping one is a ready exfiltration route. Counted anywhere in a file, since
# the code that sends to it often runs only when the user calls a function. The
# shapes are the real ones (ids and token lengths), so docs placeholders do not match.
# Kind -> (shape, detail). The detail never holds the value: it is the attacker's credential.
_CHANNELS = {
    "discord": (
        re.compile(
            r"(?<![A-Za-z0-9-])(?i:discord(?:app)?\.com)/api/(?:v\d+/)?webhooks/\d{17,20}/"
            r"[A-Za-z0-9_-]{60,80}(?![A-Za-z0-9_-])"
        ),
        "ships a Discord webhook URL with its token",
    ),
    # Bare or in a bot URL (api.telegram.org/bot<token>/sendMessage). Real secrets
    # start AA; the docs example (123456:ABC-DEF...) does not.
    "telegram": (
        re.compile(r"(?<![A-Za-z0-9_-])(?:bot)?\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])"),
        "ships a Telegram bot token",
    ),
}
# A constant that is all base64 (line breaks aside): channels are often shipped encoded.
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
_URLSAFE = str.maketrans("-_", "+/")


def analyse(source: str | bytes, top_level_only: bool, entry: Mapping[str, str] = {}) -> list[Hit]:
    """Hits in source order. Raises SyntaxError (and RecursionError) for code that will not parse.

    With top_level_only, hits in function and lambda bodies are dropped: what is
    left is what runs on import. Class bodies, if, try and with blocks all count.
    So do module-level functions that run anyway: called, applied as a decorator,
    or passed as a thread or process target=, as a threading.Timer function or
    to atexit.register, by module-level code, by another such function, or named
    in entry (functions other code calls, each with how: "called at install");
    exec inside them is left out. Hidden code counts wherever it is.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)  # bad escapes in the code read
        tree = ast.parse(source)
    with _deep_recursion():
        called = _called_functions(tree, entry)[0] if top_level_only else {}
        visitor = _Visitor(*_bindings(tree), top_level_only, called)
        visitor.bind_files(tree)
        visitor.visit(tree)
    hits = [h for h in visitor.hits if h.kind not in _CALL_ONLY]
    return sorted(hits + _channels(tree), key=lambda h: h.line)


@dataclass(frozen=True)
class Unit:
    """A function that runs only when called, or a whole script's top level."""

    name: str  # f, Class.method, outer.inner, or <module>
    line: int
    hits: tuple[Hit, ...]  # its own, and those of the functions it calls in this file


def call_units(
    source: str | bytes, entry: Mapping[str, str] = {}, whole_file: bool = False
) -> list[Unit]:
    """The functions of a file that run only when something calls them, each with
    what it does and what the functions it calls in the same file do. Raises
    SyntaxError like analyse.

    Functions that run on import (as analyse finds them, with entry) are left
    out, as is top-level code, since the import rules read those. With
    whole_file (a script or a test nothing imports), every function counts and
    so does the top level, as the unit <module>. An `if __name__ == "__main__":`
    block counts either way, as the unit <main>. A call reaches a function by
    its bare name, or a method of the same class through self, cls or the
    class name. Units with no hits are left out.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    with _deep_recursion():
        reached = set() if whole_file else set(_called_functions(tree, entry)[0])
        visitor = _Visitor(*_bindings(tree), False, {})
        visitor.bind_files(tree)
        visitor.visit(tree)
        return _units(tree, visitor.hits, reached, whole_file)


# Hits a unit keeps of each kind: enough to name the lines, and bounded however
# many functions it reaches.
_UNIT_HITS = 3


def _units(
    tree: ast.Module, hits: list[Hit], reached: set[ast.AST], whole_file: bool
) -> list[Unit]:
    names: dict[ast.AST, str] = {}  # functions, and `if __name__ == "__main__":` blocks
    classes: dict[ast.AST, str] = {}  # a method's class
    by_name: dict[str, list[ast.AST]] = {}  # functions that are not methods
    methods: dict[tuple[str, str], list[ast.AST]] = {}

    def collect(node: ast.AST, prefix: str, cls: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                collect(child, f"{prefix}{child.name}.", child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names[child] = prefix + child.name
                if cls:
                    classes[child] = cls
                    methods.setdefault((cls, child.name), []).append(child)
                else:
                    by_name.setdefault(child.name, []).append(child)
                collect(child, f"{prefix}{child.name}.", "")
            else:
                collect(child, prefix, cls)

    collect(tree, "", "")
    # A main block runs only as a script (python -m), so the import rules skip it.
    for stmt in tree.body:
        if isinstance(stmt, ast.If) and _is_main_check(stmt.test):
            names[stmt] = "<main>"
    # Each hit belongs to the innermost function or main block whose lines hold it,
    # else the top level. Inner ones start later, so they are written last.
    holder_at: dict[int, ast.AST] = {}
    for node in sorted(names, key=lambda n: n.lineno):  # type: ignore[attr-defined]
        for line in range(node.lineno, (node.end_lineno or node.lineno) + 1):  # type: ignore[attr-defined]
            holder_at[line] = node
    found: dict[ast.AST, dict[str, tuple[Hit, ...]]] = {}

    def add(node: ast.AST, kind: str, new: tuple[Hit, ...]) -> bool:
        have = found.setdefault(node, {}).get(kind, ())
        merged = tuple(dict.fromkeys(have + new))[:_UNIT_HITS]
        found[node][kind] = merged
        return merged != have

    for hit in hits:
        add(holder_at.get(hit.line, tree), hit.kind, (hit,))
    # Hand each function's hits on to its callers until nothing changes. A kind
    # changes at most _UNIT_HITS times per unit, so this ends quickly.
    callers: dict[ast.AST, set[ast.AST]] = {}
    for caller in [tree, *names]:
        for call in _own_calls(caller):
            for callee in _callees(_dotted(call.func), classes.get(caller), by_name, methods):
                callers.setdefault(callee, set()).add(caller)
    todo = list(found)
    while todo:
        node = todo.pop()
        for caller in callers.get(node, ()):
            if any([add(caller, kind, new) for kind, new in list(found[node].items())]):
                todo.append(caller)
    units = []
    for node, kinds in found.items():
        if node in reached or (node is tree and not whole_file):
            continue
        unit_hits = tuple(sorted((h for hs in kinds.values() for h in hs), key=lambda h: h.line))
        name = "<module>" if node is tree else names[node]
        units.append(Unit(name, getattr(node, "lineno", 0), unit_hits))
    return sorted(units, key=lambda u: (u.line, u.name))


def _own_calls(node: ast.AST) -> Iterator[ast.Call]:
    """Calls in node's own code: not in the functions or classes defined inside it."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.Call):
            yield child
        yield from _own_calls(child)


def _callees(
    called: str,
    cls: str | None,
    by_name: Mapping[str, list[ast.AST]],
    methods: Mapping[tuple[str, str], list[ast.AST]],
) -> list[ast.AST]:
    head, _, rest = called.partition(".")
    if not rest:
        return by_name.get(head, [])
    if "." in rest:
        return []
    if head in ("self", "cls") and cls:
        return methods.get((cls, rest), [])
    return methods.get((head, rest), [])


def _channels(tree: ast.AST) -> list[Hit]:
    """Messenger channels in string and bytes constants, anywhere in the file."""
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str | bytes):
            continue
        value = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
        hits.extend(Hit(kind, node.lineno, detail) for kind, detail in channels_in(value))
    return hits


def channels_in(value: str) -> list[tuple[str, str]]:
    """(kind, detail) for each messenger channel in one string, read whole and,
    when it is all base64, decoded too. The detail never holds the value."""
    texts = [(value, "")]
    packed = "".join(value.split())
    if _BASE64.fullmatch(packed):
        data = packed.rstrip("=").translate(_URLSAFE)
        with contextlib.suppress(binascii.Error):
            decoded = base64.b64decode(data + "=" * (-len(data) % 4)).decode("latin-1")
            texts.append((decoded, " (base64)"))
    return [
        (kind, detail + how)
        for kind, (pattern, detail) in _CHANNELS.items()
        for text, how in texts
        if pattern.search(text)
    ]


@contextlib.contextmanager
def _deep_recursion() -> Iterator[None]:
    """Real files nest deeper than the default limit (sympy). Python-to-Python calls
    do not use the C stack since 3.11, so a higher limit is safe for the tree walks."""
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, 50_000))
    try:
        yield
    finally:
        sys.setrecursionlimit(limit)


def imported_functions(source: str | bytes) -> dict[str, dict[str, str]]:
    """Modules a file imports by absolute name, anywhere in it, each with the
    names it may call from them, as {name: "called at install"}. Raises
    SyntaxError like analyse.

    `from m import f` gives m: {f} (and m.f, in case f is a submodule);
    `import m.sub as s` or `from m import sub`, then `s.f()`, gives m.sub: {f}.
    Parent packages are listed too, since importing m.sub runs m first.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    with _deep_recursion():
        return _imported_functions(tree)


def import_calls(
    source: str | bytes, package: str, entry: Mapping[str, str], how: str
) -> dict[str, dict[str, str]]:
    """Functions of other modules a file calls when it is imported, as
    {module: {name: how it is reached}}.

    Calls count when module-level code makes them (reached as how), or a
    function of the file that runs on import does (entry: functions other
    files call in it, each with how). Relative imports resolve against
    package, the file's own package. An entry name the file only imports is
    passed on, so a re-export is followed. Raises SyntaxError like analyse.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    with _deep_recursion():
        return _imported_functions(tree, package, _called_functions(tree, entry, how)[1])


def imported_modules(source: str | bytes, package: str) -> set[str]:
    """Dotted names a file may import: absolute and relative imports (resolved
    against package, the file's own package), each with its parents, and any
    dotted name inside a string, for importlib ('pkg.tests:x' too). Each word of a
    string with no spaces ('.helpers', 'tests/helpers.py') is added on its own as
    well, since a file can be loaded by a relative name or by path, and so are
    its names and words with hyphens ('pkg.my-mod', 'my-mod'), which importlib
    loads though no import statement can. Raises SyntaxError like analyse.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    names = set()
    with _deep_recursion():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = _from_module(node, package)
                names.add(base)
                names.update(f"{base}.{alias.name}" for alias in node.names)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.update(re.findall(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", node.value))
                if not re.search(r"\s", node.value):  # a name or a path, not prose
                    names.update(re.findall(r"[A-Za-z_]\w*", node.value))
                    # importlib loads names no import statement can: "pkg.my-mod"
                    names.update(re.findall(r"[\w-]+(?:\.[\w-]+)*", node.value))
                    names.update(re.findall(r"[\w-]+", node.value))
    for name in list(names):
        parts = name.split(".")
        names.update(".".join(parts[:i]) for i in range(1, len(parts)))
    return names


def command_code(tree: ast.AST) -> set[ast.AST]:
    """String constants of code handed to `-c` in a command list passed straight
    to a process call: subprocess.run([sys.executable, "-c", "import x"]). Only
    a literal or f-string's own text: an expression there runs in this process."""
    found: set[ast.AST] = set()
    with _deep_recursion():
        visitor = _Visitor(*_bindings(tree), False, {})
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = visitor.resolve(node.func)
            if name not in _PROCESS_CALLS and not (name and name.startswith(_PROCESS_PREFIXES)):
                continue
            for arg in [*node.args, *(k.value for k in node.keywords)]:
                if not isinstance(arg, ast.List | ast.Tuple):
                    continue
                for flag, code in zip(arg.elts, arg.elts[1:], strict=False):
                    if not (isinstance(flag, ast.Constant) and flag.value == "-c"):
                        continue
                    parts = code.values if isinstance(code, ast.JoinedStr) else [code]
                    found.update(part for part in parts if isinstance(part, ast.Constant))
    return found


# setup.py commands pip runs to build and install: setuptools' PEP 517 backend
# (egg_info, dist_info, bdist_wheel, editable_wheel) and the legacy setup.py
# install and develop, with the sub-commands each runs. pip never runs sdist.
_PIP_COMMANDS = frozenset(
    {"egg_info", "dist_info", "bdist_wheel", "editable_wheel", "bdist_egg", "easy_install"}
    | {"build", "build_py", "build_ext", "build_clib", "build_scripts", "develop"}
    | {"install", "install_lib", "install_headers", "install_scripts", "install_data"}
    | {"install_egg_info"}
)
# Without a pyproject.toml, pip up to 25 can build with setup.py bdist_wheel
# itself, and runs setup.py clean --all when that fails.
_LEGACY_COMMANDS = _PIP_COMMANDS | {"clean"}
_SETUP_CALLS = frozenset({"setuptools.setup", "distutils.core.setup"})
# Ways to reach a function, class or command without naming it, or to change the
# commands that run. In setup.py code that runs, any of these stops the reading.
_FRAME_ATTRS = frozenset(
    {"f_globals", "f_locals", "f_back", "getargvalues", "__subclasses__"}
    | {"get_objects", "get_referrers"}
)
_LOOKUP_ATTRS = _FRAME_ATTRS | {
    "__dict__", "__globals__", "__getattribute__", "getmembers", "getattr_static",
    "attrgetter", "methodcaller", "modules", "getattr", "setattr", "delattr", "eval", "exec",
    "globals", "vars", "locals", "__import__", "sub_commands", "cmdclass", "commands",
    "script_args", "run_setup", "run_commands", "parse_command_line",
}  # fmt: skip
_LOOKUP_NAMES = frozenset(
    {"globals", "vars", "locals", "__import__", "__builtins__", "sub_commands", "run_setup"}
)
_COMMAND_LOOKUPS = frozenset(
    {"run_command", "get_command_obj", "get_finalized_command", "reinitialize_command"}
    | {"get_command_class"}
)
_LOOKUP_WORDS = _LOOKUP_ATTRS | _LOOKUP_NAMES | _COMMAND_LOOKUPS


def reaches_setup_py(source: str | bytes) -> bool:
    """Whether code in another file that runs at install could reach setup.py's
    names or change its commands: a caller's frame, __main__, sys.modules by a
    name not written out, the garbage collector, subclasses, or sys.argv changed.
    Raises SyntaxError like analyse."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    with _deep_recursion():
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        aliases = _bindings(tree)[0]
        return any(_reaches_caller(node, parents, aliases) for node in ast.walk(tree))


def _reaches_caller(node: ast.AST, parents: Mapping, aliases: Mapping[str, str]) -> bool:
    """Whether node reaches setup.py's names from elsewhere, or changes sys.argv."""
    parent = parents.get(node)
    # by attribute, by name in a string (getattr(f, "f_globals")) or imported by name
    if isinstance(node, ast.Attribute) and node.attr in _FRAME_ATTRS:
        return True
    if isinstance(node, ast.Constant) and node.value in _FRAME_ATTRS:
        return True
    if isinstance(node, ast.alias) and node.name.rpartition(".")[2] in {*_FRAME_ATTRS, "__main__"}:
        return True
    if isinstance(node, ast.Constant) and node.value == "__main__":
        return not isinstance(parent, ast.Compare)  # __name__ == "__main__"
    if isinstance(node, ast.Name) and aliases.get(node.id, node.id) == "sys":
        return not isinstance(parent, ast.Attribute)  # sys handed on: s = sys; s.argv
    within = isinstance(parent, ast.Compare) and node in parent.comparators
    item = isinstance(parent, ast.Subscript) and parent.value is node
    if _sys_attr(node, aliases) == "argv":
        # read only: argv[i], "x" in argv, len(argv). Anything else may change it.
        read = item and isinstance(parent.ctx, ast.Load)  # type: ignore[union-attr]
        counted = isinstance(parent, ast.Call) and _dotted(parent.func) == "len"
        ops = parent.ops if within else []  # type: ignore[union-attr]
        member = within and all(isinstance(o, ast.In | ast.NotIn) for o in ops)
        return not (read or counted or member)
    if _sys_attr(node, aliases) == "modules":
        # sys.modules["name"] cannot be setup.py's namespace; __main__ or a variable can.
        written = item and isinstance(parent.slice, ast.Constant)  # type: ignore[union-attr]
        return not (written or within)
    return False


def _sys_attr(node: ast.AST, aliases: Mapping[str, str]) -> str:
    """For what may be sys.argv or sys.modules, the attribute; else empty. Taken
    widely, since this is where a change is looked for: any `x.argv`, and
    `.modules` of sys (`import sys as s`, `x.sys`) or of a call
    (`import_module("sys")`). Reads at most two links, so long chains stay linear."""
    if isinstance(node, ast.Name) and aliases.get(node.id, "") in ("sys.argv", "sys.modules"):
        return aliases[node.id].removeprefix("sys.")
    if not isinstance(node, ast.Attribute) or node.attr not in ("argv", "modules"):
        return ""
    base = node.value
    is_sys = (
        node.attr == "argv"
        or isinstance(base, ast.Call)
        or (isinstance(base, ast.Name) and aliases.get(base.id, base.id) == "sys")
        or (isinstance(base, ast.Attribute) and base.attr == "sys")
    )
    return node.attr if is_sys else ""


def not_run_by_pip(source: str | bytes, legacy: bool = True) -> list[tuple[int, int, str | None]]:
    """Line spans of setup.py and whether pip runs them: (first, last, why not)
    for code it never runs, (first, last, None) for code it may. A line belongs to
    the smallest span holding it; lines in no span run.

    Spans are the bodies of module-level functions, of the methods of command
    classes, and of `if` blocks for a command on the command line
    (`if "publish" in sys.argv:`). What runs: the top level, functions and classes
    it refers to (by name, attribute or a word in a string), and the commands pip
    runs (_PIP_COMMANDS). A command class runs when registered in a literal
    cmdclass under one of those names, or any other way, or when its name is in a
    string that runs. Empty when code that runs could reach a name some other way
    (see _LOOKUP_ATTRS): then all of it counts. Raises SyntaxError like analyse.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    with _deep_recursion():
        return _PipReader(tree, _LEGACY_COMMANDS if legacy else _PIP_COMMANDS).spans()


class _PipReader:
    """Which parts of a setup.py pip runs. See not_run_by_pip."""

    def __init__(self, tree: ast.Module, commands: frozenset[str]) -> None:
        self.tree = tree
        self.commands = commands  # the commands pip may run
        self.parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        self.aliases = _bindings(tree)[0]
        self.imports: dict[str, set[str]] = {}  # local name -> what each import binds to it
        self.bound: dict[str, int] = {}  # local name -> bindings other than imports
        self.loads: dict[str, int] = {}
        self.assigned: dict[str, ast.expr] = {}  # name = value
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                self.assigned[_dotted(node.targets[0])] = node.value
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    target = alias.name if alias.asname else local
                    self.imports.setdefault(local, set()).add(target)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    target = f"{node.module}.{alias.name}" if node.module else alias.name
                    self.imports.setdefault(alias.asname or alias.name, set()).add(target)
            elif isinstance(node, ast.Name):
                counts = self.loads if isinstance(node.ctx, ast.Load) else self.bound
                counts[node.id] = counts.get(node.id, 0) + 1
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                self.bound[node.name] = self.bound.get(node.name, 0) + 1
            elif isinstance(node, ast.arg):
                self.bound[node.arg] = self.bound.get(node.arg, 0) + 1
        self.functions: dict[str, list[ast.AST]] = {}
        self.classes: dict[str, list[ast.ClassDef]] = {}
        self._collect(tree.body)

    def _collect(self, body: list[ast.stmt]) -> None:
        """Module-level functions and classes, in if, try, with and match blocks too."""
        for stmt in body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                self.functions.setdefault(stmt.name, []).append(stmt)
            elif isinstance(stmt, ast.ClassDef):
                self.classes.setdefault(stmt.name, []).append(stmt)
            else:
                for field in ("body", "orelse", "finalbody"):
                    self._collect(getattr(stmt, field, []))
                for block in [*getattr(stmt, "handlers", []), *getattr(stmt, "cases", [])]:
                    self._collect(block.body)

    def _imported_from(self, node: ast.AST, allowed: Collection[str]) -> bool:
        """Whether a name or attribute chain is only ever an import of one of allowed
        (each a dotted name, or a top-level package with everything under it)."""
        head, _, rest = _dotted(node).partition(".")
        targets = self.imports.get(head)
        if not targets or self.bound.get(head):
            return False
        for target in targets:
            full = ".".join(p for p in (target, rest) if p)
            if full not in allowed and full.split(".")[0] not in allowed:
                return False
        return True

    def _command_classes(self) -> set[str]:
        """Classes that are plain commands: from setuptools or distutils, or other
        such classes, with no decorator, metaclass or __init_subclass__ whose code
        could run them as they are defined."""
        plain: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, defs in self.classes.items():
                if name in plain or name in self.functions or self.bound.get(name, 0) != len(defs):
                    continue
                if all(
                    not cls.decorator_list
                    and not cls.keywords
                    and not any(
                        isinstance(s, ast.FunctionDef) and s.name == "__init_subclass__"
                        for s in cls.body
                    )
                    and self._inert(cls)
                    and all(
                        (isinstance(b, ast.Name) and b.id in plain)
                        or self._imported_from(b, ("setuptools", "distutils"))
                        for b in cls.bases
                    )
                    for cls in defs
                ):
                    plain.add(name)
                    changed = True
        return plain

    def _inert(self, cls: ast.ClassDef) -> bool:
        """Whether defining the class runs nothing that could call its methods: its
        body holds only methods (with plain defaults and annotations, and no
        decorator but staticmethod, classmethod or property) and literal values
        (no call, and no object whose __set_name__ would be handed the class)."""
        plain = (ast.arguments, ast.arg, ast.Constant, ast.Name, ast.Attribute, ast.Load)
        plain += (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.UnaryOp, ast.USub, ast.keyword)

        def inert(node: ast.AST | None) -> bool:
            return node is None or all(isinstance(n, plain) for n in ast.walk(node))

        builtin = ("staticmethod", "classmethod", "property")
        for stmt in cls.body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                if not all(
                    isinstance(d, ast.Name) and d.id in builtin and not self.bound.get(d.id)
                    for d in stmt.decorator_list
                ):
                    return False
                if not (inert(stmt.args) and inert(stmt.returns)):
                    return False
                if getattr(stmt, "type_params", None):
                    return False
            elif isinstance(stmt, ast.Pass) or (
                isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            ):
                continue
            elif isinstance(stmt, ast.Assign | ast.AnnAssign):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                value = stmt.value
                literal = isinstance(
                    value, ast.Constant | ast.Tuple | ast.List | ast.Set | ast.Dict
                )
                literal = literal or isinstance(value, ast.Name) and value.id == "__doc__"
                annotation = getattr(stmt, "annotation", None)
                if not (
                    all(isinstance(t, ast.Name) for t in targets)
                    and (value is None or literal and inert(value))
                    and inert(annotation)
                ):
                    return False
            else:
                return False
        return True

    def _gate(self, test: ast.expr) -> tuple[ast.Constant, bool] | None:
        """The command an `if` runs only for, from the command line: argv[i] == "x",
        "x" in argv, argv[i].startswith("x"), or `and` with one of these. With
        whether it is the whole command or (startswith) its start."""
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            return next(filter(None, map(self._gate, test.values)), None)
        found: ast.expr | None = None
        exact = True
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            left, right = test.left, test.comparators[0]
            if isinstance(test.ops[0], ast.Eq):
                found = right if self._argv_item(left) else left if self._argv_item(right) else None
            elif isinstance(test.ops[0], ast.In) and (
                # a list of argv items; `in` one item is a substring test ("wheel" in "bdist_wheel")
                self._argv(right)
                or isinstance(right, ast.Subscript)
                and self._argv(right.value)
                and isinstance(right.slice, ast.Slice)
            ):
                found = left
        elif (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr == "startswith"
            and self._argv_item(test.func.value)
            and len(test.args) == 1
            and not test.keywords
        ):
            found, exact = test.args[0], False
        if not (isinstance(found, ast.Constant) and isinstance(found.value, str)):
            return None
        # a command name pip never passes, nor an option or path it does pass
        word = found.value
        if not re.fullmatch(r"[A-Za-z][\w-]{0,63}", word) or word in self.commands:
            return None
        if not exact and (len(word) < 2 or any(c.startswith(word) for c in self.commands)):
            return None  # "C" starts a Windows path pip passes (--dist-dir C:\\...)
        return found, exact

    def _argv(self, node: ast.AST) -> bool:
        # The real sys.argv only: a local `sys` could hold any list.
        return self._imported_from(node, ("sys.argv",))

    def _argv_item(self, node: ast.AST) -> bool:
        """sys.argv[i] for a command pip passes: i from 1, or -1. argv[0] is setup.py
        or a path under pip, and argv[-2] can be argv[0]."""
        if not (isinstance(node, ast.Subscript) and self._argv(node.value)):
            return False
        index = node.slice
        if isinstance(index, ast.UnaryOp) and isinstance(index.op, ast.USub):
            return isinstance(index.operand, ast.Constant) and index.operand.value == 1
        return isinstance(index, ast.Constant) and type(index.value) is int and index.value >= 1

    def _used_once(self, node: ast.expr) -> ast.expr:
        """For a name assigned once and read only here, the value assigned; else node.
        Read anywhere else, it could be changed before it gets here."""
        if isinstance(node, ast.Name) and self.bound.get(node.id) == 1 == self.loads.get(node.id):
            return self.assigned.get(node.id, node)
        return node

    def _slots(self, call: ast.Call) -> list[tuple[ast.Constant, ast.Name]]:
        """(name, class) pairs a setuptools setup() call registers in a literal
        cmdclass: a dict display, dict(name=...), or a name bound once to one of
        them and used only here."""
        if not (
            isinstance(call.func, ast.Name | ast.Attribute)
            and self._imported_from(call.func, _SETUP_CALLS)
        ):
            return []
        pairs = []
        for keyword in call.keywords:
            value = keyword.value
            if keyword.arg != "cmdclass":
                continue
            value = self._used_once(value)
            if isinstance(value, ast.Dict):
                items = list(zip(value.keys, value.values, strict=True))
            elif (
                isinstance(value, ast.Call)
                and _dotted(value.func) == "dict"
                and not self.bound.get("dict")
                and not value.args
            ):
                items = [(ast.Constant(k.arg), k.value) for k in value.keywords if k.arg]
            else:
                continue
            for key, cls in items:
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and isinstance(cls, ast.Name)
                ):
                    pairs.append((key, cls))
        return pairs

    def spans(self) -> list[tuple[int, int, str | None]]:
        plain = self._command_classes()
        # Regions: ("top",), ("function", name), ("method", class), ("gate", command).
        # Each with the spans of its bodies and what code in it refers to.
        Region = tuple[str, ...]
        spans: list[tuple[int, int, Region]] = []
        names: dict[Region, set[str]] = {}  # functions and classes referred to
        words: dict[Region, set[str]] = {}  # words of strings, for command names
        gates: list[tuple[Region, str, bool]] = []  # (region, command, exact or a prefix)
        slots: dict[Region, list[tuple[str, str]]] = {}  # (command, class) registered
        bases: dict[str, set[str]] = {}  # class -> its plain local bases
        nodes: dict[Region, list[ast.AST]] = {}
        skip: set[ast.AST] = set()  # cmdclass entries and gate commands: not references
        for call in ast.walk(self.tree):
            if isinstance(call, ast.Call):
                for key, cls in self._slots(call):
                    if cls.id in plain:
                        skip.update((key, cls))
        for name in plain:
            for cls in self.classes[name]:
                for base in cls.bases:
                    if isinstance(base, ast.Name) and base.id in plain:
                        bases.setdefault(name, set()).add(base.id)
                        skip.add(base)
        methods = {
            stmt: name
            for name in plain
            for cls in self.classes[name]
            for stmt in cls.body
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef)
            and not stmt.decorator_list
            and not re.fullmatch(r"__\w+__", stmt.name)
        }
        functions = {
            f: name for name, defs in self.functions.items() for f in defs if not f.decorator_list
        }

        def body_after(node: ast.AST) -> bool:
            # A body sharing a line with code that runs (a test, a decorator, a default
            # or an annotation) cannot be told apart by line.
            header = [
                child
                for field, value in ast.iter_fields(node)
                if field not in ("body", "orelse")
                for child in (value if isinstance(value, list) else [value])
                if isinstance(child, ast.AST)
            ]
            last = max(
                (getattr(n, "end_lineno", 0) or 0 for h in header for n in ast.walk(h)), default=0
            )
            return node.body[0].lineno > max(last, node.lineno)  # type: ignore[attr-defined]

        def visit(node: ast.AST, region: Region) -> None:
            nodes.setdefault(region, []).append(node)
            inner: Region | None = None
            if node in functions and body_after(node):
                inner = ("function", functions[node])
            elif node in methods and body_after(node):
                inner = ("method", methods[node])
            elif isinstance(node, ast.If) and (gate := self._gate(node.test)):
                if body_after(node):
                    inner = ("gate", gate[0].value)
                    gates.append((inner, gate[0].value, gate[1]))
                    skip.add(gate[0])
            if isinstance(node, ast.Call):
                for key, cls in self._slots(node):
                    if cls.id in plain:
                        slots.setdefault(region, []).append((key.value, cls.id))
            if node in skip:
                pass
            elif isinstance(node, ast.Name):
                names.setdefault(region, set()).add(node.id)
            elif isinstance(node, ast.Attribute):
                names.setdefault(region, set()).add(node.attr)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                is_doc = isinstance(self.parents.get(node), ast.Expr)  # a no-op string
                if not is_doc:
                    words.setdefault(region, set()).update(re.findall(r"[\w-]+", node.value))
                    names.setdefault(region, set()).update(re.findall(r"\w+", node.value))
            if inner is None:
                for child in ast.iter_child_nodes(node):
                    visit(child, region)
                return
            body = node.body  # type: ignore[attr-defined]
            spans.append((body[0].lineno, body[-1].end_lineno, inner))
            for field, value in ast.iter_fields(node):
                for child in value if isinstance(value, list) else [value]:
                    if isinstance(child, ast.AST):
                        visit(child, inner if field == "body" else region)

        visit(self.tree, ("top",))
        # What runs, to a fixed point: the top level, then whatever running code
        # refers to, and command classes registered under a command that runs.
        # A command in a string that runs runs that command: run_command("publish"),
        # or setup.py run again in a process (`python setup.py publish`).
        units = set(self.functions) | plain
        live: set[str] = set()
        pending: list[Region] = [("top",)]
        done: set[Region] = set()
        said: set[str] = set()  # words of strings in code that runs
        waiting: dict[str, list[str | Region]] = {}  # command -> classes and blocks for it
        prefixes: dict[str, list[str | Region]] = {}  # argv[i].startswith(command) blocks
        for gate_region, command, exact in gates:
            (waiting if exact else prefixes).setdefault(command, []).append(gate_region)
        while pending:
            region = pending.pop()
            if region in done:
                continue
            done.add(region)
            woken: list[str | Region] = list(units & names.get(region, set()))
            for word in words.get(region, set()) - said:
                said.add(word)
                woken += waiting.pop(word, [])
                for end in range(1, min(len(word), 64) + 1):
                    woken += prefixes.pop(word[:end], [])
            for command, cls in slots.get(region, []):
                if command in self.commands or command in said:
                    woken.append(cls)
                else:
                    waiting.setdefault(command, []).append(cls)
            pending += [item for item in woken if isinstance(item, tuple)]
            todo = [item for item in woken if isinstance(item, str)]
            while todo:
                unit = todo.pop()
                if unit not in live:
                    live.add(unit)
                    pending += [("function", unit), ("method", unit)]
                    todo += bases.get(unit, ())  # a subclass that runs runs its bases' code
        # Code that runs must not reach names any other way.
        for region in done:
            for node in nodes.get(region, []):
                if self._looks_up(node) or _reaches_caller(node, self.parents, self.aliases):
                    return []
        result = []
        for first, last, region in spans:
            if region in done:
                result.append((first, last, None))
            elif region[0] == "gate":
                result.append((first, last, f"in a block for setup.py {region[1]}"))
            elif region[0] == "method":
                commands = sorted({c for r in slots for c, k in slots[r] if k == region[1]})
                what = " or ".join(commands) + " command" if commands else "unused command class"
                result.append((first, last, f"in the {what} {region[1]}"))
            else:
                result.append((first, last, f"in {region[1]}(), which nothing pip runs calls"))
        return result

    def _looks_up(self, node: ast.AST) -> bool:
        """Whether code that runs could find a name, or change the commands, here."""
        parent = self.parents.get(node)
        called = isinstance(parent, ast.Call) and parent.func is node
        if isinstance(node, ast.Name) and node.id in _LOOKUP_NAMES:
            return True
        if isinstance(node, ast.Attribute):
            if node.attr in _LOOKUP_ATTRS:
                return True
            if node.attr in _COMMAND_LOOKUPS:  # run_command("x") is a reference to x
                args = parent.args if called else []  # type: ignore[union-attr]
                return not (args and isinstance(args[0], ast.Constant))
        if isinstance(node, ast.Name) and node.id in ("getattr", "setattr", "delattr"):
            args = parent.args if called else []  # type: ignore[union-attr]
            return not (len(args) >= 2 and isinstance(args[1], ast.Constant))
        if isinstance(node, ast.Name) and node.id in ("eval", "exec"):
            if not called:
                return True
            # Code in a string is read for references; other code needs its own namespace.
            args, keywords = parent.args, parent.keywords  # type: ignore[union-attr]
            literal = bool(args) and isinstance(args[0], ast.Constant)
            own = len(args) >= 2 or any(k.arg == "globals" for k in keywords)
            return not (literal or own)
        # A lookup named in a string (getattr(builtins, "globals")) or imported by name.
        if isinstance(node, ast.Constant) and node.value in _LOOKUP_WORDS:
            return True
        if isinstance(node, ast.alias) and node.name.rpartition(".")[2] in _LOOKUP_WORDS:
            return True
        if isinstance(node, ast.Name | ast.Attribute) and not called:
            # setup itself handed on: what calls it, and with what, is not read here
            setup = isinstance(node, ast.Attribute) and node.attr == "setup"
            setup = setup or isinstance(node, ast.Name) and node.id in self.imports
            return setup and self._imported_from(node, _SETUP_CALLS)
        if isinstance(node, ast.keyword):
            if node.arg == "script_args":
                return True
            into_setup = isinstance(parent, ast.Call) and self._imported_from(
                parent.func, _SETUP_CALLS
            )
            if node.arg is None and into_setup:  # **mapping: keys could be cmdclass, script_args
                value = self._used_once(node.value)
                if isinstance(value, ast.Dict):
                    return not all(isinstance(k, ast.Constant) for k in value.keys)
                return not (
                    isinstance(value, ast.Call)
                    and _dotted(value.func) == "dict"
                    and all(k.arg for k in value.keywords)
                )
        return False


def _from_module(node: ast.ImportFrom, package: str) -> str:
    """The module a from-import reads, a relative one resolved against package."""
    if not node.level:
        return node.module or ""
    parts = package.split(".")[: len(package.split(".")) - node.level + 1]
    return ".".join(p for p in [*parts, node.module or ""] if p)


def _imported_functions(
    tree: ast.Module, package: str = "", called: Mapping[str, str] | None = None
) -> dict[str, dict[str, str]]:
    """Modules a file imports, each with the names it calls from them and how
    each is reached: {module: {name: how}}.

    Without called (install code), every module imported counts, with every
    name imported from it and every call anywhere in the file, all "called at
    install". With called (the names called at import, each with how), only
    those calls count. Relative imports resolve against package, and are
    skipped without one.
    """
    install = "called at install"
    modules: dict[str, dict[str, str]] = {}
    # local name -> every module (or module.name) it is bound to, in any scope
    bound: dict[str, list[str]] = {}
    stars: list[str] = []  # from m import *: a bare name called may be m's
    for node in _statements(tree.body):
        if isinstance(node, ast.ImportFrom) and (package or not node.level):
            base = _from_module(node, package)
            for alias in node.names:
                if called is None:
                    modules.setdefault(base, {})[alias.name] = install
                    modules.setdefault(f"{base}.{alias.name}", {})
                if alias.name == "*":
                    stars.append(base)
                else:
                    bound.setdefault(alias.asname or alias.name, []).append(f"{base}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if called is None:
                    modules.setdefault(alias.name, {})
                local = alias.asname or alias.name.split(".")[0]
                bound.setdefault(local, []).append(alias.name if alias.asname else local)
    if called is None:
        called = {_dotted(n.func): install for n in ast.walk(tree) if isinstance(n, ast.Call)}
    for name, how in called.items():
        head, _, rest = name.partition(".")
        for target in bound.get(head, []):
            module, _, function = ".".join(p for p in (target, rest) if p).rpartition(".")
            if module:
                modules.setdefault(module, {}).setdefault(function, how)
        if head not in bound and head and not rest:
            for star in stars:
                modules.setdefault(star, {}).setdefault(head, how)
    for module in list(modules):
        parts = module.split(".")
        for i in range(1, len(parts)):
            modules.setdefault(".".join(parts[:i]), {})
    return modules


def _statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Every statement in body and in the blocks inside it, functions and classes too.

    Cheaper than ast.walk when only statements (imports) are wanted.
    """
    for stmt in body:
        yield stmt
        for field in ("body", "orelse", "finalbody"):
            yield from _statements(getattr(stmt, field, []))
        for block in [*getattr(stmt, "handlers", []), *getattr(stmt, "cases", [])]:
            yield from _statements(block.body)


def _called_functions(
    tree: ast.Module, entry: Mapping[str, str], how: str = "called at module level"
) -> tuple[dict[ast.AST, str], dict[str, str]]:
    """Module-level functions that run on import, each with how it is reached,
    and every name (f, m.f) that code running on import calls, each with how
    (module-level calls are reached as how).

    Only this file's own functions, found by name, and functions nested in one
    that runs, seen only from inside it; methods are not followed. Names of
    the file's own module-level functions are left out of the names.
    """
    Functions = dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]]

    def collect(body: list[ast.stmt], into: Functions) -> Functions:
        # Every definition of a name: which one runs may depend on an if or a try.
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                into.setdefault(stmt.name, []).append(stmt)
                continue
            if isinstance(stmt, ast.ClassDef):
                continue  # methods are not module-level functions
            for field in ("body", "orelse", "finalbody"):
                collect(getattr(stmt, field, []), into)
            for block in [*getattr(stmt, "handlers", []), *getattr(stmt, "cases", [])]:
                collect(block.body, into)
        return into

    functions = collect(tree.body, {})
    reached: dict[ast.AST, str] = {}
    todo = [(name, how, functions) for name in _called_names(tree)]
    todo += [(name, reached_as, functions) for name, reached_as in entry.items()]
    names: dict[str, str] = {}
    for name, reached_as, _ in todo:
        names.setdefault(name, reached_as)
    while todo:
        name, reached_as, scope = todo.pop()
        for function in scope.get(name, []):
            if function in reached:
                continue
            reached[function] = f"in {name}(), {reached_as}"
            # Its nested functions run when it calls them. They are added beside
            # outer names, not over them: `global g` makes g() the module's g.
            nested = collect(function.body, {})
            inner = {k: scope.get(k, []) + nested.get(k, []) for k in scope.keys() | nested}
            for stmt in function.body:
                for callee in _called_names(stmt):
                    names.setdefault(callee, reached_as)
                    todo.append((callee, reached_as, inner))
    # A local def hides a star import's name, but not a name imported by name:
    # that import may be the binding when the call runs.
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                imported.add(alias.asname or alias.name.split(".")[0])
    return reached, {n: h for n, h in names.items() if n not in functions or n in imported}


def _called_names(node: ast.AST) -> set[str]:
    """Names (f, m.f) called, or passed to a call, by code that runs when node runs.

    Function and lambda bodies are skipped (their decorators and defaults run),
    and so are `if __name__ == "__main__":` blocks. Applying a decorator calls
    it: @deco runs deco itself, not the wrapper it returns.
    """
    names: set[str] = set()

    def visit(n: ast.AST) -> None:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.update(_dotted(d) for d in n.decorator_list if _dotted(d))
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for part in [*n.decorator_list, n.args]:
                visit(part)
            return
        if isinstance(n, ast.Lambda):
            return
        if isinstance(n, ast.If) and _is_main_check(n.test):
            for part in [n.test, *n.orelse]:
                visit(part)
            return
        if isinstance(n, ast.Call):
            # Called, or handed to something that will call it: a thread or
            # process target=, a threading.Timer, or atexit.register. Other calls
            # may only wrap or register it (functools.partial, a plugin
            # registry), so they do not count.
            func = _dotted(n.func)
            handed = [k.value for k in n.keywords if k.arg == "target"]
            if func == "atexit.register":
                handed += n.args[:1]
            if func in ("threading.Timer", "Timer"):
                handed += n.args[1:2] + [k.value for k in n.keywords if k.arg == "function"]
            called = n.func
            if (  # getattr(m, "f")() calls m.f
                isinstance(called, ast.Call)
                and _dotted(called.func) == "getattr"
                and len(called.args) >= 2
                and isinstance(called.args[1], ast.Constant)
                and isinstance(called.args[1].value, str)
            ):
                called = ast.Attribute(called.args[0], called.args[1].value, ast.Load())
            for value in [called, *handed]:
                if _dotted(value):
                    names.add(_dotted(value))
                elif isinstance(value, ast.Lambda):  # target=lambda: (sleep(3), f())
                    names.update(_called_names(value.body))
        for child in ast.iter_child_nodes(n):
            visit(child)

    visit(node)
    return names


def _dotted(node: ast.AST) -> str:
    """a.b.c for a chain of names, else empty: no import aliases resolved."""
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return node.id if isinstance(node, ast.Name) else ""


def _bindings(tree: ast.AST) -> tuple[dict[str, str], list[tuple[ast.expr, list[ast.expr]]]]:
    """In one walk: imported names to their dotted names, and (value, targets) of assignments.

    The assignments let the visitor bind names to new sockets once imports are known.
    """
    aliases: dict[str, str] = {}
    assignments: list[tuple[ast.expr, list[ast.expr]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            assignments.append((node.value, node.targets))
        elif isinstance(node, ast.withitem) and isinstance(node.context_expr, ast.Call):
            if node.optional_vars is not None:
                assignments.append((node.context_expr, [node.optional_vars]))
    return aliases, assignments


class _Visitor(ast.NodeVisitor):
    def __init__(
        self,
        aliases: dict[str, str],
        assignments: list[tuple[ast.expr, list[ast.expr]]],
        top_level_only: bool,
        called: dict[ast.AST, str],
    ) -> None:
        self.aliases = aliases
        self.top_level_only = top_level_only
        self.called = called  # functions that run on import: read as top level
        self.via = ""  # how the function being read is reached, for the hit detail
        # Names bound to a new client, so s.connect() resolves to socket.socket().connect.
        for value, targets in assignments:
            bound = self.resolve(value)
            if bound and bound.endswith("()"):
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = bound
        self.hits: list[Hit] = []
        self.calls: list[str | None] = []  # the calls whose arguments we are inside
        self.function_depth = 0
        self.in_env_keyword = 0  # inside env=..., where copying os.environ is normal
        self.open_files: list[dict[str, str | None]] = []  # `with open(p) as f` in scope
        # Files each function in scope wrote to, each as the parts of its path.
        self.written: list[list[frozenset[str]]] = [[]]

    def resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if not isinstance(node, ast.Call):
            return None
        # Resolved once: twice per call is exponential down a.b().c().d() chains.
        func = self.resolve(node.func)
        if func in _CLIENTS:
            return f"{func}()"
        if (
            func in ("__import__", "importlib.import_module")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value
        return None

    def hit(self, kind: str, node: ast.AST, detail: str) -> None:
        if self.top_level_only and self.function_depth and kind != "hidden":
            return
        if self.via:
            # exec in a followed function runs code its caller hands it (six.exec_,
            # code generation in attrs): only that caller's argument could say what.
            if kind in ("exec", "exec_file"):
                return
            detail = f"{detail} ({self.via})"
        self.hits.append(Hit(kind, getattr(node, "lineno", 0), detail))

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        if node in self.called:
            outer, self.via = self.via, self.called[node]
            self.generic_visit(node)
            self.via = outer
            return
        self.function_depth += 1
        self.written.append([])
        self.generic_visit(node)
        self.written.pop()
        self.function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]
    visit_Lambda = visit_FunctionDef  # type: ignore[assignment]

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        # `with open(p) as f:` names f's path for f.read() in the body, unless the
        # body binds f to something else.
        rebound = {
            n.id
            for stmt in node.body
            for n in ast.walk(stmt)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
        }
        scope: dict[str, str | None] = {}
        for item in node.items:
            value, target = item.context_expr, item.optional_vars
            if not isinstance(target, ast.Name):
                continue
            if (opened := self._opened(value)) is not False:
                scope[target.id] = None if target.id in rebound else opened
        self.open_files.append(scope)
        self.generic_visit(node)
        self.open_files.pop()

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_If(self, node: ast.If) -> None:
        # `if __name__ == "__main__":` runs only as a script, never on import.
        if _is_main_check(node.test):
            self.visit(node.test)
            self.function_depth += 1
            for child in node.body:
                self.visit(child)
            self.function_depth -= 1
            for child in node.orelse:
                self.visit(child)
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        if (
            isinstance(node.func, ast.Call)
            and self.resolve(node.func.func) == "getattr"
            and len(node.func.args) >= 2
            and isinstance(hidden := self._value(node.func.args[1]), ast.Constant)
            and hidden.value in _HIDDEN_NAMES
        ):
            self.hit("hidden", node, f"reaches {hidden.value} through getattr")
        if (
            name == "getattr"
            and len(node.args) >= 2
            and self.resolve(node.args[0]) in ("builtins", "__builtins__")
            and self._assembled(node.args[1])
        ):
            self.hit(
                "hidden", node, "reaches a builtin through getattr by a name built at run time"
            )
        if name in _DECODERS:
            for arg in node.args:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str | bytes)
                    and _looks_encoded(arg.value)
                ):
                    self.hit("encoded", node, f"decodes a {len(arg.value)}-character blob")
        if name in _NETWORK_CALLS or _is_client_use(name):
            self.hit("network", node, f"calls {name}")
        elif name in _PROCESS_CALLS or (name and name.startswith(_PROCESS_PREFIXES)):
            self.hit("process", node, f"calls {name}")
            for arg in ast.walk(ast.Tuple(elts=node.args, ctx=ast.Load())):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if match := FETCHING_COMMAND.search(arg.value):
                        self.hit("network", node, f"runs a command that fetches ({match.group(0)})")
                        break
        elif name in _EXEC_CALLS:
            arg = node.args[0] if node.args else None
            if arg is not None and (how := self._hiding(arg)):
                self.hit("hidden", node, f"{name} of {how}")
            elif arg is not None and (read := self._file_read(arg))[0]:
                if path := read[1]:
                    self.hit("exec_file", node, path)
                else:
                    self.hit("exec", node, f"{name} of a file it cannot read here")
            elif (
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and arg.value.strip() in _HIDDEN_NAMES
            ):
                # eval("eval") hands back the builtin under another name (BlankOBF).
                self.hit("hidden", node, f"reaches {arg.value.strip()} through {name} of its name")
            elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                # The code is in plain sight: read it, and report what it does here.
                try:
                    inner = analyse(arg.value, self.top_level_only)
                except (SyntaxError, ValueError, RecursionError):
                    self.hit("exec", node, f"calls {name}")
                else:
                    for found in inner:
                        if found.kind not in _CHANNELS:  # the string itself is read for those
                            self.hit(found.kind, node, found.detail)
            else:
                self.hit("exec", node, f"calls {name}")
        elif name in _ENVIRON_BULK_CALLS and not self.in_env_keyword:
            self.hit("environ", node, f"calls {name}")
        self._call_kinds(node, name)
        if not self.in_env_keyword:
            for arg in node.args:
                if self.resolve(arg) == "os.environ":
                    self.hit("environ", node, "passes all of os.environ")
        # A method on something unresolved, Path(p).expanduser(), is kept by method name.
        if name is None and isinstance(node.func, ast.Attribute):
            self.calls.append(f".{node.func.attr}")
        else:
            self.calls.append(name)
        self.visit(node.func)  # a method call on a call: Path(p).read_text()
        for arg in node.args:
            self.visit(arg)
        for keyword in node.keywords:
            is_env = keyword.arg == "env"
            self.in_env_keyword += is_env
            self.visit(keyword.value)
            self.in_env_keyword -= is_env
        self.calls.pop()

    def _call_kinds(self, node: ast.Call, name: str | None) -> None:
        """Hits only call-time combinations use: alone, each is everyday code."""
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name in _DECODERS:
            self.hit("decode", node, f"calls {name}")
        # A file written here and run later in the same function: a dropper.
        mode = node.args[1] if len(node.args) > 1 else None
        mode = next((k.value for k in node.keywords if k.arg == "mode"), mode)
        target: ast.AST | None = None
        if (
            name in _OPENERS
            and isinstance(mode, ast.Constant)
            and set(str(mode.value)) & set("wax")
        ):
            target = node.args[0] if node.args else None
        elif name in _COPIES:
            target = node.args[1] if len(node.args) > 1 else None
        elif method in ("write_bytes", "write_text"):
            target = node.func.value  # type: ignore[attr-defined]
        if target is not None and (parts := frozenset(_path_keys(target))):
            self.written[-1].append(parts)
        process = name in _PROCESS_CALLS or (name and name.startswith(_PROCESS_PREFIXES))
        if process or name in _LOADERS or name == "os.startfile":
            # What runs: the arguments, not cwd= or env= (a tool run in the folder written to).
            args = [
                *node.args,
                *(k.value for k in node.keywords if k.arg in ("args", "executable")),
            ]
            used = {key for arg in args for key in _path_keys(arg, deep=True)}
            if any(_names_whole_path(parts, used) for parts in self.written[-1]):
                self.hit("runs_written", node, f"runs a file it wrote ({name})")
        if name == "os.dup2" and node.args and isinstance(node.args[0], ast.Call):
            if isinstance(node.args[0].func, ast.Attribute) and node.args[0].func.attr == "fileno":
                self.hit("redirect", node, "points a standard stream at a socket or file")
        for arg in ast.walk(ast.Tuple(elts=node.args, ctx=ast.Load())) if process else ():
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if PIPE_TO_SHELL.search(arg.value):
                    self.hit("fetch_run", node, "runs a command that downloads code and runs it")
                    break

    def visit_Expr(self, node: ast.Expr) -> None:
        # A string on its own (a docstring) does nothing: prose there is not a path.
        if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._check_iterated(node.iter)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self._check_iterated(node.iter)
        self.generic_visit(node)

    def visit_FormattedValue(self, node: ast.FormattedValue) -> None:
        if self.resolve(node.value) == "os.environ":
            self.hit("environ", node, "formats all of os.environ")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # A path counts when something around it does more than build or test the path.
        if not isinstance(node.value, str):
            return
        if all(c in _PATH_BUILDERS for c in self.calls):
            # Named, not used: only call-time combinations (BKT-CALL-003) count that.
            if match := _PERSISTENCE_PATH.search(node.value):
                self.hit("names_persistence", node, f"names a start-up location ({match.group(0)})")
            return
        if match := _SECRET_PATH.search(node.value):
            self.hit("secrets", node, f"passes a credential path ({match.group(0).strip('/~')})")
        elif match := _PERSISTENCE_PATH.search(node.value):
            self.hit("persistence", node, f"passes a start-up location ({match.group(0)})")

    def bind_files(self, tree: ast.AST) -> None:
        """Names for this file's own folder, and for files opened by a known path.

        A name bound more than once to different things is left unknown, so
        `with open('v.py') as f` cannot vouch for a later `with open(x) as f`.
        """
        pairs: list[tuple[str, ast.expr]] = []
        bindings: dict[str, int] = {}  # every binding: assignments, loops, parameters
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                bindings[node.id] = bindings.get(node.id, 0) + 1
            elif isinstance(node, ast.arg):
                bindings[node.arg] = bindings.get(node.arg, 0) + 1
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                targets, value = [node.optional_vars], node.context_expr
            else:
                continue
            pairs += [(t.id, value) for t in targets if isinstance(t, ast.Name)]
        here: dict[str, int] = {}
        for name, value in pairs:
            here[name] = here.get(name, 0) + (self._here_levels(value) == 1)
        self.here = {name for name, n in here.items() if n == bindings.get(name)}
        # Names bound exactly once, so a path held in one can be followed.
        self.single = {name: value for name, value in pairs if bindings.get(name) == 1}
        paths: dict[str, list[str | None]] = {}
        for name, value in pairs:
            if (opened := self._opened(value)) is not False:
                paths.setdefault(name, []).append(opened)
        self.handles = {
            name: found[0]
            for name, found in paths.items()
            if len(found) == bindings.get(name) and len(set(found)) == 1
        }

    def _here_levels(self, node: ast.AST) -> int | None:
        """How many folders up from __file__ node is, when built only from __file__."""
        if isinstance(node, ast.Name):
            return 0 if node.id == "__file__" else None
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            inner = self._here_levels(node.value)
            return None if inner is None else inner + 1
        if not isinstance(node, ast.Call) or node.keywords:
            return None
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("resolve", "absolute"):
            return self._here_levels(node.func.value) if not node.args else None
        if len(node.args) != 1:
            return None
        inner = self._here_levels(node.args[0])
        func = self.resolve(node.func)
        if inner is not None and func == "os.path.dirname":
            return inner + 1
        if func in ("os.path.abspath", "os.path.realpath", "pathlib.Path"):
            return inner
        return None

    def _opened(self, node: ast.AST) -> str | None | bool:
        """For open(p) or Path(p).open(): the local path, or None when it is not
        local. False when node does not open a file."""
        if not isinstance(node, ast.Call):
            return False
        if self.resolve(node.func) in _OPENERS:
            return self._local_path(node.args[0]) if node.args else None
        if isinstance(node.func, ast.Attribute) and node.func.attr == "open":
            return self._local_path(node.func.value)  # (here / "v.py").open()
        return False

    def _local_path(self, node: ast.AST, seen: frozenset[str] = frozenset()) -> str | None:
        """A path relative to this file's folder ("" for the folder itself), or None.

        Constants, names bound once to such a path, and parts joined with
        os.path.join or / onto this file's folder (built only from __file__) or
        onto another local path. An absolute part is never local: os.path.join
        would start again from it, and the file is not in the package.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.replace("\\", "/")
            return None if value.startswith("/") or value[1:3] == ":/" else value
        if isinstance(node, ast.Name):
            if node.id in self.here:
                return ""
            if node.id in self.single and node.id not in seen:
                return self._local_path(self.single[node.id], seen | {node.id})
            return None
        if self._here_levels(node) == 1:
            return ""
        if (
            isinstance(node, ast.Call)
            and self.resolve(node.func) == "pathlib.Path"
            and len(node.args) == 1
        ):
            return self._local_path(node.args[0], seen)
        parts: list[ast.expr] = []
        if isinstance(node, ast.Call) and self.resolve(node.func) in (
            "os.path.join",
            "pathlib.Path",
        ):
            parts = list(node.args)  # Path("pkg", "v.py") joins its parts as os.path.join does
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                parts.insert(0, node.right)
                node = node.left
            parts.insert(0, node)
        if len(parts) < 2:
            return None
        names = [self._local_path(part, seen) for part in parts]
        if any(name is None for name in names) or "" in names[1:]:
            return None
        return "/".join(name for name in names if name)  # type: ignore[misc]

    def _file_read(self, node: ast.AST) -> tuple[bool, str | None]:
        """Whether node reads a whole file, and its path when that is this file's own
        folder: open(p).read(), Path(p).read_text(), f.read() of `with open(p) as f`,
        (here / "v.py").read_text(), or compile() of one. The setup.py version trick."""
        if not isinstance(node, ast.Call):
            return False, None
        if isinstance(node.func, ast.Name) and node.func.id == "compile" and node.args:
            return self._file_read(node.args[0])
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "read_text")):
            return False, None
        target = node.func.value
        if isinstance(target, ast.Name):
            for scope in reversed(self.open_files):
                if target.id in scope:
                    return True, scope[target.id]
            return True, self.handles.get(target.id)
        if isinstance(target, ast.Call) and self.resolve(target.func) in _OPENERS:
            return True, self._local_path(target.args[0]) if target.args else None
        return True, self._local_path(target)  # Path(...), here / "v.py", or not a path

    def _value(self, node: ast.AST, seen: set[str] | None = None) -> ast.AST:
        """node, or for a name bound once in this file, the value bound to it,
        followed through other such names. seen: names already followed."""
        seen = set() if seen is None else seen
        while isinstance(node, ast.Name) and node.id in self.single and node.id not in seen:
            seen.add(node.id)
            node = self.single[node.id]
        return node

    def _assembled(self, node: ast.AST) -> bool:
        """Whether a name handed to getattr is assembled at run time ('ch' + 'r',
        ''.join(...)), in place or in a name bound once: an obfuscator's shape. A
        plain variable is introspection (numpy, pytest) and is left alone."""
        seen: set[str] = set()  # one set for the whole chain: x = x.strip() must end
        node = self._value(node, seen)
        # Trimmed or recased, a name is still what it was: name.removeprefix("builtins.")
        # of a plain variable is a type lookup (flake8-bugbear), of a literal is assembly.
        while (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _TRIMS
        ):
            node = self._value(node.func.value, seen)
            if isinstance(node, ast.Constant):
                return True
        if seen and not self._from_literals(node):
            return False  # a name held from a lookup (sphinx: t = node.get(...)) is plain
        return isinstance(node, (ast.BinOp, ast.Call, ast.Subscript, ast.JoinedStr))

    def _from_literals(self, node: ast.AST, memo: dict[str, bool] | None = None) -> bool:
        """Whether a value is built from literals alone: chr() codes joined, a
        decoded constant, operator.add of two strings. Its names are builtins
        that build strings, decoders, string modules, its own comprehension and
        lambda variables, and names bound once to such values in turn
        (_A = "ex"; _N = _A + "ec"). memo: names already decided."""
        memo = {} if memo is None else memo
        local: set[str] = set()  # comprehension and lambda variables
        for scope in ast.walk(node):
            if isinstance(scope, ast.comprehension):
                local |= {n.id for n in ast.walk(scope.target) if isinstance(n, ast.Name)}
            elif isinstance(scope, ast.Lambda):
                local |= {a.arg for a in ast.walk(scope.args) if isinstance(a, ast.arg)}
        decoders = {
            id(head)
            for n in ast.walk(node)
            if isinstance(n, ast.Attribute) and self.resolve(n) in _DECODERS
            for head in ast.walk(n)
        }
        for name in ast.walk(node):
            if (
                not isinstance(name, ast.Name)
                or name.id in _BUILDERS | local
                or id(name) in decoders
            ):
                continue
            resolved = self.resolve(name) or ""
            if resolved in _DECODERS or resolved.split(".")[0] in _STRING_MODULES:
                continue
            if name.id not in self.single:
                return False  # a lookup (node.get(...)), a parameter, a loop variable
            if name.id not in memo:
                memo[name.id] = False  # a name built from itself builds nothing
                memo[name.id] = self._from_literals(self.single[name.id], memo)
            if not memo[name.id]:
                return False
        return True

    def _hiding(self, node: ast.AST) -> str | None:
        """How the argument of an exec call hides its code, or None."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and (decoder := self.resolve(child.func)) in _DECODERS:
                return f"data decoded by {decoder}"
            if isinstance(child, ast.Slice) and _is_minus_one(child.step):
                return "a reversed string"
            if isinstance(child, ast.BinOp) and isinstance(child.op, ast.BitXor):
                return "XOR-decoded data"
        return None

    def _check_iterated(self, node: ast.AST) -> None:
        if self.resolve(node) == "os.environ":
            self.hit("environ", node, "iterates over os.environ")


def _names_whole_path(parts: frozenset[str], used: set[str]) -> bool:
    """Whether a run's arguments name every part of a written path. A constant
    part also counts inside a command line (os.system("start C:/x/s.exe")) when
    it holds a folder or is the command itself, so "jq . out.json" does not run
    out.json."""
    commands = [key[1:] for key in used if key[0] in "'\""]
    for part in parts:
        if part in used:
            continue
        text = part[1:-1] if part[0] in "'\"" else ""
        if not text or not any(
            text in c and ("/" in text or "\\" in text or c.lstrip().startswith(text))
            for c in commands
        ):
            return False
    return True


def _path_keys(node: ast.AST, deep: bool = False) -> set[str]:
    """Names (a, self.path) and string constants a path is built from, to match
    a file written with one run later. deep: every name inside, for the run side."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        # "/" or ".py" alone would join unrelated paths
        return {repr(node.value)} if len(node.value) >= 4 else set()
    if dotted := _dotted(node):
        keys = {dotted}
        if deep and isinstance(node, ast.Attribute):
            keys |= _path_keys(node.value, deep)
        return keys
    parts: list[ast.AST] = []
    if isinstance(node, ast.Call):
        parts = [*node.args, *(k.value for k in node.keywords)]
        if deep or isinstance(node.func, ast.Attribute) and not _dotted(node.func):
            parts.append(node.func)
    elif isinstance(node, ast.BinOp):
        parts = [node.left, node.right]
    elif isinstance(node, ast.JoinedStr):
        parts = [v.value if isinstance(v, ast.FormattedValue) else v for v in node.values]
    elif deep and isinstance(node, ast.List | ast.Tuple):
        parts = list(node.elts)
    elif deep and isinstance(node, ast.Attribute):
        parts = [node.value]
    return {key for part in parts for key in _path_keys(part, deep)}


def _is_client_use(name: str | None) -> bool:
    """A call on a client object that uses it: Session().get, not Session().close."""
    client, _, method = (name or "").partition("().")
    return client in _CLIENTS and bool(method) and "." not in method and method not in _CLIENT_SETUP


def _is_minus_one(node: ast.AST | None) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        node = node.operand
        return isinstance(node, ast.Constant) and node.value == 1
    return isinstance(node, ast.Constant) and node.value == -1


def _looks_encoded(value: object) -> bool:
    """Long, base64- or hex-alphabet only, and high entropy: packed data, not prose."""
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    if not isinstance(value, str) or len(value) < _ENCODED_MIN_LENGTH:
        return False
    if not _ENCODED_ALPHABET.match(value):
        return False
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())
    return entropy >= _ENCODED_MIN_ENTROPY


def _is_main_check(test: ast.AST) -> bool:
    """`__name__ == "__main__"`, either way round, or an `and` that includes it."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return any(_is_main_check(value) for value in test.values)
    if not isinstance(test, ast.Compare) or not isinstance(test.ops[0], ast.Eq):
        return False
    sides = [test.left, *test.comparators]
    names = {s.id for s in sides if isinstance(s, ast.Name)}
    values = {s.value for s in sides if isinstance(s, ast.Constant)}
    return names == {"__name__"} and values == {"__main__"}
