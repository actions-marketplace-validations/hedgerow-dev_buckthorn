# Rules

Every finding has a rule id. Ids are public and stable within a major version.
npm rules use `BKT-NPM-*` (see npm, at the end); ids that mean the same thing
in both ecosystems (`BKT-SKIP-*`, `BKT-LOCK-*`, `BKT-EXFIL-*`) are shared.

Severity sets the verdict: anything above `info` makes an artifact `flagged`.
`info` notes are context: shown in JSON, hidden in text output, never a
failure on their own. Coverage rules (`BKT-SKIP-*`) mean something was not
read, and make the verdict `not_verified`, never `clean`.

## Coverage

| Rule | Meaning |
|---|---|
| BKT-SKIP-001 | The archive would not open, or the file name is not a wheel or sdist, or a tar holds an npm `package.json` but npm and pip would read it differently, so it is read both ways (see npm), or an sdist member's name holds a backslash (a folder separator on Windows only, so where it unpacks depends on the system), or two sdist members unpack to the same file, or an sdist's `setup.py`, `setup.cfg` or `pyproject.toml` is named in another case (`Setup.py`) or ends in a dot or space, which macOS or Windows read as the real one. |
| BKT-SKIP-002 | An archive limit was hit (member count, member size, total size). What was read is still checked. |
| BKT-SKIP-003 | A metadata or Python file could not be parsed, or was too large to parse, or a package's modules call each other too much to follow every call (see Code that runs at import). In an npm tarball, also: JavaScript that runs on its own and cannot be read (see npm). |
| BKT-SKIP-004 | A link inside an archive or an environment. Links are never followed. |
| BKT-SKIP-005 | An installed distribution has no RECORD, or one that cannot be read, so its files are unknown. |
| BKT-LOCK-002 | A pinned artifact could not be checked (see Lockfiles below). |
| BKT-MCP-001 | What an MCP server runs could not be checked (see MCP configs below). |
| BKT-MCP-005 | The packages an MCP server would install with its own package could not be checked (see MCP configs below). |
| BKT-SKIP-006 | A model repo's config or remote code was not read: not in the repo at that commit, not fetched (a gated repo, a network error), over a limit, not matching the blob id the Hub lists, outside the repo, a class bound some way other than a class statement, or code in another repo during a local scan. See Hugging Face remote code. |

## Code that runs at install

Read from `setup.py` and from a build backend shipped in the sdist. A shipped
backend counts whole, since pip calls its functions by name. In `setup.py`,
what pip runs counts: the top level (an `if __name__ == "__main__":` block
too, since pip runs `setup.py` as the main script), the functions and classes
it refers to, and the commands pip runs. Those are `egg_info`, `dist_info`,
`bdist_wheel` and `editable_wheel` (setuptools' PEP 517 backend), `install`
and `develop` (the legacy route), `bdist_egg` and `easy_install` (an old
`install`), and their sub-commands: `build`, `build_py`, `build_ext`,
`build_clib`, `build_scripts`, `install_lib`, `install_headers`,
`install_scripts`, `install_data` and `install_egg_info`. Without a
`pyproject.toml`, `clean` counts too: pip up to 25 can build with
`setup.py bdist_wheel` itself, and runs `setup.py clean --all` when that
fails. pip never runs `sdist`, `test`, `upload` or a project's own `publish`
or `lint`.

What pip never runs is shown as an info note ("runs only on request, not at
install"), with the same rule id: a command class registered only under other
names (or not at all), a block for such a command on the command line
(`if sys.argv[-1] == "publish":`, `"publish" in sys.argv`,
`sys.argv[1].startswith("pub")`, or `and` with one of these), and a
function nothing that runs refers to (a call commented out). Hidden code and
exfiltration channels count there anyway.

This is read so that an attacker cannot hide install code in it. A function
or class counts as run when code that runs refers to it any way at all: a
call, a name passed on, an attribute of that name, or the name as a word in
a string. A command class counts when registered under a command pip runs,
or anywhere but a plain `cmdclass` in a `setuptools.setup()` call (a dict
display or `dict(...)`, directly or in a name used only there, with names
written out), or when a class that runs subclasses it. It must come from
`setuptools` or `distutils` or another such class, with no decorator,
metaclass or `__init_subclass__`, and defining it must run nothing that could
call its methods: its body holds only methods (with plain defaults and no
decorator but `staticmethod`, `classmethod` or `property`) and literal
values (no call, and no object whose `__set_name__` would be handed the
class). A command named as a word in a string in
code that runs runs too, command class and command-line block alike:
`run_command("publish")`, or setup.py run again in a process
(`python setup.py publish`). A command-line block must test the real
`sys.argv` at an index from 1, or -1 (argv[0] is `setup.py` or a path, and
argv[-2] can be argv[0]), and `"x" in sys.argv[1]` is not one (it is a
substring test, and `"wheel"` is in `bdist_wheel`). `startswith` needs two
letters or more, as one can start a Windows path pip passes.

The whole file counts as install code, as before, when code that runs could
reach a name or a command some other way: `globals()`, `vars()`, `__dict__`,
a frame, the garbage collector, `getattr` or `run_command` with a name not
written out, any of these named in a string or imported by name, `exec` of
unknown code without its own namespace, `sub_commands`, `script_args`, a
`**` mapping into `setup()` not written out, `setup` itself handed on, or
`sys.argv` used other than read. So does a build backend other than
setuptools' own (no `build-backend` means setuptools), or one in the sdist
(`backend-path`), since it may run any command. So do a `setup.cfg`
alias named like a command pip runs (`egg_info = publish egg_info`), a
cmdclass named in `setup.cfg` or `pyproject.toml`, aliases in
`pyproject.toml`, a `distutils.commands` entry point, and any other `.py`
or `.pyw` file in the sdist that reaches into a caller's frame, `__main__`,
`sys.modules`, subclasses or the garbage collector, hands `sys` on or
changes `sys.argv`: any module can run at install, as importing one runs
its package's `__init__` and whatever that imports. So does code in the
sdist that is not read: bytecode, a native module, or an archive zipimport
can load (`.zip`, `.egg`, `.whl`, `.pyz`). A body that shares a line with
code that runs (a test, a decorator, a default or an annotation) counts too,
since findings carry lines.

Not caught: setup.py run again in a process with a command built at run
time. The process call is still reported as install code.

Other `.py` files beside `setup.py` or in a `backend-path` folder may be
imported by them, so their top-level code is read too. So is any local module
`setup.py` or the backend imports (anywhere in the file, including inside an
install command), along with the functions it calls from that module:
`from main import main; main()` reads `main()` as install code. The module is
looked up in every package root (below), since setup.py often puts `src/` on
`sys.path` first: `from pkg import hook; hook()` reads `hook()` in
`src/pkg/__init__.py`. A package
module reached this way is read as install code too, and so are the
functions it calls in the package's other modules, followed as at import
(below). Member names are read as pip unpacks them: one top folder is
stripped only when every file sits in it.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-INSTALL-001 | high | Network access: an HTTP or FTP call, a DNS lookup, connecting or sending on a socket (making one is not enough), or a subprocess command line holding `curl`, `wget`, PowerShell download commands or a URL. |
| BKT-INSTALL-002 | medium | Runs a process (`subprocess`, `os.system`, `os.exec*` and similar, and `pip.main`). Common in packages that build C extensions. |
| BKT-INSTALL-003 | medium | `exec`, `eval` or `compile` of code that cannot be read here. Not raised for a string literal (its code is read and reported in place) or for `exec(open(...).read())`, the usual version-file trick. |
| BKT-INSTALL-004 | high | Passes a credential path to a call that does more than build or test the path (`open`, `shutil.copy`, an unknown helper): `~/.ssh`, `~/.aws`, gcloud, `.git-credentials`, `.netrc`, browser login stores and similar. `os.path.join`, `expanduser`, `Path()` and `exists` alone do not count, nor does holding it in `set()`, `frozenset()`, `tuple()`, `list()` or `dict()`. |
| BKT-INSTALL-005 | high | Passes a start-up location to a call, on the same terms: shell profiles, cron, launch agents, systemd user units, Windows Run keys. |
| BKT-INSTALL-006 | info | Reads the whole environment (`dict(os.environ)`, iterating it). Not raised inside an `env=` argument. |
| BKT-INSTALL-007 | info | The build backend is shipped in the sdist (`backend-path`). Its code is read and reported under the rules above. |
| BKT-INSTALL-008 | critical | Reads credentials or the whole environment **and** uses the network. |
| BKT-INSTALL-009 | info | Names the sdist's build requirements (`build-system.requires` in `pyproject.toml`, the first 10). pip installs them and runs them at install, and they are not read here: check them as you would any dependency. |

An `exec(open('pkg/_version.py').read())` in `setup.py` is not reported as
exec: the named file's top level is read as install-time code in its own
right, since exec runs a file's top level as an import would. The same holds
for `with open(p) as f: exec(f.read())` and `Path(p).open()`, for a path held
in a name bound once, and for paths joined onto `setup.py`'s own folder
(`os.path.join(here, "pkg", "v.py")` or `Path(__file__).parent / "v.py"`,
where `here` is built only from `__file__`). An absolute path is never the
package's own file. An exec of a file the package does not contain, or one in
any other folder or named at run time, is reported as exec, since that code
cannot be read.

## Code that runs at import

Read from every `.py` file a wheel installs to site-packages, and from the
modules of an sdist's packages, which installing it puts there: each folder
from a package root (the top of the sdist, `src/`, or a literal
`package_dir={"": "lib"}` in `setup.py`) down to the file has an
`__init__.py` (so a `src/` with its own `__init__.py` is also a package called
`src`). Code the sdist says it installs is read too, with or without
`__init__.py`: a name listed in an egg-info `top_level.txt`, or the top-level
part of each name in a literal `packages=` list in `setup.py`, brings in that
folder under any package root, whole (a namespace package), or that loose
module (`src/tool.py`); a literal `py_modules=` brings in just its module
files. Test folders at any depth
(`test`, `testing`, `tests*`) and root-level `doc`, `docs`, `example`,
`examples`, `scripts`, `devscripts`, `dev`, `tools`, `build`, `bench`,
`benchmarks` and `ci` folders are skipped, as builds usually leave them out,
unless named as installed that way (test folders inside a package stay out).
These lists are the uploader's word, so they can add code but never hide any.
Files already read as install code are skipped too. Not read yet: namespace
packages and loose modules nothing names that way (a name or root built at
run time or passed through a variable or `**kwargs`, a `package_dir` entry for
a named package, `find_namespace_packages()`, or one given only in
`setup.cfg`, `pyproject.toml` or another build backend's config). Only
top-level code
counts (module and class bodies, including `if`, `try` and `with` blocks),
since function bodies and `if __name__ ==
"__main__":` blocks do not run on import. A module-level function counts as
top-level code when module-level code calls it, applies it as a decorator,
passes it (or a lambda that calls it) as a thread or process `target=` or as
the function of a `threading.Timer`, or passes it to `atexit.register`,
directly or through other such functions. So does a function nested in one
of these that it calls or hands on in the same ways. Applying a decorator
runs the decorator itself, not the wrapper it returns. The finding names the
function and how it is reached: `in f(), called at module level`.

This holds across the files of one wheel, sdist or installed distribution:
`from .m import f; f()`, `from . import m; m.f()`, `import pkg.m as mm;
mm.f()`, `getattr(m, "f")()`, `from .m import *` then `f()`, and a name
another module re-exports all read `f` in `m` as import code. Chains are
followed from file to file. The finding is on the file that holds the code,
since its lines are there, and names the file whose top-level code starts
the chain: `in f(), called at import by pkg/__init__.py`. A `__main__.py`
starts no chain, since only `python -m` runs it. When setup.py imports a
package module, so that it is read as install code, the functions other
package modules call in it are read there too. Following calls re-reads a
module each time it gains functions; if that would re-read more than ten
times the package's Python source, the rest is not followed and BKT-SKIP-003
is raised.

Not followed: methods, functions bound by assignment (`g = m.f; g()`), modules
found at run time (`importlib.import_module`, `sys.modules`), a thread target
passed by position, `threading` or `atexit` imported under another name, and
other distributions' functions. `exec` inside a followed function is not
reported, since the code it runs comes from its caller. Same meanings and
severities as the install rules.

In a wheel or an installed environment, these findings are info in a test
file (under a top-level `test`, `tests` or `_tests` folder, under a `test`,
`tests`, `_tests` or `testing` folder inside a package, or named
`conftest.py`, `test_*.py` or `*_test.py` inside a package) that nothing
outside the tests imports: `import pkg` never runs it. A top-level module or
a top-level `testing` package is never a test file, since the user may import
it by that name. A test file still counts when a module that runs imports it,
directly, relatively, through other test files, by a dotted name anywhere in
a string (importlib, `pkg.tests:x`) or by a word of a string with no spaces
(a relative name or a path), or when an entry point names it or a module
inside it (a `pytest11` plugin loads in every project). No test file is
quiet when the code that runs walks its package's modules (`pkgutil`), or
both imports by a name it builds and lists a directory, in the same file or
not: then it may load any of them. A built name with no listing is the lazy
loader many big packages use, and does not count. The functions a test
file calls in other modules count only when the test file does. A module too
large to parse, or a member name with a backslash, leaves every finding as it
is.

The same goes for code under a folder no `import` statement can name, in a
wheel, an environment or an sdist: a folder inside the tree, below the
top-level name, that is not an identifier or is a keyword
(`node_modules/npm/node_modules/node-gyp/gyp/gyp_main.py` and
`node-gyp/__init__.py` itself, a `.hidden` folder). Only importlib or a path can load it, so its findings are info
until a module that runs (or an sdist's install code) names it, in the ways
listed above, hyphens and all (`importlib.import_module("pkg.my-mod")`). A
name built at run time counts as for test files. pycasbin's sdist
names `node_modules` in `top_level.txt`, so pip installs it, but nothing
imports it. A top-level name or a module's own file name that cannot be
imported still counts: it is how the distribution names its own code, and
malicious uploads often do (`dify-api/__init__.py`, `123bla/`). A folder
with a dot inside its name (`a.b`) is still read, as its parts look like
identifiers.
Hidden-code rules count anywhere.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-IMPORT-001 | high | Network access at import. |
| BKT-IMPORT-002 | medium | Runs a process at import. |
| BKT-IMPORT-003 | medium | `exec`, `eval` or `compile` at import. |
| BKT-IMPORT-004 | high | Passes a credential path to a call at import. |
| BKT-IMPORT-005 | high | Passes a start-up location to a call at import. |
| BKT-IMPORT-006 | info | Reads the whole environment at import. |
| BKT-IMPORT-008 | critical | Reads credentials or the whole environment **and** uses the network at import. |

## Hidden code

Raised anywhere in a file, inside functions too, in wheels, in sdist install
code and in sdist package modules.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-HIDE-001 | high | `exec`, `eval` or `compile` of data decoded at run time (base64, zlib, marshal, rot13, hex, a reversed string, XOR), or reaching `exec`, `eval`, `system` or `__import__` through `getattr` by name, or through `eval` of the name itself (`eval("eval")`), or reaching any builtin through `getattr` by a name assembled at run time (`'ch' + 'r'`, `''.join(map(chr, ...))`). The name can be written in the call or held in a variable the file binds once to a value built from literals (`_RUN = chr(101) + ...`, then `getattr(builtins, _RUN)`; chr() codes joined, a decoded constant, `operator.add` of strings), with names inside that value followed the same way (`_A = 'ex'; _RUN = _A + 'ec'`). A variable holding a lookup (`t = node.get(...)`), a parameter or a loop variable is not. A plain variable is not enough, and nor is one only trimmed or recased (`name.removeprefix("builtins.")`, `.strip()`, `.lower()`), which is a type lookup. |
| BKT-HIDE-002 | low | A long, high-entropy base64 or hex literal passed to a decoder. |
| BKT-HIDE-003 | medium | A `.pyc` with no `.py` beside it: a module whose code cannot be read. |
| BKT-HIDE-004 | high | A `__pycache__` `.pyc` that is hash-based with source checking off: Python runs it instead of the `.py` beside it, so the readable source can be a decoy. |

## Shipped exfiltration channels

The one exception to "only what runs": many stealers send their loot from a
function the user calls, or from a console script, so nothing runs at install
or import. What they do ship is the channel itself, with its secret. A live
Discord webhook or Telegram bot token in a package lets anyone who holds it
post there, and real libraries take these from their user, not from their own
source.

Read from string constants (bytes too) anywhere in a Python file, inside
functions as well: every `.py` a wheel installs to site-packages, and in an
sdist the install code and package modules read by the rules above. Only
constants, not raw text: comments and non-Python files are not read, since
data files (a PDF in a test folder) can hold a token-shaped run by chance.
Escapes are decoded and adjacent literals count as one string
(`"https://discord.com/api/" "webhooks/..."`). A constant that is wholly
base64 (line breaks aside) is decoded and read too. Test files count, unlike for the import
rules: the channel is shipped whether or not anything runs it, and sdist test
folders are already left out as not installed. The value is never shown: the
finding names the kind of channel and the lines.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-EXFIL-001 | medium | A Discord webhook URL with its id and token: `discord.com` or `discordapp.com` in any case (so `canary.` and `ptb.` hosts too), `/api/webhooks/` or `/api/vN/webhooks/`, a 17 to 20 digit id and a 60 to 80 character token. |
| BKT-EXFIL-002 | medium | A Telegram bot token: an 8 to 10 digit bot id, a colon and a 35 character secret starting `AA`, alone or after `bot` in a URL. Real tokens have that shape; the docs example (`123456:ABC-DEF...`) does not. |

Not caught: a channel assembled at run time (`"disc" + "ord.com"`, a format
string, a list joined), base64 inside a longer string, other encodings (XOR,
hex, zlib), a channel fetched from elsewhere or kept in a non-Python file,
files the rules above do not read (loose modules and namespace packages
nothing names as installed, a wheel's `.data/scripts`), and other channels (Slack webhooks, paste sites, tunnels). A
package that is a Discord or Telegram tool and hard-codes its own channel is
flagged as well.

## Code that runs when called

Off by default; on with `BUCKTHORN_CALL_TIME=1`. Much malware does its work
in a function the user calls, or in a script, so nothing runs at install or
import. Reading that code the same way flags most normal packages too: in a
function, a network call, a subprocess or a file write is everyday library
code. So here a single capability is never flagged. Only a combination in one
unit of code is, when together the parts look like a payload.

What is read: the functions of every installed module that nothing runs at
install or import (methods too, and those of a file `setup.py` execs), its
`if __name__ == "__main__":` block as the unit `<main>`, and the whole of
every other Python file in the artifact (tests, docs, examples, scripts, a
wheel's `.data/scripts`), its top level as the unit `<module>`. Test files
count here even when the import rules treat them as info: they run when the
tests run. Install and import code keep the rules above, unchanged. A file too large or that will not parse adds nothing here:
an installed module is already reported as not parsed (BKT-SKIP-003), and the
other files never ran on their own.

A unit is one function plus the functions it calls in the same file: by bare
name, or a method of the same class through `self`, `cls` or the class name,
followed through further calls. Nested functions are units of their own and
part of the function that calls them. The finding names the units and the
lines of the hits that make the combination, up to three of each kind per
unit.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-CALL-001 | high | Fetches code and runs it. Network access (as BKT-IMPORT-001) in one unit with any of: `exec`, `eval` or `compile` of code not readable here or of decoded data; running a file the same function wrote (`open(p, "wb")`, `urlretrieve(url, p)`, `shutil.copy`, `write_bytes`, then every part of `p` in the arguments of a process call, `os.startfile` or a library loader, not in `cwd=`; or a constant path inside a command line, when it holds a folder or is the command). A command that pipes a download into a shell (`curl ... \| sh`, `irm ... \| iex`, as BKT-MCP-004) counts on its own. |
| BKT-CALL-002 | high | Decodes data and runs it: a decoder (as BKT-HIDE-001: base64, zlib, marshal, hex and the rest) in one unit with `exec`, `eval` or `compile`, or running a file the same function wrote. BKT-HIDE-001 already covers the two in one expression in the files it reads; this covers them split across statements or functions, and in tests and scripts. |
| BKT-CALL-003 | high | Uses a start-up location and the network: a start-up location (the BKT-INSTALL-005 list) named anywhere in a unit, even only in a path builder, with network access. Shell completion installers write to shell profiles too, but do not fetch. |
| BKT-CALL-004 | high | A reverse shell: `os.dup2(x.fileno(), ...)` in one unit with network access and a process call (`pty.spawn`, `subprocess`). A daemon that points its streams at `/dev/null` has no network access there. |
| BKT-CALL-005 | high | Reads credentials and uses the network: a credential path passed to a call that does more than build or test it (as BKT-INSTALL-004), with network access, in one unit. A path only built (`os.path.join(home, ".ssh")`, as SSH clients do) does not count, nor does reading the whole environment, which API clients do all the time. |

Not caught: these rules match plain payloads, and a two-line rewrite dodges
each one. A credential path held in a variable before `open`, a descriptor
held in a variable before `dup2` or passed as `stdin=`, `curl -o x && sh x`,
a command built from several strings, a file written by `NamedTemporaryFile`
or run under another name or from another function, and calls through a
variable, `getattr`, a callback or another module.

## Code that runs at interpreter start

"Installed to site-packages" includes a wheel's `purelib` and `platlib`
folders and its data scheme's `lib/pythonX.Y/site-packages` (or
`Lib/site-packages`), which lands there in a virtualenv.

An sdist's `setup.py`, build backend or their config can put any file it
ships at the top of site-packages (`data_files`, a copy in a custom install
command, a folder mapped to the wheel root), so every `.pth` an sdist ships is
read as installed, wherever it sits and whether or not anything names it.
`.pth` files in test folders at any depth (`test`, `testing`, `tests*`) are
skipped, unless the install code or config mentions `.pth` anywhere (`setup.py`,
`setup.cfg`, `pyproject.toml`, the backend, the files read as install code).
When it does, string literals in the install code are also read as `.pth`
text, for install code that writes the file itself; the finding then points
at the line in that file. Code after `-c` in a command list passed straight to
a process call (`subprocess.run([sys.executable, "-c", "import x"])`) is not
read this way: the process runs it, nothing writes it to a file.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-PTH-001 | medium | A `.pth` file installed to site-packages (for an sdist, as above) has an `import` line, which runs on every Python start. |
| BKT-PTH-002 | high | That line touches `sys.modules`, `builtins`, `meta_path` or `path_hooks` (the ShadowPickle "overwritten module" shape). |
| BKT-START-001 | high | The wheel installs `sitecustomize` or `usercustomize`, which Python imports on every start. |
| BKT-SCRIPT-001 | high | A console script, GUI script or `.data/scripts` file named `python`, `pip`, `git` or `ssh` (version suffixes and `.exe` included), unless the distribution is that tool. |

## Unexpected binaries

| Rule | Severity | Meaning |
|---|---|---|
| BKT-BIN-001 | medium | A native library (`.so`, `.pyd`, `.dll`, `.dylib`) in a wheel tagged pure Python, or in an sdist. |
| BKT-BIN-002 | high | An ELF, Mach-O or PE executable named like source, text or an image. |
| BKT-BIN-003 | info | A standalone executable in a pure-Python wheel or an sdist. pip and setuptools ship Windows launchers this way. |

An sdist ships source, so it is read like a pure-Python wheel: a binary in
it was not built from anything read here. Every file counts, wherever it
sits, except in test folders at any depth (`test`, `testing`, `tests*`),
which builds leave out and where parser fixtures live. An empty file holds
no code: meson's test cases (vendored in numpy) ship empty
`libboost_regex.so.0.1.0` stand-ins, so in an sdist those are left out.

## Package integrity

| Rule | Severity | Meaning |
|---|---|---|
| BKT-REC-001 | high | A wheel file does not match its hash in `RECORD`. Every copy of a duplicated name is checked. |
| BKT-REC-002 | medium | A wheel file has no sha256-or-stronger hash in `RECORD`, or there is no `RECORD`, or it cannot be read (a field too long for pip to read either). |
| BKT-META-001 | medium | `METADATA` or `PKG-INFO` is missing or names another package or version than the file name, or a wheel does not have exactly one `.dist-info` folder. |

## Lockfiles

`buckthorn check` fetches pinned artifacts from PyPI and checks each one's
sha256 before reading a byte of it. For `package-lock.json` and
`npm-shrinkwrap.json` (version 2 or 3) it fetches each tarball from
registry.npmjs.org (by name and version when an entry has no `resolved`
URL) and checks its sha512 `integrity` the same way; a package
whose `os` or `cpu` field rules out this machine is skipped like another
platform's wheel. Lockfiles list every platform's wheels,
so by default only the file this machine would install is checked for each
package (the best-matching wheel, else the sdist). `--all-files` checks every
pinned file.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-LOCK-001 | high | The downloaded file's hash (sha256, or sha512 for npm) is not the one the lockfile pins. The file is not scanned. |
| BKT-LOCK-002 | info (coverage) | A pin could not be checked: not pinned with `==` and a hash, from another index or a git or local source, not found on PyPI, not fetched, or a file name that is not a plain wheel or sdist name. For npm: a `resolved` URL off registry.npmjs.org (git, local, another registry), no sha512 `integrity`, or a lockfile version 1. |
| BKT-LOCK-003 | info | No file of a pin installs on this machine (a Windows-only wheel on macOS, or an npm package for another `os` or `cpu`), so none was checked. `--all-files` checks them all. |

## MCP configs

`buckthorn check` also reads an agent's MCP config, found by its content, not
its name: the `mcpServers` table of Claude Code (`.mcp.json`, and
`~/.claude.json` with its per-project tables), Claude Desktop, Cursor and
Windsurf, and the `servers` table of VS Code's `mcp.json` (comments and
trailing commas allowed). Agents start these servers when the config loads,
with the developer's credentials.

Each server's launch is read from its `command` and `args`:

- `uvx`, `uv tool run`, `pipx run` and `uv run --with`: the package (`--from`
  or `--spec` if given, `--with` packages too) is fetched from PyPI and its
  sha256 checked, as for a lockfile pin, then scanned. The launcher must be a
  bare name or a plain absolute path: a relative path or one built from a
  variable (`${workspaceFolder}/uvx`) can be a file the repository ships. `pkg==1.0` and `pkg@1.0`
  are pinned. Anything else runs whatever is newest when the agent starts, so
  the newest release the spec allows is checked (not yanked, no pre-release
  unless only those match). The packages that release depends on are checked
  with it; see Dependencies below.
- Wrappers are looked through: `cmd /c` and `sh -c` with a plain command and
  no shell syntax, and `env A=1`.
- npm launchers (`npx`, `bunx`, `pnpm dlx` and the like) and containers
  (`docker run`) are not checked yet.
- `python -m pkg` runs a module already installed somewhere; check that
  environment with `buckthorn env`. A local program or script is your code
  or code already on the machine. So is what `uv run` runs, unless it has
  `--no-project` (else uv installs the project in the folder the agent starts
  it in) and the command is named like a `--with` package (else it is found
  on PATH or on disk); its `--with` packages are still checked. A lone script
  is not scanned: the import rules only read top-level code, and a
  script's `main()` runs too, so a clean result would mean little.
- A remote server (`url`, `serverUrl`, or an `http`, `sse` or `ws` type,
  with no `command`) runs nothing here. Claude Code's `headersHelper` does: it is read as a
  shell command.

A launcher option this check does not know stops it, since its value could
be taken for the package. So does anything that changes where the package
comes from, which version is picked or what runs: an index, a local path or
file, a constraints or config file, a pre-release or resolution setting, a
working folder or an interpreter path (uv runs it). So does an `env` (or `env` wrapper)
that sets `PATH`, `PYTHON*`, `UV_*`, `PIP_*`, `PIPX_*`, `LD_*`, `DYLD_*`,
`VIRTUAL_ENV` or `CONDA_*`, and VS Code's `envFile`. A uv or pip config file
already on the machine, or the machine's own PATH, can do the same and is not
read.

Servers in `~/.claude.json`'s per-project tables are named with the project
path after the key (`db (/path/to/project)`), since two projects can use one
name.

The config holds credentials (`env`, arguments, URLs, headers). Findings name
a server by its config key and a package by its name; no other value from the
config is ever shown.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-MCP-001 | info (coverage) | What the server runs was not checked: npm, a container, a local program, a module from an environment, a git or URL source, another index, an option not known, or a package PyPI does not have. |
| BKT-MCP-002 | info | The server package is not pinned to a version: what was checked is today's newest, and the next release runs at the next start without review. A takeover only has to publish one. Info because most configs leave the pin out, and flagging it would hide real findings; text output still counts them. |
| BKT-MCP-003 | medium | Installed from a git repository with no commit pinned: any push to the branch changes what runs, with no release or hash in between. |
| BKT-MCP-004 | high | A shell command downloads code and runs it (`curl ... \| sh`, `$(curl ...)`, `irm ... \| iex`): no pin, no hash, every start. |
| BKT-MCP-005 | info (coverage) | The packages this one would install with it could not be checked: no static dependency metadata, dependencies computed at build time, a URL or path dependency, a marker that could not be evaluated, a requirement that could not be parsed, no set of versions that satisfies the constraints, or a dependency set past the limit (400 packages, or 5,000 resolution steps). |
| BKT-MCP-006 | info | A remote server: nothing is installed or run on this machine for it. |
| BKT-MCP-007 | info | A dependency is not pinned to one version (`==` or `===`, with no wildcard). The newest release that matches was checked; a later match is installed at the next start. Info, like BKT-MCP-002, so a normal tree does not hide other findings; text output counts them. |

**Dependencies.** uvx and pipx install the server's dependencies, and so does
this check. Nothing is installed, built or run to find them. The list is the
static `requires_dist` PyPI publishes for that release (empty means none;
missing means unknown). When PyPI publishes none, the `Requires-Dist` headers
in the file are read after its sha256 is checked. A wheel that has none
depends on nothing. An sdist that omits them, or marks them dynamic, is
BKT-MCP-005: there is no static list, and nothing is built to find one.

Versions are chosen the way uv and pip choose for this machine. The newest
release the specifiers allow that installs here (not yanked, unless the
requirement pins that version; no pre-release unless only those match;
`Requires-Python` and the wheel tags included). Environment markers are
evaluated for this machine. Only the extras the requirement names are
included. A dependency pinned with `==` or `===` and no wildcard is checked
at that version. Anything else is BKT-MCP-007. The server package itself
stays BKT-MCP-002 when the config leaves the pin out: that is the config,
not a line of someone else's metadata.

`scan` and `check_release` still read one release. A lockfile already names
every dependency; this walk is only for an MCP config, which does not.

## Upgrades

`buckthorn diff OLD NEW` reports only findings the new version has and the old
one does not. Paths are matched with the version taken out, so
`pkg-1.0/setup.py` and `pkg-1.1/setup.py` are the same file.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-DIFF-001 | medium | The old version installed as a wheel; the new one is an sdist, so installing it now runs install-time code. |

## Installed environments

`buckthorn env PATH` reads a virtualenv or site-packages folder in place.
Each distribution's RECORD is the inventory: every file is hashed against it
(a mismatch is BKT-REC-001, a file changed since install) and then read by
the wheel rules above. Large native libraries are hashed in full but only
their first 64 KB is read.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-ENV-001 | info | A file or folder at the top of site-packages that no installed package's RECORD lists. Files are still read by the `.pth`, start-up and import rules, so a dropped `.pth` with an import line is flagged on its own. The `_virtualenv.pth` and `_virtualenv.py` pair a virtualenv seeds is expected while the `.pth` is exactly `import _virtualenv`; the `.py` is still read. |
| BKT-ENV-002 | info | An editable install. The files the environment holds for it (.pth, finder) are read like any other; the project's own code outside the environment is not. |

## npm

`buckthorn scan` reads a tar as an npm tarball when one top folder holds
everything, with a `package.json` in it. `npm pack` calls that folder
`package/`; npm strips it whatever its name, and old registry tarballs vary.
It goes by what the archive holds. When npm and pip would read it
differently, it is read both ways, with the sdist and the npm rules, and gets
a `BKT-SKIP-001`: when npm would drop or merge members (a second top folder,
a file at the top, an absolute name), when Python build files (`PKG-INFO`,
`setup.py`, `setup.cfg`, `pyproject.toml`) sit beside the `package.json` and
the folder is `package/` or the name ends `.tgz` (in any case: `Setup.py` is
`setup.py` on a case-insensitive disk), or when the read was cut short by an
archive limit or by entries past a zero block or a bad header (Python's tar
reader stops there; npm's reads on and installs them). A Python sdist that ships a `package.json` (a JupyterLab
extension, say) is still an sdist: its top folder is `name-version` and its
name ends `.tar.gz`.

What is judged: `package.json`, and the JavaScript that runs on its own,
which is what install scripts run and what `require` or `import` of the
package runs (both below). That JavaScript is tokenized (a stdlib tokenizer,
nothing run). Files that do not run on their own are not read and do not
block `clean`: `bin` commands (they run when the user runs them), files
nothing loads (tests, examples, build scripts, unused files), and type
declarations.

Each file that runs on its own and cannot be read gets a `BKT-SKIP-003` of
its own, so the package is `not_verified`:

- It does not tokenize: a syntax the tokenizer cannot read (an unterminated
  string, regex, template or comment, unbalanced brackets, a bad escape, a
  character it does not know, JSX), text that is not UTF-8, or a limit
  (over 5 MB, over 2,000,000 tokens, or brackets nested over 1,000 deep).
  Past 32 MB of JavaScript read in one package, the rest is not read.
- It loads a module named at run time (`require(name)`, `import(path)`):
  what that runs is not known. A string joined onto `__dirname` is read as
  the path it names. So is a local path the package does not ship (an addon
  built or fetched at install, say): it cannot be read.
- It is, or loads, a native addon: a `.node` file (as an entry, or loaded),
  or `bindings`, `node-gyp-build`, `node-pre-gyp`'s `find` or
  `process.dlopen` called at load.
- An install script builds a `binding.gyp` the package ships (`node-gyp`,
  `node-gyp-build`, `prebuild-install` or `node-pre-gyp` in the command, or
  npm's implicit `node-gyp rebuild`): gyp can run commands (`<!(cmd)`), and
  the code it compiles runs native.
- An install script runs a file that is not JavaScript (`sh install.sh`, a
  binary), a command line that does not parse, or scripts that run each
  other (`npm run`) more than 32 deep.
- Following calls between files would re-read more than ten times the
  package's JavaScript (as for Python), or one name in one scope is bound
  more than 256 ways (a cap on work).
- Two files read differ only in case: npm also installs onto
  case-insensitive disks, where one replaces the other. File names are
  matched in any case for the same reason (`INDEX.JS` is `index.js`).

How Node runs a file decides how it is read: `<!--` and a `-->` at the
start of a line are comments in a script and code in an ES module. `.mjs` is
a module and `.cjs` a script. A `.js` file (or one with another extension)
follows the nearest `package.json`'s `"type"`; with none, it is a module when
it has a top-level `import` or `export` statement, `import.meta` or a
top-level `await`, as Node 22 detects. Node has more triggers (a top-level
`const require`, an `await` in a top-level block), so a `.js` with HTML-like
comments that reads as a script and also as a module is a `BKT-SKIP-003`.

A `package.json` that will not parse, is over 5 MB or is not a JSON object is
`BKT-SKIP-003` and `BKT-NPM-META-001`. So is a field these rules read
(`scripts`, a script, `bin`, `directories.bin`) of the wrong type, as
`BKT-SKIP-003` alone. So is a `bin` (or `directories.bin`) that installs
`package.json` itself as a command: `sh` runs a file with no `#!` line as a
shell script, and a JSON string can hold `$(...)`.

Severities assume the install scripts run. npm 12, pnpm 10, Bun and current
Yarn skip dependency install scripts until you approve them, but older npm in
CI still runs them, and approving one is the decision these findings are for.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-NPM-SCRIPT-001 | medium | `package.json` has a `preinstall`, `install` or `postinstall` script, which npm runs at install. An empty script runs nothing. Info when the script is only a native build (`node-gyp rebuild`, `node-gyp-build`, `node-gyp-build-optional-packages`, `prebuild-install`, with flags, a flag taking at most one plain word such as `-r napi`, and `\|\|` between them) and the package does not ship that tool itself (a `bin` of that name, or anything under `node_modules/`), or when a `binding.gyp` with no `install` or `preinstall` script makes npm run `node-gyp rebuild` (unless `gypfile` is `false`). Info for `prepare` too: npm runs it for a git dependency or a local install, never for a registry tarball. |
| BKT-NPM-INSTALL-001 | high | A `preinstall`, `install` or `postinstall` command fetches: it holds `curl`, `wget`, PowerShell download commands or a URL (as for `BKT-INSTALL-001`), itself or in a script it runs with `npm run`. Or the JavaScript it runs uses the network (below). |
| BKT-NPM-BIN-001 | high | A `bin` command (or a file under `directories.bin`) named `node`, `npm`, `npx`, `git`, `ssh` or `sh`, in any case and after npm keeps only the base name, unless the package is that tool (`npm` also ships `npx`). A string `bin` is named after the package. |
| BKT-NPM-META-001 | medium | `package.json` is missing or unreadable, or its `name` and `version` do not give the file name. The registry names `@scope/pkg` 1.0.0 `pkg-1.0.0.tgz` and `npm pack` names it `scope-pkg-1.0.0.tgz`; both match. |

`BKT-EXFIL-001` and `BKT-EXFIL-002` are read from every key and string value
in `package.json`, as above, and from the JavaScript read (below). Not
judged: `.npmrc` and other files in the tarball that npm does not run.

### JavaScript an install script runs

Each `preinstall`, `install` and `postinstall` command is split into simple
commands at `&&`, `||`, `;`, `|`, `&` and the brackets of `$(...)` and
backquotes, and each is read for the JavaScript it runs:

- `node FILE`, with Node's options skipped, `FILE` found as Node finds it (as
  written, with `.js`, `.json` or `.node` added, or a folder's
  `package.json` `main` or `index.js`).
- `node -e CODE` (or `-p`): the code itself, reported on `package.json` with
  the script's name.
- `node -r MODULE` and the other preload options: the module.
- A file of the package run by path (`./install.js`), or by `sh`, `bash`,
  `python` or another interpreter: read when it is JavaScript (`.js`, `.cjs`,
  `.mjs`, or a `#!` line naming node), else a `BKT-SKIP-003` saying it is not
  read.
- `npm run NAME` (with `preNAME` and `postNAME`), `yarn NAME` and `pnpm NAME`:
  that script's command, in turn, each script once. `cd DIR` changes the
  folder later names are found in, and `sh -c CMD` is read as a command.

- `node-gyp-build` (and `node-gyp-build-optional-packages`): unless building
  from source, it tests the package's prebuilt addon at install, requiring
  the file `package.json` `prebuild.test` names (read as install code) or
  loading a shipped `.node` file (a `BKT-SKIP-003`).

A file the script names that the package does not ship runs nothing. Other
commands (`node-gyp`, a dependency's bin) are not this package's code.

The whole file counts, functions too, as for `setup.py`. So does every local
file it loads (`require`, `import`, `import()`), read like an entry file at
load (below): its top-level code, plus the functions the install file calls
in it (`require('./lib').send()` reads `send`), named in the finding as
`in send(), called at install by package/install.js`. A load named at run time
(`require(name)`) is a `BKT-SKIP-003`, unless it is a string joined onto
`__dirname` (`+`, a template, `path.join` or `path.resolve`).

| Rule | Severity | Meaning |
|---|---|---|
| BKT-NPM-INSTALL-002 | medium | Runs a process: `child_process` `exec`, `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`, `fork`, and `shelljs.exec`, `execa`, `cross-spawn`. A command line holding a download tool or a URL is also `BKT-NPM-INSTALL-001`. |
| BKT-NPM-INSTALL-003 | medium | `eval`, `Function`, `vm.runInThisContext`, `vm.runInNewContext`, `vm.runInContext`, `vm.compileFunction`, `vm.Script` or `vm.SourceTextModule` of code that cannot be read here. A string written out (`Function('return this')`) is read, and what it does is reported in place. |
| BKT-NPM-INSTALL-004 | high | Passes a credential path to a call that does more than build, test or print the path: `~/.ssh`, `~/.aws`, `~/.npmrc`, gcloud, `.git-credentials`, `.netrc`, browser login stores and wallets (the Python list). `path.join`, `path.resolve`, `os.homedir`, `fs.existsSync`, string methods and `console.log` alone do not count, and nor does a string inside an object literal (a config's deny list is data, not a path handed on). |
| BKT-NPM-INSTALL-005 | high | Passes a start-up location to a call, on the same terms: shell profiles, cron, launch agents, systemd user units, Windows Run keys. |
| BKT-NPM-INSTALL-006 | info | Reads the whole environment: `process.env` passed to a call (`JSON.stringify(process.env)`, `Object.keys(process.env)`), spread (`{...process.env}`), iterated (`for (k in process.env)`) or put in a template. Not a copy made for a child process: `{...process.env}` or `Object.assign({}, process.env, ...)` as the value of an `env` property, or of a variable or property named `env` or ending `Env` or `_env` (`const env = {...process.env, A: '1'}`). |
| BKT-NPM-INSTALL-008 | critical | Reads credentials or the whole environment **and** uses the network, in one file. |

Network access (`BKT-NPM-INSTALL-001`) is: `fetch`, `WebSocket`, `http` and
`https` `request` and `get`, `http2.connect`, `net` and `tls` `connect`, a
`dns` lookup, calling an HTTP client package (`axios`, `node-fetch`, `got`,
`request`, `undici`, `needle`, `superagent`, `ws` and the like) or one of its
sending methods (`get`, `post`, ...), or using a socket or client made from one
(`new net.Socket().connect`, `axios.create().get`, `XMLHttpRequest` `open` and
`send`). Making an agent or a client alone is not network access.

Calls are matched by what a name is bound to in its scope:
`const { execSync } = require('child_process')`, `import * as cp from
'node:child_process'`, `__importStar(require('child_process'))` and the
`(0, cp.execSync)(...)` compilers write all read as `child_process.execSync`;
a parameter of the same name does not. A `.call` or `.apply` is the call
itself, and `globalThis.eval` is `eval`.

### JavaScript that runs at load

`require('pkg')` or `import 'pkg'` runs the package's entry files:

- `main`, found as `require` finds it (with `.js`, `.json` or `.node` added,
  or a folder's `index.js`, never a second `package.json`'s `main`); a
  `main` that is missing falls back to `index.js`, as Node does.
- Every `exports` target, the package's own and each subpath's, under every
  condition (`require`, `import`, `node`, `default`, `browser`, ...) except
  `types`. A `*` pattern takes every `.js`, `.cjs` and `.mjs` file that fits
  it. A subpath target is read when it is JavaScript (`.js`, `.cjs`, `.mjs`),
  has no extension, or is a `.node` addon; data (`.json`, `.css`, a `.so`)
  is left out, as a bundler or a loader takes it by its extension. The
  package's own entry (`"."`), as a plain target or under a condition Node
  itself uses (`require`, `import`, `node`, `default`, `module-sync`), is
  read whatever its extension, since `require` runs it as JavaScript.
  TypeScript (`.ts`, `.d.ts` and the like) never is: Node does not strip
  types inside `node_modules`.
- With neither `main` nor `exports`, `index.js`.

From each entry file, the code that runs at load is read, with the local
files it loads (`require`, static `import`, `export ... from`, `import()`):
packages bundled under the tarball's own `node_modules`, the package's own
name and `#imports` names are followed too. A file is read as JavaScript
whatever its extension, as `require` reads it (`require('./data.txt')` runs
`data.txt`), except `.json`. What runs at load:

- The top level: blocks, loops and class bodies count. Function bodies do
  not, with these exceptions.
- Functions invoked where they are written: `(function(){...})()`,
  `!function(){...}()`, `(() => {...})()`, `(function(){...}).call(this)`,
  `new function(){...}`, a function used as a template tag, and
  functions written in the arguments of such a call (the factory of a UMD
  wrapper, a webpack 4 or browserify bundle's modules).
- Functions code that runs calls by name (`f()`, `(f)()`, `(0, f)()`,
  `f.call()`), declared or bound to a name (`const f = () => ...`, an alias
  `const g = f`), found by scope: an inner function or a parameter of the
  same name hides an outer one. So do a method of an object literal bound to
  a name (`o.m()`) and a class's constructor (`new C()`).
- Callbacks handed to `setTimeout`, `setImmediate`, `setInterval`,
  `queueMicrotask`, `process.nextTick`, `new Promise`, `.then`, `.catch`,
  `.finally`, array and string methods (`forEach`, `map`, `filter`,
  `reduce`, `reduceRight`, `some`, `every`, `find`, `findIndex`, `findLast`,
  `findLastIndex`, `flatMap`, `sort`, `replace`, `replaceAll`, `Array.from`),
  and `addEventListener` (a page's code runs on its own `load` events).
- A bundle's modules: the functions in an esbuild or rolldown
  `__commonJS`/`__esm` wrapper and in webpack's `__webpack_modules__` table
  count as running, as the bundle requires them.
- In another file of the package, the functions code that runs calls there:
  `require('./lib').f()`, `const {f} = require('./lib'); f()`,
  `import {f} from './lib.mjs'; f()`, a default export called, and compiled
  `(0, lib_1.f)()`. Exports are found as `exports.f = ...`,
  `module.exports = f` or `{f, g}`, `export function f`, `export const f`,
  `export default` and `export {f}`; `export * from` and
  `module.exports = require(...)` pass the names on. The finding names the
  function and the file that calls it: `in f(), called at load by
  package/index.js`.

Not read: other methods (a class's other than its constructor, an object's
reached any way but `o.m()`, `this.m()`), functions that are only stored,
wrapped or registered (`memoize(fn)`, `emitter.on('x', fn)`), functions
reached through a computed name (`table[k]()`) other than the bundle shapes
above, a class's field initialisers and static blocks, code that runs only
when the user calls what the package exports, other packages that are not
bundled, and `bin` commands, which run only when the user runs them. Files
nothing loads are not read. A file read as install code is not read again.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-NPM-IMPORT-001 | high | Network access at load. |
| BKT-NPM-IMPORT-002 | medium | Runs a process at load. |
| BKT-NPM-IMPORT-003 | medium | `eval`, `Function` or `vm` of code that cannot be read, at load. |
| BKT-NPM-IMPORT-004 | high | Passes a credential path to a call at load. |
| BKT-NPM-IMPORT-005 | high | Passes a start-up location to a call at load. |
| BKT-NPM-IMPORT-006 | info | Reads the whole environment at load. |
| BKT-NPM-IMPORT-008 | critical | Reads credentials or the whole environment **and** uses the network at load, in one file. |

Same meanings as the install rules above.

### Hidden JavaScript

Raised anywhere in a file read by the rules above (install files, entry
files and the files they load), inside functions too, whether or not the
code runs.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-NPM-HIDE-001 | high | `eval`, `Function`, `vm` or `require` of decoded data: `atob`, `Buffer.from`, `String.fromCharCode`, `fromCodePoint`, `unescape`, `decodeURIComponent`, a decipher, `zlib` inflate or gunzip, a reversed string, XOR, or a name bound once to one of these (`const s = atob(x); eval(s)`). Or `eval`, `Function` or `vm` of a string spelt with `\x`, `\u` or octal escapes, or of the name `eval`, `Function` or `require` itself (`eval('eval')`). Or `eval` reached through the global object with code named at run time (`globalThis.eval(s)`); `(0, eval)(s)` is ordinary global eval and is read as `eval`. Or the global object indexed by a name built at run time (`globalThis['ev' + 'al']`, `global[atob(x)]`; a plain variable or a `Symbol` is not enough) or by the name `eval`, `Function`, `require` or `process` (`global['eval']`). Or a module required by a name split into pieces (`require('child_' + 'process')`). |
| BKT-NPM-HIDE-002 | low | A long, high-entropy base64 or hex literal (strings joined with `+` count as one) handed to a decoder: `atob`, `Buffer.from` with `base64`, `base64url` or `hex`, and the rest above. The same test as `BKT-HIDE-002`. |

A string written out and handed to `eval` (`Function('return this')`,
`(0, eval)('this')`) is read as code, and what it does is reported in place.

### Shipped channels in JavaScript

`BKT-EXFIL-001` and `BKT-EXFIL-002` (see Shipped exfiltration channels) are
read from every string and template literal in the JavaScript files read
above, inside functions too, with escapes decoded, and a string that is all
base64 decoded too, as for Python. The value is never shown. Not read:
strings joined at run time (`'https://disc' + 'ord.com/...'`, a template
with `${}` inside the channel), comments, and files the rules above do not
read (`bin` commands, files nothing loads).

## Hugging Face remote code

`from_pretrained(repo, trust_remote_code=True)` imports Python files from the
model repo and builds the classes its configs name. `buckthorn hf org/name@commit`
fetches and reads that code; `buckthorn scan FOLDER` reads a downloaded repo or
a Hub cache snapshot (a folder with no wheels or sdists and a `config.json`,
`tokenizer_config.json`, `preprocessor_config.json` or `processor_config.json`).
Nothing is imported or run.

What is read: every `*config.json` and `modules.json` at the repo root, then
the files they name: `auto_map` values (`module.Class`, or `org/repo--module.Class`
for code in another repo), `custom_pipelines` `impl`s, and sentence-transformers
`modules.json` types that name a `.py` in the repo or another repo, and
`custom_generate/generate.py`, which transformers 5 imports at load whenever
`trust_remote_code` is set, `auto_map` or not. Then every file those import
with `from .x import` or `import .x`, matched the way transformers matches them
(a regex on the text, so a match in a docstring counts too). From the Hub,
files are fetched by commit from `huggingface.co/<repo>/resolve/<commit>/` and
checked against the blob id (or LFS sha256) the Hub API lists for that commit.
Weights are never fetched, and nor are other `.py` files (demos, scripts).
Limits: 5 MB a file, 100 files and 64 MB in all.

What counts as running at load:

- The top level of every file read, as at import: transformers imports each one.
  That includes what defining a class runs: its decorators, its metaclass's
  dunders and a repo base class's `__init_subclass__`.
- For each class the configs name (and its `config_class`): its dunder methods
  but `__call__`, and the methods transformers calls or reads on a model,
  config, tokenizer or processor while loading it (`from_pretrained`,
  `post_init`, `_init_weights`, `tie_weights`, `get_vocab`, `to_dict` and the
  rest, taken from transformers 4.44.2 and 5.22.2), in the class or a base
  class in the repo.
- Any other class of the repo that load-time code refers to: its dunders.
- Whatever these refer to: functions and classes by name or relative import,
  and methods through `self`, `cls`, `super()` or a class name.

`forward`, `generate`, `chat` and other methods the user calls run only when
called, so they are not read unless load-time code refers to them. Hidden code
and exfiltration channels count anywhere in the files read, as for packages.

| Rule | Severity | Meaning |
|---|---|---|
| BKT-HF-001 | high | Network access at model load. |
| BKT-HF-002 | medium | Runs a process at model load. |
| BKT-HF-003 | medium | `exec`, `eval` or `compile` at model load. |
| BKT-HF-004 | high | Passes a credential path to a call at model load. |
| BKT-HF-005 | high | Passes a start-up location to a call at model load. |
| BKT-HF-006 | info | Reads the whole environment at model load. |
| BKT-HF-008 | critical | Reads credentials or the whole environment **and** uses the network at model load. |
| BKT-HF-009 | medium | Fetches more code at model load, which this scan does not read: `hf_hub_download`, `snapshot_download` or `cached_file` of a `.py` file, `get_class_from_dynamic_module`, `torch.hub.load`, any call with `trust_remote_code=True`, or a file whose load-time code both downloads and runs code (`exec`, hidden code, `spec_from_file_location`, `exec_module`, `runpy.run_path`). |
| BKT-HF-010 | low | `auto_map` loads code from another repo (`org/repo--module.Class`; a repo naming itself this way is read at the commit asked for, as transformers does). transformers fetches that at the other repo's main branch whatever revision the model is loaded at, so it can change under a pinned model. From the Hub it is fetched and read at today's commit; a local scan does not read it (BKT-SKIP-006). As info: the repo asked for was not pinned to a commit, with the commit it was read at. |

The rules are the import rules with the trigger changed, so they get their own
ids: an allowlist entry or a policy can treat "runs when you load this model"
apart from "runs when you import this package". In an allowlist, `package` is
the repo id (`org/name`) and `version` the commit. Findings in code from
another repo cannot be allowed, since that code follows the other repo's main
branch.

Not read: code transformers loads from a `subfolder=`, code another library
loads its own way (diffusers custom pipelines, PEFT adapters), a class passed
around by assignment (`layer = Block; layer(config)`), and anything a method
the user calls does. Gated and private repos cannot be fetched (no token is
sent): download one and scan the folder.
