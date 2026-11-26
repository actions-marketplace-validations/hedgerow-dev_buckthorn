"""Read JavaScript as a list of tokens. Nothing is run, and no tree is built.

The source is hostile, so the reader is one loop over the text with no
recursion, every regex is linear (possessive quantifiers, no nested choices
that can backtrack), and there are limits on size, token count and bracket
depth. Anything it cannot read raises JSError, which callers report as
BKT-SKIP-003: an unread file is never taken for a harmless one.

A slash is a regex or a division by what comes before it: after a value (a
name, number, string, `)`, `]`, or the `}` of an object or a function
expression) it divides; anywhere else it starts a regex. The `)` of
`if (...)`, `while`, `for` and `with`, and the `}` of a block, end a
statement, so a slash after them is a regex. JSX is not read: a file with it
mostly fails closed.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable, Mapping
from typing import NamedTuple

from buckthorn.code import (
    _PERSISTENCE_PATH,
    _SECRET_PATH,
    FETCHING_COMMAND,
    Hit,
    _looks_encoded,
    channels_in,
)

_CHANNELS = frozenset({"discord", "telegram"})  # kinds of hit channels_in gives

MAX_SOURCE_BYTES = 5 * 1024 * 1024  # the same cap as one Python file
MAX_TOKENS = 2_000_000
MAX_DEPTH = 1_000  # brackets open at once: ( [ { and ${


class Token(NamedTuple):
    # name (identifiers and keywords), private (#x), punct, num, string, regex,
    # template (no substitutions), template_head, template_middle, template_tail.
    kind: str
    # Names, strings and template text are decoded (\u0065val is eval); the
    # rest is as written. Brackets are punct; ${ and its } belong to the
    # template tokens around them.
    value: str
    line: int
    # Brackets open around the token. An opener and its closer sit at the
    # outer depth, so a file's top-level tokens are at depth 0.
    depth: int
    # A string spelt with \x, \u or octal escapes: text written so it cannot be read.
    escaped: bool = False


class JSError(Exception):
    """The file could not be read. kind says why, for coverage notes."""

    def __init__(self, kind: str, line: int) -> None:
        super().__init__(f"{kind} at line {line}")
        self.kind = kind
        self.line = line


_SPACE = (
    "\t\v\f \xa0\ufeff\u1680"
    + "".join(chr(c) for c in range(0x2000, 0x200B))
    + "\u202f\u205f\u3000\n\r\u2028\u2029"
)
_WHITESPACE = re.compile(f"[{re.escape(_SPACE)}]++")
_LINE_END = re.compile(r"[\n\r\u2028\u2029]")
_UNICODE_ESCAPE = r"\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]++\})"
_NAME = re.compile(rf"(?:[^\W\d]|\$|{_UNICODE_ESCAPE})(?:[\w$\u200c\u200d]|{_UNICODE_ESCAPE})*+")
_NUMBER = re.compile(
    r"0[xX][0-9a-fA-F_]++n?|0[oO][0-7_]++n?|0[bB][01_]++n?"
    r"|(?:[0-9][0-9_]*+(?:\.[0-9_]*+)?|\.[0-9][0-9_]*+)(?:[eE][+-]?[0-9][0-9_]*+)?n?"
)
_PUNCT = re.compile(
    r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\||\?\?"
    r"|\?\.(?![0-9])|\+\+|--|\+=|-=|\*=|%=|&=|\|=|\^=|<<|>>|\*\*|[;,<>+\-*%&|^!~?:=@.]"
)
_STRING = {
    q: re.compile(rf"{q}[^{q}\\\n\r]*+(?:\\(?:\r\n|[\s\S])[^{q}\\\n\r]*+)*+{q}") for q in "'\""
}
# Template text up to the closing ` or a ${.
_TEMPLATE = re.compile(r"[^`\\$]*+(?:(?:\\[\s\S]|\$(?!\{))[^`\\$]*+)*+")
_NOT_LINE_END = r"[^\n\r\u2028\u2029]"
_REGEX = re.compile(
    rf"/(?:[^\\/\[\n\r\u2028\u2029]|\\{_NOT_LINE_END}"
    rf"|\[(?:[^\]\\\n\r\u2028\u2029]|\\{_NOT_LINE_END})*+\])++/[\w$]*+"
)
_ESCAPE = re.compile(
    r"\\(u\{[0-9a-fA-F]*+\}?|u[0-9a-fA-F]{0,4}|x[0-9a-fA-F]{0,2}"
    r"|[0-3][0-7]{0,2}|[4-7][0-7]?|\r\n|[\s\S])"
)
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v"}
_LINE_CONTINUATIONS = frozenset({"\n", "\r", "\r\n", "\u2028", "\u2029"})

# Names after which an expression starts (so a slash is a regex, a { an
# object), and after which a statement starts.
_BEFORE_EXPRESSION = frozenset(
    {"return", "typeof", "instanceof", "in", "new", "delete", "void", "throw", "case"}
    | {"yield", "await", "extends", "default"}
)
_BEFORE_STATEMENT = frozenset({"else", "do", "try", "finally"})
_STATEMENT_PARENS = frozenset({"if", "while", "for", "with"})
_CLOSERS = {"(": ")", "[": "]", "{": "}"}


def tokenize(source: str | bytes, module: bool | None = False) -> list[Token]:
    """Tokens of a JavaScript file, without comments. Raises JSError.

    module says how Node runs the file: True for an ES module, False for a
    script (CommonJS). They differ only in `<!--` and a `-->` at the start of
    a line, which are comments in a script and operators in a module. With
    None (a .js file, which Node may run either way), either fails closed.
    """
    if len(source) > MAX_SOURCE_BYTES:
        raise JSError("too-large", 0)
    if isinstance(source, bytes):
        source = source.removeprefix(b"\xef\xbb\xbf")
        try:
            source = source.decode()
        except UnicodeDecodeError as exc:
            raise JSError("not-utf8", source[: exc.start].count(b"\n") + 1) from None
    source = source.removeprefix("\ufeff")  # Node drops a BOM

    tokens: list[Token] = []
    stack: list[tuple[str, str]] = []  # open brackets: (opener, what it opened)
    ternaries = [0]  # ? still waiting for their :, at the top and in each open bracket
    pos, line, end = 0, 1, len(source)
    # What may come next: "stmt" (a statement), "expr" (an expression), or
    # "value" (an operator, as a value came last).
    ctx = "stmt"
    newline = True  # a line ends between the last token and this one
    function_expr = False  # a function expression waits for its (
    async_ctx = ctx  # ctx before the last `async`
    escaped = False  # the string being read has \x, \u or octal escapes
    closed = ""  # what the last closed bracket opened
    if source.startswith("#!"):
        stop = _LINE_END.search(source)
        pos = stop.start() if stop else end

    while pos < end:
        c = source[pos]
        if c in _SPACE:
            match = _WHITESPACE.match(source, pos)
            text = match.group()
            if lines := _lines(text):
                line, newline = line + lines, True
            pos = match.end()
            continue
        depth, start = len(stack), line
        if c == "/" and source.startswith("//", pos):
            stop = _LINE_END.search(source, pos)
            pos = stop.start() if stop else end
            continue
        if c == "/" and source.startswith("/*", pos):
            stop = source.find("*/", pos + 2)
            if stop < 0:
                raise JSError("unterminated-comment", line)
            if lines := _lines(source[pos:stop]):
                line, newline = line + lines, True
            pos = stop + 2
            continue
        if module is not True and (
            (c == "<" and source.startswith("<!--", pos))
            or (c == "-" and newline and source.startswith("-->", pos))
        ):
            if module is None:
                raise JSError("html-comment", line)
            stop = _LINE_END.search(source, pos)
            pos = stop.start() if stop else end
            continue

        if c == "/":
            if ctx == "value":
                kind = "punct"
                value = "/=" if source.startswith("/=", pos) else "/"
                ctx = "expr"
            else:
                match = _REGEX.match(source, pos)
                if not match:
                    raise JSError("unterminated-regex", line)
                kind, value, ctx = "regex", match.group(), "value"
            pos += len(value)
        elif c in "'\"":
            match = _STRING[c].match(source, pos)
            if not match:
                raise JSError("unterminated-string", line)
            raw = match.group()
            kind, value, ctx = "string", _unescape(raw[1:-1], True, line), "value"
            escaped = "\\" in raw and any(
                m.group(1)[0] in "ux01234567" for m in _ESCAPE.finditer(raw)
            )
            line += _lines(raw)
            pos = match.end()
        elif c == "`" or (c == "}" and stack and stack[-1][0] == "${"):
            if c == "}":
                stack.pop()
                ternaries.pop()
                depth = len(stack)
            pos, text, opens = _template_text(source, pos + 1, line)
            if opens:
                if len(stack) >= MAX_DEPTH:
                    raise JSError("too-deep", line)
                stack.append(("${", "template"))
                ternaries.append(0)
            if c == "`":
                kind = "template_head" if opens else "template"
            else:
                kind = "template_middle" if opens else "template_tail"
            value, ctx = _unescape(text, False, line), "expr" if opens else "value"
            line += _lines(text)
        elif c in "([{":
            if len(stack) >= MAX_DEPTH:
                raise JSError("too-deep", line)
            if c == "(":
                opened = "function" if function_expr else ""
                if _word(tokens, 1) in _STATEMENT_PARENS or (
                    _word(tokens, 1) == "await" and _word(tokens, 2) == "for"
                ):
                    opened = "statement"
                function_expr, ctx = False, "expr"
            elif c == "[":
                opened, ctx = "", "expr"
            elif tokens and _is(tokens[-1], "=>"):
                opened, ctx = "block", "stmt"  # an arrow function's body
            elif ctx == "expr":
                opened = "object"
            elif tokens and _is(tokens[-1], ")") and closed == "function":
                opened, ctx = "function", "stmt"
            else:
                opened, ctx = "block", "stmt"
            stack.append((c, opened))
            ternaries.append(0)
            kind, value = "punct", c
            pos += 1
        elif c in ")]}":
            if not stack or _CLOSERS.get(stack[-1][0]) != c:
                raise JSError("unbalanced", line)
            closed = stack.pop()[1]
            ternaries.pop()
            depth = len(stack)
            ctx = "stmt" if closed in ("statement", "block") else "value"
            kind, value = "punct", c
            pos += 1
        elif "0" <= c <= "9" or (c == "." and "0" <= source[pos + 1 : pos + 2] <= "9"):
            match = _NUMBER.match(source, pos)
            kind, value, ctx = "num", match.group(), "value"
            pos = match.end()
        elif c == "#" and (match := _NAME.match(source, pos + 1)):
            kind, value, ctx = "private", "#" + _unescape(match.group(), True, line), "value"
            pos = match.end()
        elif match := _NAME.match(source, pos):
            raw = match.group()
            kind, value = "name", _unescape(raw, True, line)
            if raw != value or _word(tokens, 0) is None:
                ctx = "value"  # a property name, or a keyword spelt with escapes (not one)
            elif value in _BEFORE_EXPRESSION:
                ctx = "expr"
            elif value == "of" and ctx == "value" and stack and stack[-1][1] == "statement":
                ctx = "expr"  # for (x of /re/): `of` after the loop variable
            elif value in _BEFORE_STATEMENT:
                ctx = "stmt"
            elif value == "function":
                before = async_ctx if _word(tokens, 1) == "async" else ctx
                function_expr, ctx = before == "expr", "expr"
            else:
                if value == "async":
                    async_ctx = ctx
                ctx = "value"
            pos = match.end()
        elif match := _PUNCT.match(source, pos):
            kind, value = "punct", match.group()
            if value in ("++", "--"):
                ctx = "value" if ctx == "value" and not newline else "expr"  # postfix or prefix
            elif value == "?":
                ternaries[-1] += 1
                ctx = "expr"
            elif value == ":" and ternaries[-1]:
                ternaries[-1] -= 1
                ctx = "expr"
            elif value == ";" or (
                value == ":" and (not stack or stack[-1][1] in ("block", "function"))
            ):
                ctx = "stmt"  # after a statement, a label or a case
            else:
                ctx = "expr"
            pos = match.end()
        else:
            raise JSError("unexpected-char", line)

        tokens.append(Token(kind, value, start, depth, escaped))
        escaped = False
        if len(tokens) > MAX_TOKENS:
            raise JSError("too-many-tokens", line)
        newline = False
        if function_expr and kind != "name" and (kind, value) != ("punct", "*"):
            function_expr = False  # `function` was not a function's: an object key, say

    if stack:
        raise JSError("unterminated-template" if stack[-1][0] == "${" else "unbalanced", line)
    return tokens


def _template_text(source: str, pos: int, line: int) -> tuple[int, str, bool]:
    """(where it ends, the raw text, whether a ${ ends it) for template text at pos."""
    match = _TEMPLATE.match(source, pos)
    stop = match.end()
    if source.startswith("`", stop):
        return stop + 1, match.group(), False
    if source.startswith("${", stop):
        return stop + 2, match.group(), True
    raise JSError("unterminated-template", line)


def _is(token: Token, punct: str) -> bool:
    return token.kind == "punct" and token.value == punct


def _word(tokens: list[Token], back: int) -> str | None:
    """The name `back` tokens before the end ("" if that is not a name), or
    None if it is a property name (after . or ?.). back 0 asks about the
    token being read now."""
    if back and (len(tokens) < back or tokens[-back].kind != "name"):
        return ""
    before = tokens[-back - 1] if len(tokens) > back else None
    if before and (_is(before, ".") or _is(before, "?.")):
        return None
    return tokens[-back].value if back else ""


def _lines(text: str) -> int:
    """Line ends in text; \\r\\n is one."""
    if not text:
        return 0
    return (
        text.count("\n")
        + text.count("\r")
        - text.count("\r\n")
        + text.count("\u2028")
        + text.count("\u2029")
    )


def _unescape(text: str, strict: bool, line: int) -> str:
    """The value of string, template or name text with its escapes decoded.

    strict: a malformed \\x or \\u escape raises JSError (it is a syntax error
    in a string or name); in a template it is kept as written, as a tagged
    template allows it.
    """
    if "\\" not in text:
        return text

    def one(match: re.Match[str]) -> str:
        escape = match.group(1)
        if escape[0] in "ux":
            if escape[0] == "x":
                whole, digits = len(escape) == 3, escape[1:]
            elif escape.startswith("u{"):
                whole, digits = escape.endswith("}"), escape[2:-1].lstrip("0") or "0"
            else:
                whole, digits = len(escape) == 5, escape[1:]
            # Over six digits is past U+10FFFF: not read as a (huge) number.
            code = int(digits, 16) if whole and 0 < len(digits) <= 6 else -1
            if escape == "u{}" or not 0 <= code <= 0x10FFFF:
                if strict:
                    raise JSError("bad-escape", line)
                return match.group()
            return chr(code)
        if escape in _LINE_CONTINUATIONS:
            return ""
        if escape[0] in "01234567":
            return chr(int(escape, 8))
        return _SIMPLE_ESCAPES.get(escape, escape)  # \8, \9 and \q stand for themselves

    value = _ESCAPE.sub(one, text)
    if "\\u" in text:  # join escaped surrogate pairs: \uD83D\uDE00 is one character
        value = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
    return value


_NOT_CALLEES = frozenset(
    _BEFORE_EXPRESSION | _BEFORE_STATEMENT | _STATEMENT_PARENS | {"switch", "catch", "function"}
)


def calls(tokens: list[Token]) -> list[tuple[str, int]]:
    """(callee, index of its "(") for each call made by name: f(), a.b(),
    a["b"](), a?.b(), and require("x").y() as "require().y". Definitions
    (`function f() {}`, a method `m() {}`) and `async () =>` are left out.

    A helper for the code rules, not a parser: a callee that is not a name
    chain, such as `(0, eval)(s)` or `f()()`, is not listed.
    """
    pairs: dict[int, int] = {}  # index of each ( or [ -> index of its closer, and back
    open_: list[int] = []
    for i, token in enumerate(tokens):
        if token.kind == "punct" and token.value in ("(", "["):
            open_.append(i)
        elif token.kind == "punct" and token.value in (")", "]"):
            pairs[i] = open_.pop()
            pairs[pairs[i]] = i
    found = []
    for i, token in enumerate(tokens):
        if not _is(token, "("):
            continue
        # `m() {` on one line defines a method; on the next line the call
        # stands and a block follows it.
        after = tokens[pairs[i] + 1] if pairs[i] + 1 < len(tokens) else None
        if after and _is(after, "=>"):
            continue
        if after and _is(after, "{") and after.line == tokens[pairs[i]].line:
            continue
        j = i - 1
        if j >= 0 and _is(tokens[j], "?."):
            j -= 1
        parts: list[str] = []
        suffix = ""
        while j >= 0:
            t = tokens[j]
            if t.kind == "name":
                parts.append(t.value + suffix)
                j, suffix = j - 1, ""
                if j >= 0 and (_is(tokens[j], ".") or _is(tokens[j], "?.")):
                    j -= 1
                    continue
                break
            if _is(t, "]") and pairs[j] == j - 2:
                if tokens[j - 1].kind not in ("string", "template"):
                    break
                parts.append(tokens[j - 1].value + suffix)
                j, suffix = j - 3, ""
                if j >= 0 and _is(tokens[j], "?."):
                    j -= 1
                continue
            if _is(t, ")") and parts and not suffix:
                j, suffix = pairs[j] - 1, "()"
                continue
            break
        if not parts or suffix:
            continue
        if parts[-1] in _NOT_CALLEES and len(parts) == 1:
            continue
        if j >= 0 and tokens[j].kind == "name" and tokens[j].value == "function":
            continue
        if j > 0 and _is(tokens[j], "*") and tokens[j - 1].value == "function":
            continue
        found.append((".".join(reversed(parts)), i))
    return found


# What code does, read from its tokens: the same kinds of hit code.py finds in
# Python, so the npm rules mean what the Python rules mean.

_NETWORK_CALLS = frozenset(
    {"fetch", "WebSocket", "http.request", "http.get", "https.request", "https.get"}
    | {"http2.connect", "net.connect", "net.createConnection", "tls.connect"}
)
# HTTP and socket client packages: calling one, or one of these methods on it, sends.
_NETWORK_PACKAGES = frozenset(
    {"node-fetch", "cross-fetch", "isomorphic-fetch", "make-fetch-happen", "axios", "got"}
    | {"request", "request-promise", "request-promise-native", "superagent", "needle", "undici"}
    | {"phin", "bent", "ky", "ofetch", "sync-request", "then-request", "ws", "isomorphic-ws"}
)
_SENDING_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "del", "head", "options", "request", "fetch"}
    | {"stream", "connect", "send", "write", "open"}
)
# Making one of these connects nothing; using it does (a socket's connect, a
# client's get), as for code.py's clients.
_CLIENTS = frozenset(
    {"net.Socket", "tls.TLSSocket", "dgram.createSocket", "XMLHttpRequest", "axios.create"}
    | {"got.extend", "undici.Client", "undici.Pool"}
)
_PROCESS_CALLS = frozenset(
    {f"child_process.{f}" for f in ("exec", "execSync", "execFile", "execFileSync")}
    | {f"child_process.{f}" for f in ("spawn", "spawnSync", "fork")}
    | {"shelljs.exec", "execa", "execa.sync", "execa.command", "execa.commandSync"}
    | {"cross-spawn", "cross-spawn.sync"}
)
# Calls that run a string as code. For Function the code is the last argument.
_EXEC_CALLS = frozenset(
    {"eval", "Function", "vm.Script", "vm.SourceTextModule", "vm.compileFunction"}
    | {"vm.runInThisContext", "vm.runInNewContext", "vm.runInContext"}
)
_LOADERS = frozenset({"require", "module.require", "process.mainModule.require", "import"})
# Names that, reached by a computed name or evaluated from their own name,
# are a way round reading as exec.
_HIDDEN_NAMES = frozenset({"eval", "Function", "require", "process", "global", "globalThis"})
# Calls that turn data back into text: atob, Buffer.from(s, 'base64'), ...
_DECODERS = frozenset(
    {"atob", "Buffer.from", "String.fromCharCode", "String.fromCodePoint", "unescape"}
    | {"decodeURIComponent", "decodeURI", "crypto.createDecipheriv", "crypto.createDecipher"}
    | {f"zlib.{f}Sync" for f in ("inflate", "inflateRaw", "gunzip", "unzip", "brotliDecompress")}
)
_DECODING_METHODS = frozenset({".reverse", ".fromCharCode", ".fromCodePoint"})
# The global object, under each name it goes by: globalThis.eval is eval.
_GLOBALS = frozenset({"global", "globalThis", "window", "self"})
# Calls that only build, test or print a path: a credential path inside
# nothing but these is a path, not a read (as code.py's path builders).
_PATH_BUILDERS = frozenset(
    {f"path.{f}" for f in ("join", "resolve", "normalize", "dirname", "basename", "extname")}
    | {f"path.{f}" for f in ("relative", "parse", "format", "isAbsolute")}
    | {f"path.{o}.{f}" for o in ("posix", "win32") for f in ("join", "resolve", "normalize")}
    | {"os.homedir", "fs.existsSync", "fs.exists", "String", "RegExp", "require.resolve"}
    | {f"console.{f}" for f in ("log", "warn", "error", "info", "debug")}
    | {".endsWith", ".startsWith", ".includes", ".indexOf", ".test", ".match", ".replace"}
    | {".split", ".concat", ".join", ".resolve"}
)
# Code that loads a compiled addon, whose native code cannot be read.
_NATIVE_LOADERS = frozenset(
    {"bindings", "node-gyp-build", "node-gyp-build-optional-packages", "process.dlopen"}
    | {"node-pre-gyp.find", "@mapbox/node-pre-gyp.find"}
)
# Calls that run a function handed to them now or soon, not only when
# something else happens: its body runs at load too.
_RUNS_CALLBACK = frozenset(
    {"setTimeout", "setImmediate", "setInterval", "queueMicrotask", "process.nextTick"}
    | {"Promise", ".then", ".catch", ".finally", ".forEach", ".map", ".filter", ".reduce"}
    | {".some", ".every", ".find", ".flatMap", ".findIndex", ".findLast", ".findLastIndex"}
    | {".reduceRight", ".sort", ".replace", ".replaceAll", "Array.from"}
    # A page's code runs on its own events: DOMContentLoaded, load.
    | {".addEventListener"}
)
# How bundlers keep each bundled module in a function, run when the bundle
# requires it: esbuild and rolldown wrap them in a call, webpack keeps a table.
_BUNDLE_WRAPPERS = frozenset({"__commonJS", "__esm", "__commonJSMin", "__esmMin"})
_MODULE_TABLES = frozenset({"__webpack_modules__"})
_NOT_METHODS = frozenset({"if", "for", "while", "with", "switch", "catch", "function"})
# Names that continue the expression before them, even on a new line.
_CONTINUES = frozenset({"in", "of", "instanceof"})
_BUILTINS = frozenset(
    {"assert", "async_hooks", "buffer", "child_process", "cluster", "constants", "crypto"}
    | {"dgram", "dns", "events", "fs", "http", "http2", "https", "inspector", "module", "net"}
    | {"os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "stream"}
    | {"string_decoder", "timers", "tls", "tty", "url", "util", "v8", "vm", "worker_threads"}
    | {"zlib", "fs/promises", "dns/promises", "timers/promises", "stream/promises"}
)
_RUNNING_KINDS = frozenset({"network", "process", "exec", "secrets", "persistence", "environ"})
# Values one name may be bound to in one scope (functions, modules, objects)
# before the file counts as crowded: a cap on work, failing closed.
_MAX_BINDINGS = 256


class Analysis(NamedTuple):
    hits: list[Hit]  # in source order; "native" is a compiled addon loaded
    # Modules and files loaded by code that runs, each with the names code
    # that runs calls on it ("" for the module itself or its default export).
    loads: dict[str, set[str]]
    dynamic: list[int]  # lines of loads named at run time: require(x), import(x)
    crowded: bool = False  # a name is bound more ways than are followed: not all read
    unfound: tuple[str, ...] = ()  # names in entry no export gave a function for


class _Function(NamedTuple):
    start: int  # first token: function, async, the first parameter, or a method's (
    params: tuple[int, int]  # token range of the parameters, inclusive
    body: tuple[int, int]  # token range of the body, inclusive
    name: str
    declared: bool  # a declaration: it binds its name in the scope around it


class _Call(NamedTuple):
    open: int  # index of its (
    names: list[tuple[str, tuple[str, ...]]]  # what the callee may be: (module, attributes)
    method: str  # ".name" for a method on something unresolved
    new: bool
    indirect: bool  # f reached through the global object


def analyse(tokens: list[Token], whole: bool, entry: Mapping[str, str] = {}) -> Analysis:
    """What a file's code does when it runs, and what it loads.

    whole: the file runs whole, as an install script does, so code in
    functions counts too. Otherwise only code that runs at load counts: the
    top level (blocks and class bodies too); functions invoked where they are
    written; functions that code calls by name, found by scope; callbacks it
    hands to setTimeout, a promise or an array method; and the exports named
    in entry (functions other files call, each with how it is reached).
    """
    return _Reader(tokens, whole, entry).run()


def _pairs(tokens: list[Token]) -> dict[int, int]:
    """Index of each bracket's partner, both ways."""
    pairs: dict[int, int] = {}
    open_: list[int] = []
    for i, token in enumerate(tokens):
        if token.kind == "punct" and token.value in ("(", "[", "{"):
            open_.append(i)
        elif token.kind == "punct" and token.value in (")", "]", "}"):
            pairs[i] = open_.pop()
            pairs[pairs[i]] = i
    return pairs


def _after_dot(tokens: list[Token], i: int) -> bool:
    return i > 0 and (_is(tokens[i - 1], ".") or _is(tokens[i - 1], "?."))


def _name(token: Token, value: str) -> bool:
    return token.kind == "name" and token.value == value


def _ends_value(token: Token) -> bool:
    if token.kind == "name":
        return token.value not in _BEFORE_EXPRESSION and token.value not in _CONTINUES
    if token.kind == "punct":
        return token.value in (")", "]", "}", "++", "--")
    return token.kind not in ("template_head", "template_middle")


def _starts_value(token: Token) -> bool:
    if token.kind == "name":
        return token.value not in _CONTINUES
    return token.kind in ("num", "string", "template", "template_head", "private", "regex")


def unprefixed(spec: str) -> str:
    return spec.removeprefix("node:")


def is_builtin(spec: str) -> bool:
    return unprefixed(spec) in _BUILTINS


def _is_decoder(name: str) -> bool:
    return name in _DECODERS or name in _DECODING_METHODS


def _is_network(name: str) -> bool:
    if name in _NETWORK_CALLS:
        return True
    parts = name.split(".")
    if parts[0] in ("dns", "dns/promises") and len(parts) > 1:
        return parts[-1].startswith(("lookup", "resolve", "reverse"))
    if parts[0] in _NETWORK_PACKAGES:
        return len(parts) == 1 or (len(parts) == 2 and parts[1] in _SENDING_METHODS)
    client, _, method = name.partition("().")
    return client in _CLIENTS and method in _SENDING_METHODS


class _Reader:
    """One file's tokens read for what runs: functions, scopes and calls."""

    def __init__(self, tokens: list[Token], whole: bool, entry: Mapping[str, str]) -> None:
        self.tokens, self.whole, self.entry = tokens, whole, entry
        self.pairs = _pairs(tokens)
        self.enclosing = [-1] * len(tokens)  # the ( [ or { each token is in, -1 for none
        open_: list[int] = []
        for i, t in enumerate(tokens):
            self.enclosing[i] = open_[-1] if open_ else -1
            if t.kind == "punct" and t.value in ("(", "[", "{"):
                open_.append(i)
            elif t.kind == "punct" and t.value in (")", "]", "}"):
                open_.pop()
                self.enclosing[i] = open_[-1] if open_ else -1
        self._ends: dict[int, int] = {}  # _expression_end, by start
        self.declared: set[str] = set()  # every name any scope binds
        self.module_names: set[str] = set()  # names some scope binds to a module
        self.rebound: set[tuple[int, str]] = set()  # (scope, name) bound to more than one value
        self.crowded = False  # some name is bound more ways than _MAX_BINDINGS
        self._called: dict[tuple, list[tuple[str, int]]] = {}  # _called_functions, by callee
        self.functions: list[_Function] = []
        self.claimed: set[int] = set()  # each ( that opens parameters, not a call
        self._find_functions()
        self.starts: dict[int, list[int]] = {}
        for n, f in enumerate(self.functions):
            self.starts.setdefault(f.start, []).append(n)
        self._owners()
        # Per scope (-1 for the file), each name with what it may be bound to:
        # ("fn", function), ("mod", module, attributes) or ("var", start, end).
        self.scope: dict[int, dict[str, list[tuple]]] = {-1: {}}
        self.loads: dict[str, set[str]] = {}
        self.dynamic: list[int] = []
        self.hits: list[Hit] = []
        self.exports: dict[str, list[int]] = {}  # name other files call -> functions
        self.reexports: list[str] = []  # export * from 'm', module.exports = require('m')
        # A bundle's module table (var __webpack_modules__ = {...}), by scope:
        # its functions run when the bundle's require runs them.
        self.tables: dict[int, list[tuple[int, int]]] = {}
        self.children: dict[int, list[int]] = {}
        for f in range(len(self.functions)):
            self.children.setdefault(self.parent[f], []).append(f)
        self._declarations()
        self.calls = self._calls()
        # Positions searched by range (see hiding, _computed_global).
        self.decoding = sorted(
            [i for i, c in self.calls.items() if any(map(_is_decoder, [*self.dotted(c), c.method]))]
            + [i for i, t in enumerate(tokens) if _is(t, "^")]
        )
        self.symbols = [
            i
            for i, t in enumerate(tokens)
            if t.kind == "name"
            and ("Symbol" in t.value or (t.value == "for" and _after_dot(tokens, i)))
        ]
        self.building = [
            i
            for i, t in enumerate(tokens)
            if _is(t, "+") or _is(t, "(") or t.kind == "template_head"
        ]

    # Structure: functions, and the function each token is in.

    def _find_functions(self) -> None:
        tokens, pairs, n = self.tokens, self.pairs, len(self.tokens)
        # Last to first, so an arrow's body end is known when an arrow
        # around it (a => b => c) looks for its own: linear, not quadratic.
        for i in range(n - 1, -1, -1):
            t = tokens[i]
            if _name(t, "function") and not _after_dot(tokens, i):
                j = i + 1
                if j < n and _is(tokens[j], "*"):
                    j += 1
                name = ""
                if j < n and tokens[j].kind == "name":
                    name, j = tokens[j].value, j + 1
                if j >= n or not _is(tokens[j], "(") or pairs[j] + 1 >= n:
                    continue
                if not _is(tokens[pairs[j] + 1], "{"):
                    continue
                start = i - 1 if i and _name(tokens[i - 1], "async") else i
                self.claimed.add(j)
                body = (pairs[j] + 1, pairs[pairs[j] + 1])
                declared = self._statement_start(start)
                self.functions.append(_Function(start, (j, pairs[j]), body, name, declared))
            elif _is(t, "=>") and i:
                if tokens[i - 1].kind == "name":
                    params = (i - 1, i - 1)
                elif _is(tokens[i - 1], ")"):
                    params = (pairs[i - 1], i - 1)
                    self.claimed.add(pairs[i - 1])
                else:
                    continue
                start = params[0]
                if (
                    start
                    and _name(tokens[start - 1], "async")
                    and not _after_dot(tokens, start - 1)
                ):
                    start -= 1
                if i + 1 < n and _is(tokens[i + 1], "{"):
                    body = (i + 1, pairs[i + 1])
                else:
                    body = (i + 1, self._expression_end(i + 1))
                self.functions.append(_Function(start, params, body, "", False))
        # Methods, in a class or an object: `name(...) {`, the { on the line of
        # the ). A call is never followed by a block on its own line that way.
        for i, t in enumerate(tokens):
            if not _is(t, "(") or i in self.claimed or not i:
                continue
            close = pairs[i]
            if close + 1 >= n or not _is(tokens[close + 1], "{"):
                continue
            before = tokens[i - 1]
            if tokens[close + 1].line != tokens[close].line:
                continue
            if before.kind == "name" and before.value in _NOT_METHODS:
                if not _after_dot(tokens, i - 1):
                    continue
            if before.kind not in ("name", "string", "num", "private") and not _is(before, "]"):
                continue
            j = i - 1  # `class A extends mixin(B) {` calls mixin
            while j > 0 and (tokens[j].kind == "name" or _is(tokens[j], ".")):
                j -= 1
            if _name(tokens[j], "extends"):
                continue
            self.claimed.add(i)
            name = before.value if before.kind == "name" else ""
            body = (close + 1, pairs[close + 1])
            self.functions.append(_Function(i, (i, close), body, name, False))

    def _statement_start(self, i: int) -> bool:
        """Whether a function starting at i is a declaration: it starts a statement."""
        if not i:
            return True
        before = self.tokens[i - 1]
        if before.kind == "punct":
            return before.value in (";", "{", "}")
        if before.kind == "name" and before.value in ("export", "default"):
            return True
        return before.line < self.tokens[i].line and _ends_value(before)

    def _expression_end(self, k: int) -> int:
        """Index of the last token of the expression starting at k: it ends
        before a , or ; or an unmatched : at its depth, at the end of the
        bracket it is in, or at a line end where a new statement must start."""
        tokens, n = self.tokens, len(self.tokens)
        if k >= n:
            return n - 1
        if k in self._ends:
            return self._ends[k]
        depth, pending, last, j = tokens[k].depth, 0, k - 1, k
        while j < n:
            t = tokens[j]
            if t.depth < depth:
                break
            if t.depth == depth:
                if j > k and t.line > tokens[last].line and _ends_value(tokens[last]):
                    if _starts_value(t) or _is(t, "{"):
                        break
                if t.kind == "punct":
                    if t.value in (",", ";"):
                        break
                    if t.value == "?":
                        pending += 1
                    elif t.value == ":":
                        if not pending:
                            break
                        pending -= 1
                    elif t.value in ("(", "[", "{"):
                        last = j = self.pairs[j]
                        j += 1
                        continue
                    elif t.value in ("=>", "=") and j + 1 in self._ends:
                        # The rest is an expression already measured (a => b
                        # => c, a = b = c): it stops where this one would.
                        last = j = self._ends[j + 1]
                        j += 1
                        continue
            last = j
            j += 1
        self._ends[k] = max(last, k)
        return self._ends[k]

    def _owners(self) -> None:
        """owner[i]: the innermost function token i is in, -1 for none; and
        parent[f]: the function function f is in."""
        order = sorted(range(len(self.functions)), key=lambda f: self.functions[f].start)
        self.owner = [-1] * len(self.tokens)
        self.parent = [-1] * len(self.functions)
        stack: list[int] = []
        k = 0
        for i in range(len(self.tokens)):
            while k < len(order) and self.functions[order[k]].start <= i:
                while stack and self.functions[stack[-1]].body[1] < self.functions[order[k]].start:
                    stack.pop()
                self.parent[order[k]] = stack[-1] if stack else -1
                stack.append(order[k])
                k += 1
            while stack and self.functions[stack[-1]].body[1] < i:
                stack.pop()
            self.owner[i] = stack[-1] if stack else -1

    # Names: what each is bound to, scope by scope.

    def _bind(self, scope: int, name: str, value: tuple) -> None:
        """Add what name may be bound to in scope. A plain variable is kept
        once (later ones are counted, for `bound once`), others once each; a
        name bound more ways than is followed makes the file crowded."""
        values = self.scope.setdefault(scope, {}).setdefault(name, [])
        self.declared.add(name)
        if value[0] == "var" and any(v[0] == "var" for v in values):
            self.rebound.add((scope, name))
        elif value not in values:
            if len(values) >= _MAX_BINDINGS:
                self.crowded = True
                return
            values.append(value)
            if value[0] == "mod":
                self.module_names.add(name)

    def lookup(self, name: str, scope: int) -> list[tuple]:
        """What name may be bound to in scope: the first scope out from it
        that declares the name. Empty for a global."""
        if name not in self.declared:
            return []
        while True:
            if name in self.scope.get(scope, {}):
                return self.scope[scope][name]
            if scope == -1:
                return []
            scope = self.parent[scope]

    def _declarations(self) -> None:
        tokens, n = self.tokens, len(self.tokens)
        for f, function in enumerate(self.functions):
            if function.declared and function.name:
                self._bind(self.parent[f], function.name, ("fn", f))
            a, b = function.params
            depth = tokens[a].depth + _is(tokens[a], "(")
            for i in range(a, b + 1):
                if tokens[i].kind == "name" and tokens[i].depth == depth:
                    if i == b or not _is(tokens[i + 1], ":"):
                        self._bind(f, tokens[i].value, ("var", i, i))
        for i in range(n - 1, -1, -1):  # last to first: a = b = c is linear (_expression_end)
            if _is(tokens[i], "="):
                self._expression_end(i + 1)
        declared: set[int] = set()
        exports = []
        for i, t in enumerate(tokens):
            if t.kind != "name" or _after_dot(tokens, i) or i in declared:
                continue
            if t.value in ("var", "let", "const") and i + 1 < n:
                declared |= self._declarators(i + 1)
            elif t.value == "import" and not t.depth and i + 1 < n:
                if not (_is(tokens[i + 1], "(") or _is(tokens[i + 1], ".")):
                    self._import(i)
            elif t.value == "export" and not t.depth:
                exports.append(i)
            elif t.value == "class" and i + 1 < n and tokens[i + 1].kind == "name":
                self._bind(self.owner[i], tokens[i + 1].value, self._class(i))
            elif i + 2 < n and _is(tokens[i + 1], "=") and t.value not in _BEFORE_EXPRESSION:
                scope = self.owner[i]  # the scope that declares it, else the file
                while scope != -1 and t.value not in self.scope.get(scope, {}):
                    scope = self.parent[scope]
                value = self._value(i + 2, self._expression_end(i + 2), self.owner[i])
                self._bind(scope, t.value, value)
        for i in exports:
            self._export(i)
        self._module_exports()
        self._bundle_exports()

    def _declarators(self, i: int) -> set[int]:
        """Bind the names declared from i on (`a = 1, {b, c: d} = require('m')`);
        returns the indices of the names."""
        tokens, n, scope = self.tokens, len(self.tokens), self.owner[i]
        done = set()
        while i < n:
            if tokens[i].kind == "name":
                names, j = [(tokens[i].value, "")], i + 1
            elif _is(tokens[i], "{") or _is(tokens[i], "["):
                names, j = self._pattern(i), self.pairs[i] + 1
            else:
                return done
            done.add(i)
            if j < n and _is(tokens[j], "="):
                end = self._expression_end(j + 1)
                value = self._value(j + 1, end, scope)
                if names and names[0][0] in _MODULE_TABLES:
                    self.tables.setdefault(scope, []).append((j, end + 1))
            else:
                end, value = j - 1, ("var", i, i)
            for local, key in names:
                if key and value[0] == "mod":
                    self._bind(scope, local, ("mod", value[1], (*value[2], key)))
                else:
                    self._bind(scope, local, value if not key else ("var", i, i))
            i = end + 1
            if i >= n or not _is(tokens[i], ","):
                return done
            i += 1
        return done

    def _pattern(self, i: int) -> list[tuple[str, str]]:
        """(local, key) for each name an object pattern {a, b: c} binds. An
        array pattern's names take no key."""
        tokens, depth, found = self.tokens, self.tokens[i].depth + 1, []
        array = _is(tokens[i], "[")
        for j in range(i + 1, self.pairs[i]):
            t = tokens[j]
            if t.kind != "name" or t.depth != depth or _is(tokens[j + 1], ":"):
                continue
            before = tokens[j - 1]
            if _is(before, ":") and tokens[j - 2].kind in ("name", "string"):
                found.append((t.value, "" if array else tokens[j - 2].value))
            elif _is(before, "{") or _is(before, ",") or _is(before, "["):
                found.append((t.value, "" if array else t.value))
        return found

    def _value(self, a: int, b: int, scope: int) -> tuple:
        """What the expression a..b binds a name to: ("fn", function), ("obj",
        start, end) for an object literal, ("class", start, end) for a class
        body, ("mod", module, attributes), or ("var", start, end)."""
        tokens = self.tokens
        if a > b or a >= len(tokens):
            return ("var", a, b)
        for f in self.starts.get(a, []):
            if self.functions[f].body[1] == b:
                return ("fn", f)
        if _is(tokens[a], "{") and self.pairs[a] == b:
            return ("obj", a, b)
        if _name(tokens[a], "class"):
            return self._class(a)
        if a == b and tokens[a].kind == "name":  # an alias: const g = f
            for value in self.lookup(tokens[a].value, scope):
                if value[0] in ("fn", "obj", "class"):
                    return value
        start = a + 1 if _name(tokens[a], "new") else a
        if start > b or tokens[start].kind != "name":
            return ("var", a, b)
        # One wrapper around a require: __importStar(require('m')), as compilers write.
        if (
            start + 2 < b
            and _is(tokens[start + 1], "(")
            and self.pairs[start + 1] == b
            and _name(tokens[start + 2], "require")
        ):
            return self._value(start + 2, b - 1, scope)
        found = self._chain(start, scope)
        if found is None or not found[0]:
            return ("var", a, b)
        (module, attributes), end = found[0][0], found[1]
        if end == b:
            return ("mod", module, attributes)
        # util.promisify(f) runs f: promisify(exec) is exec.
        if (
            (module, attributes) == ("util", ("promisify",))
            and _is(tokens[end + 1], "(")
            and self.pairs[end + 1] == b
        ):
            return self._value(end + 2, b - 1, scope)
        if _is(tokens[end + 1], "(") and self.pairs[end + 1] == b and attributes:
            if ".".join(p for p in (module, *attributes) if p) in _CLIENTS:
                return ("mod", module, (*attributes[:-1], attributes[-1] + "()"))
        return ("var", a, b)

    def _class(self, i: int) -> tuple:
        """("class", start, end) for the body of the class whose keyword is at i."""
        tokens, j = self.tokens, i + 1
        while j < len(tokens) and not (_is(tokens[j], "{") and tokens[j].depth == tokens[i].depth):
            if tokens[j].kind == "punct" and tokens[j].value in ("(", "["):
                j = self.pairs[j]  # extends mixin({...})
            j += 1
        return ("class", j, self.pairs[j]) if j < len(tokens) else ("var", i, i)

    def _members(self, a: int, b: int) -> dict[str, list[int]]:
        """The functions an object literal or class body at a..b holds, by
        key: {f, g: h, k() {}, l: function () {}}."""
        tokens, depth = self.tokens, self.tokens[a].depth + 1
        found: dict[str, list[int]] = {}
        for j in range(a + 1, b):
            t = tokens[j]
            if t.depth != depth or t.kind not in ("name", "string"):
                continue
            after = tokens[j + 1]
            if _is(after, "("):  # a method
                methods = [
                    f for f in self.starts.get(j + 1, []) if self.functions[f].params[0] == j + 1
                ]
                found.setdefault(t.value, []).extend(methods)
                continue
            if not (_is(tokens[j - 1], "{") or _is(tokens[j - 1], ",")):
                continue
            if _is(after, ",") or _is(after, "}"):
                found.setdefault(t.value, []).extend(self._functions_named(t.value))
            elif _is(after, ":"):
                value = self._value(j + 2, self._expression_end(j + 2), self.owner[j])
                found.setdefault(t.value, []).extend(self._functions_of(value))
        return found

    def _chain(self, i: int, scope: int) -> tuple[list[tuple[str, tuple[str, ...]]], int] | None:
        """For a name chain from i (a.b.c, a['b'], require('m').c): what it may
        stand for, as (module, attributes), and the index of its last token."""
        tokens, n = self.tokens, len(self.tokens)
        if tokens[i].kind != "name":
            return None
        parts: list[str] = []
        j = i + 1
        if _name(tokens[i], "require") and j < n and _is(tokens[j], "("):
            spec = self.spec(j + 1, self.pairs[j] - 1)
            if spec is None:
                return None
            module, j = unprefixed(spec[0]), self.pairs[j] + 1
        else:
            module, parts = "", [tokens[i].value]
        while j + 1 < n:
            if (_is(tokens[j], ".") or _is(tokens[j], "?.")) and tokens[j + 1].kind == "name":
                parts.append(tokens[j + 1].value)
                j += 2
            elif (
                _is(tokens[j], "[")
                and self.pairs[j] == j + 2
                and tokens[j + 1].kind in ("string", "template")
            ):
                parts.append(tokens[j + 1].value)
                j += 3
            else:
                break
        if module:
            return [(module, tuple(parts))], j - 1
        return self.resolve(parts, scope), j - 1

    def resolve(self, parts: list[str], scope: int) -> list[tuple[str, tuple[str, ...]]]:
        """(module, attributes) a name chain may stand for, through what its
        first name is bound to; a global ("", parts) when nothing binds it."""
        values = self.lookup(parts[0], scope)
        if not values:
            if parts[0] in _GLOBALS and len(parts) > 1:
                parts = parts[1:]
            return [("", tuple(parts))]
        names = []
        for value in values:
            if value[0] != "mod":
                continue
            attributes = (*value[2], *parts[1:])
            if value[1] and attributes[:1] == ("default",):
                attributes = attributes[1:]  # interop: m.default is the module
            names.append((value[1], attributes))
        return names

    def spec(self, a: int, b: int) -> tuple[str, int] | None:
        """The module a load names, and how many strings it is built from: a
        string, strings joined with +, or strings joined onto __dirname (with
        +, a template, path.join or path.resolve). None when it is named at
        run time."""
        tokens = self.tokens
        if a > b:
            return None
        if literal := self.literal(a, b):
            return literal
        if _name(tokens[a], "__dirname") and a + 1 < b and _is(tokens[a + 1], "+"):
            rest = self.literal(a + 2, b)
            return ("./" + rest[0].lstrip("/"), rest[1]) if rest else None
        if tokens[a].kind == "template_head" and not tokens[a].value and a + 2 == b:
            if _name(tokens[a + 1], "__dirname") and tokens[b].kind == "template_tail":
                return "./" + tokens[b].value.lstrip("/"), 1
        found = self._chain(a, self.owner[a]) if tokens[a].kind == "name" else None
        if found and found[1] + 1 <= b and _is(tokens[found[1] + 1], "("):
            if self.pairs[found[1] + 1] == b and any(
                ".".join((m, *p)).lstrip(".") in ("path.join", "path.resolve") for m, p in found[0]
            ):
                args = self.arguments(found[1] + 1)
                if args and args[0][0] == args[0][1] and _name(tokens[args[0][0]], "__dirname"):
                    rest = [self.literal(s, e) for s, e in args[1:]]
                    if all(rest):
                        return "./" + "/".join(r[0] for r in rest if r), 1
        return None

    def literal(self, a: int, b: int) -> tuple[str, int] | None:
        """The value of strings joined with +, and how many strings there are."""
        tokens, parts = self.tokens, []
        if a > b or (b - a) % 2:
            return None
        for j in range(a, b + 1):
            if (j - a) % 2:
                if not _is(tokens[j], "+"):
                    return None
            elif tokens[j].kind in ("string", "template"):
                parts.append(tokens[j].value)
            else:
                return None
        return "".join(parts), len(parts)

    def arguments(self, i: int) -> list[tuple[int, int]]:
        """Token ranges of the arguments of the call whose ( is at i."""
        close, depth = self.pairs[i], self.tokens[i].depth + 1
        ranges, start = [], i + 1
        for j in range(i + 1, close + 1):
            if j == close or (_is(self.tokens[j], ",") and self.tokens[j].depth == depth):
                if start < j:
                    ranges.append((start, j - 1))
                start = j + 1
        return ranges

    def _import(self, i: int) -> None:
        """import d, {a, b as c}, * as n from 'm', or import 'm': m loads."""
        tokens, n = self.tokens, len(self.tokens)
        bound: list[tuple[str, tuple[str, ...]]] = []
        j = i + 1
        while j < n and tokens[j].kind != "string":
            t = tokens[j]
            if _is(t, "{"):
                bound += [(local, (key,) if key else ()) for local, key in self._names(j)]
                j = self.pairs[j]
            elif _is(t, "*") and j + 2 < n and _name(tokens[j + 1], "as"):
                bound.append((tokens[j + 2].value, ()))
                j += 2
            elif t.kind == "name" and t.value not in ("from", "type"):
                bound.append((t.value, ()))  # the default export
            elif not (_is(t, ",") or t.kind == "name"):
                return  # not an import statement read here (TypeScript's import x = ...)
            j += 1
        if j < n:
            spec = unprefixed(tokens[j].value)
            self.loads.setdefault(spec, set())
            for local, attributes in bound:
                self._bind(-1, local, ("mod", spec, attributes))

    def _names(self, i: int) -> list[tuple[str, str]]:
        """(local, other) for {a, b as c, default as d}; default is ""."""
        tokens, found, j = self.tokens, [], i + 1
        while j < self.pairs[i]:
            if tokens[j].kind in ("name", "string"):
                other = local = tokens[j].value
                if j + 2 < self.pairs[i] and _name(tokens[j + 1], "as"):
                    local, j = tokens[j + 2].value, j + 2
                found.append((local, "" if other == "default" else other))
            j += 1
        return found

    def _export(self, i: int) -> None:
        """export ... from 'm' loads m; `export function f`, `export const f =`,
        `export default f` and `export {f as g}` name what other files call."""
        tokens, n = self.tokens, len(self.tokens)
        if i + 2 >= n:
            return
        nxt = tokens[i + 1]
        if _is(nxt, "*") or _is(nxt, "{"):
            j = self.pairs[i + 1] + 1 if _is(nxt, "{") else i + 2
            if j < n and _name(tokens[j], "as"):
                j += 2
            if j + 1 < n and _name(tokens[j], "from") and tokens[j + 1].kind == "string":
                spec = unprefixed(tokens[j + 1].value)
                self.loads.setdefault(spec, set())
                if _is(nxt, "*") and j == i + 2:
                    self.reexports.append(spec)
            elif _is(nxt, "{"):
                for local, other in self._names(i + 1):
                    self.exports.setdefault(other, []).extend(self._functions_named(local))
            return
        j = i + 2 if _name(nxt, "default") else i + 1
        key = "" if j == i + 2 else None
        for f in self.starts.get(j, []):
            name = self.functions[f].name
            if key is not None or name:
                self.exports.setdefault(name if key is None else key, []).append(f)
        if key is not None and tokens[j].kind == "name":
            self.exports.setdefault("", []).extend(self._functions_named(tokens[j].value))
        elif tokens[j].value in ("const", "let", "var") and j + 1 < n:
            name = tokens[j + 1].value
            self.exports.setdefault(name, []).extend(self._functions_named(name))

    def _functions_named(self, name: str) -> list[int]:
        return [v[1] for v in self.lookup(name, -1) if v[0] == "fn"]

    def _module_exports(self) -> None:
        """exports.f = ... and module.exports = ...: a function, a name, an
        object of them, or another module's exports."""
        tokens, n = self.tokens, len(self.tokens)
        for i, t in enumerate(tokens):
            if t.kind != "name" or self.owner[i] != -1 or _after_dot(tokens, i):
                continue
            if t.value == "module" and i + 3 < n and _is(tokens[i + 1], "."):
                if not _name(tokens[i + 2], "exports"):
                    continue
                j = i + 3
            elif t.value == "exports":
                j = i + 1
            else:
                continue
            key = ""
            if j + 1 < n and _is(tokens[j], ".") and tokens[j + 1].kind == "name":
                key, j = tokens[j + 1].value, j + 2
            elif j + 1 < n and _is(tokens[j], "[") and tokens[j + 1].kind == "string":
                key, j = tokens[j + 1].value, self.pairs[j] + 1
            elif t.value == "exports":
                continue
            if j + 1 >= n or not _is(tokens[j], "="):
                continue
            a, end = j + 1, self._expression_end(j + 1)
            if _is(tokens[a], "{") and not key and self.pairs[a] == end:
                self._exported_object(a)
            elif _name(tokens[a], "require") and not key:
                found = self._chain(a, -1)
                if found and found[1] == end and not found[0][0][1]:
                    self.reexports.append(found[0][0][0])
            else:
                value = self._value(a, end, -1)
                self.exports.setdefault(key, []).extend(self._functions_of(value))

    def _bundle_exports(self) -> None:
        """A bundle's exports, for entry names no export above gave a function
        for: esbuild's __export(x, {f: () => g}) and webpack's
        __webpack_require__.d(x, {f: () => g}), which make each export a getter
        that returns a local function, and `t.f = function` at any depth, as a
        webpack module function sets its exports parameter."""
        tokens, n = self.tokens, len(self.tokens)
        missing = {name for name in self.entry if name and not self.exports.get(name)}
        for i in range(1, n - 3):
            t = tokens[i]
            if t.kind not in ("name", "string") or t.value not in missing:
                continue
            found: list[int] = []
            if _is(tokens[i - 1], ".") and _is(tokens[i + 1], "="):
                found = self.starts.get(i + 2, [])
                if not found and tokens[i + 2].kind == "name":  # t.f = g
                    bound = self.lookup(tokens[i + 2].value, self.owner[i])
                    found = [v[1] for v in bound if v[0] == "fn"]
            elif (
                (_is(tokens[i - 1], "{") or _is(tokens[i - 1], ","))
                and i + 5 < n
                and all(_is(tokens[i + k], v) for k, v in ((1, ":"), (2, "("), (3, ")"), (4, "=>")))
                and tokens[i + 5].kind == "name"
                # The getter returns one name and nothing else.
                and (i + 6 >= n or _is(tokens[i + 6], ",") or _is(tokens[i + 6], "}"))
            ):
                bound = self.lookup(tokens[i + 5].value, self.owner[i])
                found = [v[1] for v in bound if v[0] == "fn"]
            if found:
                self.exports.setdefault(t.value, []).extend(found)

    def _functions_of(self, value: tuple) -> list[int]:
        if value[0] == "fn":
            return [value[1]]
        if value[0] == "var" and value[1] == value[2] and self.tokens[value[1]].kind == "name":
            return self._functions_named(self.tokens[value[1]].value)
        return []

    def _exported_object(self, a: int) -> None:
        """module.exports = {f, g: h, k() {}}"""
        for key, found in self._members(a, self.pairs[a]).items():
            self.exports.setdefault(key, []).extend(found)

    # Calls.

    def _calls(self) -> dict[int, _Call]:
        """Each call, by the index of its (."""
        tokens, calls = self.tokens, {}
        for i, t in enumerate(tokens):
            if not _is(t, "(") or i in self.claimed or not i:
                continue
            scope = self.owner[i]
            j = i - 1
            if _is(tokens[j], "?."):
                j -= 1
            if _is(tokens[j], ")"):
                p = self.pairs[j]
                # (0, f)(): f called with no `this`, as compilers write it. For
                # eval that is ordinary global eval, read as eval itself, unless
                # f is reached through the global object.
                if p + 3 <= j and tokens[p + 1].kind == "num" and _is(tokens[p + 2], ","):
                    found = self._chain(p + 3, scope)
                    if found and found[1] == j - 1:
                        indirect = p + 4 < j and tokens[p + 3].value in _GLOBALS
                        calls[i] = _Call(i, found[0], "", False, indirect)
                        continue
                if p and _name(tokens[p - 1], "require") and not _after_dot(tokens, p - 1):
                    found = self._chain(p - 1, scope)  # require('m')(...)
                    if found:
                        calls[i] = _Call(i, found[0], "", False, False)
                elif p + 2 == j and tokens[p + 1].kind == "name":  # (f)(...)
                    found = self._chain(p + 1, scope)
                    calls[i] = _Call(i, found[0] if found else [], "", False, False)
                continue
            k = j  # back to the start of the chain: a.b.c, a['b'], require('m').c
            while True:
                if tokens[k].kind == "name" and k >= 2 and _after_dot(tokens, k):
                    k -= 2
                elif _is(tokens[k], "]") and self.pairs[k] == k - 2 and k >= 3:
                    if tokens[k - 1].kind not in ("string", "template"):
                        break
                    k -= 3
                else:
                    break
            method = f".{tokens[j].value}" if tokens[j].kind == "name" and k != j else ""
            if _is(tokens[k], ")"):
                p = self.pairs[k]
                if not (p and _name(tokens[p - 1], "require") and not _after_dot(tokens, p - 1)):
                    calls[i] = _Call(i, [], method, False, False)
                    continue
                k = p - 1
            if tokens[k].kind != "name":
                if method:
                    calls[i] = _Call(i, [], method, False, False)
                continue
            if k == j and tokens[k].value in _NOT_CALLEES:
                continue
            if k == j and tokens[k].value == "require" and not self.lookup("require", scope):
                calls[i] = _Call(i, [("", ("require",))], "", False, False)
                continue
            found = self._chain(k, scope)
            if not found or found[1] != j:
                calls[i] = _Call(i, [], method, False, False)
                continue
            new = k > 0 and _name(tokens[k - 1], "new")
            indirect = k != j and tokens[k].value in _GLOBALS
            calls[i] = _Call(i, found[0], method, new, indirect)
        return calls

    @staticmethod
    def dotted(call: _Call) -> list[str]:
        """What the callee may be, as dotted names; f.call() and f.apply() are f()."""
        found = []
        for module, attributes in call.names:
            if attributes[-1:] in (("call",), ("apply",)):
                attributes = attributes[:-1]
            found.append(".".join(p for p in (module, *attributes) if p))
        return found

    # What runs.

    def _invoked(self) -> dict[int, int]:
        """Function expressions called where they are written, each with the (
        of that call (-1 for none): (function(){})(), !function(){}(),
        (() => {})(), function(){}.call(this), new function(){}."""
        tokens, n, found = self.tokens, len(self.tokens), {}
        for f, function in enumerate(self.functions):
            s, nxt = function.start, function.body[1] + 1
            if function.declared or (
                _is(tokens[s], "(") and _is(tokens[function.params[1] + 1], "{")
            ):
                continue  # a declaration, or a method
            if nxt < n and _is(tokens[nxt], ")") and s and self.pairs[nxt] == s - 1:
                nxt += 1  # (function(){})
            if nxt < n and _is(tokens[nxt], "("):
                found[f] = nxt
            elif (
                nxt + 2 < n and _is(tokens[nxt], ".") and tokens[nxt + 1].value in ("call", "apply")
            ):
                if _is(tokens[nxt + 2], "("):
                    found[f] = nxt + 2
            elif s and _name(tokens[s - 1], "new"):
                found[f] = -1
            elif nxt < n and tokens[nxt].kind in ("template", "template_head"):
                found[f] = -1  # (function(){})`...`, a tagged template calls it
        return found

    def _running(self) -> dict[int, str]:
        """Scopes that run at load, each with how it is reached ("" for code
        that runs as part of the top level)."""
        invoked = self._invoked()
        calls_in: dict[int, list[_Call]] = {}
        for call in self.calls.values():
            calls_in.setdefault(self.owner[call.open], []).append(call)
        invoked_in: dict[int, list[int]] = {}
        for f in invoked:
            invoked_in.setdefault(self.parent[f], []).append(f)
        running: dict[int, str] = {-1: ""}
        roots: dict[int, str] = {-1: "called at load"}  # how the chain each scope is in starts
        todo = [-1]

        def reach(f: int, name: str, scope: int) -> None:
            """f runs, called by name (as code.py says it) or run in place."""
            if f not in running:
                running[f] = f"in {name}(), {roots[scope]}" if name else running[scope]
                roots[f] = roots[scope]
                todo.append(f)

        for name, how in self.entry.items():
            for f in self.exports.get(name, []):
                if f not in running:
                    shown = self.functions[f].name or name or "the default export"
                    running[f], roots[f] = f"in {shown}(), {how}", how
                    todo.append(f)
        while todo:
            scope = todo.pop()
            for f in invoked_in.get(scope, []):
                reach(f, "", scope)
                if invoked[f] > 0:  # a UMD factory, or a bundle's modules handed in
                    self._inside(invoked[f], self.pairs[invoked[f]], scope, reach)
            for call in calls_in.get(scope, []):
                for name, f in self._called_functions(call, scope):
                    reach(f, name, scope)
                dotted = self.dotted(call)
                if call.method in _RUNS_CALLBACK or any(d in _RUNS_CALLBACK for d in dotted):
                    self._callbacks(call.open, scope, reach)
                if any(d.rpartition(".")[2] in _BUNDLE_WRAPPERS for d in dotted):
                    self._inside(call.open, self.pairs[call.open], scope, reach)
            for a, b in self.tables.get(scope, []):
                self._inside(a, b, scope, reach)
        return running

    def _inside(self, a: int, b: int, scope: int, reach: Callable[[int, str, int], None]) -> None:
        """Run every function of scope written between tokens a and b."""
        for f in self.children.get(scope, []):
            if a < self.functions[f].start < b:
                reach(f, "", scope)

    def _called_functions(self, call: _Call, scope: int) -> list[tuple[str, int]]:
        """(name, function) for this file's functions a call calls by name:
        f(), (f)(), (0, f)(), f.call(), f.apply(), o.m() of an object literal,
        and a class's constructor for new C()."""
        tokens, j = self.tokens, call.open - 1
        if _is(tokens[j], "?."):
            j -= 1
        if _is(tokens[j], ")"):  # (f) or (0, f)
            p = self.pairs[j]
            if not (p + 2 == j or (p + 4 == j and tokens[p + 1].kind == "num")):
                return []
            j -= 1
        if tokens[j].kind == "name" and tokens[j].value in ("call", "apply") and j >= 2:
            if _is(tokens[j - 1], "."):
                j -= 2
        if tokens[j].kind != "name":
            return []
        member = ""
        if _after_dot(tokens, j):  # o.m()
            if j < 2 or tokens[j - 2].kind != "name" or _after_dot(tokens, j - 2):
                return []
            member, j = tokens[j].value, j - 2
        name = tokens[j].value
        key = (name, member, call.new, scope)
        if key not in self._called:  # each callee once per scope: lookups can be long
            self._called[key] = self._functions_called(name, member, call.new, scope)
        return self._called[key]

    def _functions_called(
        self, name: str, member: str, new: bool, scope: int
    ) -> list[tuple[str, int]]:
        found = []
        for value in self.lookup(name, scope):
            if value[0] == "fn" and not member:
                found.append((name, value[1]))
            elif value[0] == "obj" and member:
                found += [
                    (f"{name}.{member}", f) for f in self._members(*value[1:]).get(member, [])
                ]
            elif value[0] == "class" and new and not member:
                found += [
                    (f"{name}.constructor", f)
                    for f in self._members(*value[1:]).get("constructor", [])
                ]
        return found

    def _callbacks(self, open_: int, scope: int, reach: Callable[[int, str, int], None]) -> None:
        """Functions handed to the call whose ( is at open_, which it runs."""
        for a, b in self.arguments(open_):
            for f in self.starts.get(a, []):
                if self.functions[f].body[1] == b:
                    reach(f, "", scope)
            if a == b and self.tokens[a].kind == "name":
                for value in self.lookup(self.tokens[a].value, scope):
                    if value[0] == "fn":
                        reach(value[1], self.tokens[a].value, scope)

    # Hits.

    def hit(self, kind: str, line: int, detail: str) -> None:
        self.hits.append(Hit(kind, line, detail))

    def run(self) -> Analysis:
        tokens = self.tokens
        if self.whole:
            running = {f: "" for f in range(-1, len(self.functions))}
        else:
            running = self._running()
        stack: list[str | None] = []  # each open bracket's callee, None for one that is no call
        for i, t in enumerate(tokens):
            scope = self.owner[i]
            runs, before = scope in running, len(self.hits)
            if t.kind == "punct" and t.value in ("(", "[", "{"):
                call = self.calls.get(i)
                if call is not None:
                    self._hidden(call)  # anywhere, run or not
                    if runs:
                        self._call(call)
                elif t.value == "[" and i:
                    self._computed_global(i, scope)
                dotted = self.dotted(call) if call else []
                if call is None:  # an object or a block: calls outside get no value from in it
                    stack.append("{" if t.value == "{" else None)
                else:
                    stack.append(dotted[0] if dotted else call.method or "?")
            elif t.kind == "punct" and t.value in (")", "]", "}"):
                stack.pop()
            elif t.kind == "name" and runs and not _after_dot(tokens, i):
                if t.value == "process" or t.value in self.module_names:
                    self._environ(i, scope, stack)
            elif t.kind in (
                "string",
                "template",
                "template_head",
                "template_middle",
                "template_tail",
            ):
                for kind, detail in channels_in(t.value):  # anywhere, run or not
                    self.hit(kind, t.line, detail)
                if runs and t.kind in ("string", "template", "template_tail"):
                    self._path(t, stack)
            via = running.get(scope, "")
            for n in range(before, len(self.hits)):
                h = self.hits[n]
                if via and h.kind in _RUNNING_KINDS:
                    self.hits[n] = Hit(h.kind, h.line, f"{h.detail} ({via})")
        exported = {name for name in self.entry if name not in self.exports}
        for spec in self.reexports:
            self.loads.setdefault(spec, set()).update(exported)
        hits = sorted(self.hits, key=lambda h: h.line)
        unfound = () if self.reexports else tuple(n for n in self.entry if not self.exports.get(n))
        return Analysis(hits, self.loads, self.dynamic, self.crowded, unfound)

    def _call(self, call: _Call) -> None:
        tokens, line = self.tokens, self.tokens[call.open].line
        dotted = self.dotted(call)
        args = self.arguments(call.open)
        if any(d in _LOADERS for d in dotted) or (call.method == ".require" and not dotted):
            spec = self.spec(*args[0]) if args else None
            if spec is None:
                self.dynamic.append(line)
            else:
                self.loads.setdefault(unprefixed(spec[0]), set())
            return
        for module, attributes in call.names:
            if module and not is_builtin(module):
                self.loads.setdefault(module, set()).add(attributes[0] if attributes else "")
        for name in dotted:
            if _is_network(name):
                self.hit("network", line, f"calls {name}")
            elif name in _PROCESS_CALLS:
                self.hit("process", line, f"calls {name}")
                for j in range(call.open + 1, self.pairs[call.open]):
                    if tokens[j].kind in ("string", "template", "template_head", "template_tail"):
                        if match := FETCHING_COMMAND.search(tokens[j].value):
                            detail = f"runs a command that fetches ({match.group(0)})"
                            self.hit("network", line, detail)
                            break
            elif name in _EXEC_CALLS:
                # With no code (new Function(), a feature test) nothing runs.
                # Hidden code (see _hidden) is reported as that, not as exec.
                code = args[-1] if name == "Function" and args else args[0] if args else None
                if code and (literal := self.literal(*code)) is not None:
                    self._exec(name, literal[0], line)
                elif code and not (call.indirect or self.hiding(*code)):
                    self.hit("exec", line, f"calls {name}")
            elif name in _NATIVE_LOADERS:
                self.hit("native", line, f"loads a native addon through {name}")
            else:
                continue
            break

    def _hidden(self, call: _Call) -> None:
        """Hidden code: eval, Function, vm or require of decoded data, eval
        reached indirectly, a module name split up; and long encoded blobs
        handed to a decoder."""
        line, dotted = self.tokens[call.open].line, self.dotted(call)
        if not any(d in _DECODERS or d in _EXEC_CALLS or d in _LOADERS for d in dotted):
            return
        args = self.arguments(call.open)
        if not args:
            return
        if any(d in _DECODERS for d in dotted) and (literal := self.literal(*args[0])):
            encoding = self.literal(*args[1]) if len(args) > 1 else None
            decodes = "Buffer.from" not in dotted or (
                encoding is not None and encoding[0] in ("base64", "base64url", "hex")
            )
            if decodes and _looks_encoded(literal[0]):
                self.hit("encoded", line, f"decodes a {len(literal[0])}-character blob")
        if names := [d for d in dotted if d in _EXEC_CALLS]:
            code = args[-1] if names[0] == "Function" else args[0]
            if how := self.hiding(*code):
                self.hit("hidden", line, f"{names[0]} of {how}")
            elif call.indirect and names[0] == "eval" and self.literal(*code) is None:
                self.hit("hidden", line, "calls eval indirectly")
        elif any(d in _LOADERS for d in dotted):
            if self.literal(*args[0]) is None and (how := self.hiding(*args[0])):
                self.hit("hidden", line, f"require of {how}")
            spec = self.spec(*args[0])
            if spec and spec[1] > 1 and not spec[0].startswith("."):
                self.hit("hidden", line, "requires a module by a name split into pieces")

    def hiding(self, a: int, b: int, follow: bool = True) -> str | None:
        """How the code in a..b hides what it is, or None: decoded data,
        a string spelt with escapes, the name of eval itself, or a name bound
        once to decoded data."""
        tokens = self.tokens
        if (literal := self.literal(a, b)) is not None:
            if any(tokens[j].escaped for j in range(a, b + 1)):
                return "a string spelt with escapes"
            if literal[0].strip() in _HIDDEN_NAMES:
                return f"the name {literal[0].strip()}"
            return None
        # The first decoder call or ^ in the range, found by bisection: nested
        # calls each search their arguments, so a scan would be quadratic.
        k = bisect.bisect_left(self.decoding, a)
        if k < len(self.decoding) and self.decoding[k] <= b:
            j = self.decoding[k]
            if _is(tokens[j], "^"):
                return "XOR-decoded data"
            call = self.calls[j]
            name = next(d for d in [*self.dotted(call), call.method] if _is_decoder(d))
            return f"data decoded by {name.lstrip('.')}"
        if follow and a == b and tokens[a].kind == "name":
            values = self.lookup(tokens[a].value, self.owner[a])
            once = all(name != tokens[a].value for _, name in self.rebound)
            if once and len(values) == 1 and values[0][0] == "var" and values[0][1] < values[0][2]:
                return self.hiding(values[0][1], values[0][2], False)
        return None

    def _computed_global(self, i: int, scope: int) -> None:
        """global[...] by a name built at run time, or by the name of eval."""
        tokens = self.tokens
        before = tokens[i - 1]
        if before.kind != "name" or before.value not in _GLOBALS or _after_dot(tokens, i - 1):
            return
        if self.lookup(before.value, scope):
            return  # a local of that name (var self = this)
        a, b = i + 1, self.pairs[i] - 1
        if (literal := self.literal(a, b)) is not None:
            if literal[0] in _HIDDEN_NAMES:
                self.hit("hidden", before.line, f"reaches {literal[0]} through a computed name")
            return
        k = bisect.bisect_left(self.symbols, a)
        if k < len(self.symbols) and self.symbols[k] <= b:
            return  # globalThis[Symbol.for('x')]: a shared key, not a name
        k = bisect.bisect_left(self.building, a)
        if k < len(self.building) and self.building[k] <= b:
            self.hit("hidden", before.line, "reaches a global by a name built at run time")

    def _exec(self, name: str, code: str, line: int) -> None:
        """exec of a string written out: the string is read, and what it does
        reported here."""
        try:
            inner = analyse(tokenize(code), self.whole)
        except JSError:
            self.hit("exec", line, f"calls {name}")
            return
        # A channel is found in the string itself, not again in the code it holds.
        self.hits += [Hit(h.kind, line, h.detail) for h in inner.hits if h.kind not in _CHANNELS]
        for spec, names in inner.loads.items():
            self.loads.setdefault(spec, set()).update(names)
        self.dynamic += [line] * len(inner.dynamic)

    def _path(self, token: Token, stack: list[str | None]) -> None:
        """A credential path or a start-up location handed to a call that does
        more than build, test or print a path. A value in an object literal is
        data (a config's deny list), not a path handed on."""
        if match := _SECRET_PATH.search(token.value):
            kind, detail = "secrets", f"passes a credential path ({match.group(0).strip('/~')})"
        elif match := _PERSISTENCE_PATH.search(token.value):
            kind, detail = "persistence", f"passes a start-up location ({match.group(0)})"
        else:
            return
        calls = []
        for callee in reversed(stack):
            if callee == "{":
                break
            if callee is not None:
                calls.append(callee)
        if calls and not all(c in _PATH_BUILDERS for c in calls):
            self.hit(kind, token.line, detail)

    def _environ(self, i: int, scope: int, stack: list[str | None]) -> None:
        """process.env used whole: passed to a call, spread, iterated or
        formatted. Not inside an `env:` property, which hands a child process
        its environment."""
        tokens, n = self.tokens, len(self.tokens)
        found = self._chain(i, scope)
        if not found or ("", ("process", "env")) not in found[0] or not i:
            return
        end = found[1]
        after = tokens[end + 1] if end + 1 < n else None
        if after is not None and after.kind == "punct" and after.value in (".", "?.", "[", "="):
            return
        before, line = tokens[i - 1], tokens[i].line
        if self._child_environment(i):
            return
        if _is(before, "..."):
            self.hit("environ", line, "copies all of process.env")
        elif _name(before, "in") and self._for_in(i):
            self.hit("environ", line, "iterates over process.env")
        elif before.kind in ("template_head", "template_middle"):
            self.hit("environ", line, "formats all of process.env")
        elif (_is(before, "(") or _is(before, ",")) and stack and stack[-1] not in (None, "{"):
            if after is not None and (_is(after, ")") or _is(after, ",")):
                self.hit("environ", line, "passes all of process.env")

    def _for_in(self, i: int) -> bool:
        """Whether the `in` before i is a for-in loop's, not a membership test."""
        j = self.enclosing[i]
        return j > 0 and _is(self.tokens[j], "(") and _name(self.tokens[j - 1], "for")

    def _child_environment(self, i: int) -> bool:
        """Whether process.env at i is copied into an environment for a child
        process: {...process.env} or Object.assign({}, process.env, ...) as the
        value of an `env` property, or of a variable or property named env or
        ending Env or _env (`const env = {...process.env, A: 1}`)."""
        tokens, j = self.tokens, self.enclosing[i]
        if j < 0:
            return False
        if _is(tokens[j], "("):
            call = self.calls.get(j)
            if call is None or "Object.assign" not in self.dotted(call):
                return False
            j -= 1  # back over Object.assign
            while j >= 2 and _is(tokens[j - 1], "."):
                j -= 2
            j -= 1
        elif _is(tokens[j], "{"):
            j -= 1
        else:
            return False
        if j < 1 or not (_is(tokens[j], ":") or _is(tokens[j], "=")):
            return False
        name = tokens[j - 1]
        return name.kind in ("name", "string") and (
            name.value.lower() == "env" or name.value.endswith(("Env", "_env", "_ENV"))
        )
