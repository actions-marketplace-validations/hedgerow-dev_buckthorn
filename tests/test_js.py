"""The JavaScript tokenizer: tokens, depth, and failing closed on hostile input.

Every JavaScript snippet here is a string that is tokenized, never run.
"""

import time

import pytest

from buckthorn import js
from buckthorn.js import JSError, Token, calls, tokenize


def _kv(source, module=False):
    return [(t.kind, t.value) for t in tokenize(source, module)]


def _regexes(source):
    return [t.value for t in tokenize(source) if t.kind == "regex"]


def _fails(source, module=False):
    with pytest.raises(JSError) as info:
        tokenize(source, module)
    return info.value.kind


def test_simple_statement():
    assert tokenize("var a = 1;") == [
        Token("name", "var", 1, 0),
        Token("name", "a", 1, 0),
        Token("punct", "=", 1, 0),
        Token("num", "1", 1, 0),
        Token("punct", ";", 1, 0),
    ]


def test_longest_punctuator_wins():
    source = "a>>>=b?.c??d...e===f**=g=>h?.5:i"
    puncts = [v for k, v in _kv(source) if k == "punct"]
    assert puncts == [">>>=", "?.", "??", "...", "===", "**=", "=>", "?", ":"]
    assert ("num", ".5") in _kv(source)  # ?.5 is ? then .5


# Regex or division: decided by what comes before the slash.


@pytest.mark.parametrize(
    "source, regexes",
    [
        ("a / b / c", []),
        ("x = /ab+c/g.test(s)", ["/ab+c/g"]),
        ("return /re/", ["/re/"]),
        ("return/a/.test(b)", ["/a/"]),
        ("return a/b/c", []),
        ("if (x) /re/.test(y)", ["/re/"]),
        ("while (x) /re/.exec(y)", ["/re/"]),
        ("(a) / 2", []),
        ("f(x) / 2 / g(y)", []),
        ("a[0] / 2 / b[1]", []),
        ("if (a) {}\n/re/.test(b)", ["/re/"]),
        ("x = {a: 1} / 2 / 3", []),
        ("x = function () {} / 2 / 3", []),
        ("x = async function () {} / 2 / 3", []),
        ("function f() {}\n/re/.test(b)", ["/re/"]),
        ("x = () => {}\n/re/.test(b)", ["/re/"]),
        ("a.return / 2 / b.typeof", []),
        ("typeof /re/", ["/re/"]),
        ("a++ / 2 / b--", []),
        ("x = [/a/, /b/]", ["/a/", "/b/"]),
        ("f(/a/, b / c)", ["/a/"]),
        ("x = a ? /a/ : /b/", ["/a/", "/b/"]),
        ("x = !/a/.test(s)", ["/a/"]),
        ("switch (x) { case /a/: }", ["/a/"]),
        ("x = a\n/re/i", []),  # no semicolon is inserted before a slash: division
        ("this / 2 / that", []),
        ("`a${b}` / 2 / c", []),
        ("'s' / 2 / t", []),
        ("x = /[/]/.test(s)", ["/[/]/"]),
        ("x = /a\\/b/", ["/a\\/b/"]),
        ("x = /=/.test(s)", ["/=/"]),
        ("a /= 2 / b", []),
        ("x = /[\\]/]+/u", ["/[\\]/]+/u"]),
        ("for (const k of y) /a/.test(k)", ["/a/"]),
        ("x = y => /a/.test(y)", ["/a/"]),
        ("yield /a/", ["/a/"]),
        ("x = a\n++/re/.lastIndex", ["/re/"]),
        # A statement starts after a semicolon: a declaration, not an expression.
        ("a();\nfunction f() {}\n/'/.test(s)", ["/'/"]),
        ("x;{}\n/re/.test(s)", ["/re/"]),
        # `function` as an object key does not make the next ( a function's.
        ("o = {function: 1}; foo(x)\n{ }\n/re/.test(y)", ["/re/"]),
        # The : of a ternary is followed by an expression, even in a block.
        ("function g(){ return c ? a : {k: 1} / 2 / 3 }", []),
        ("x = a ? b : c\nlabel: {}\n/re/.test(s)", ["/re/"]),
    ],
)
def test_regex_or_division(source, regexes):
    assert _regexes(source) == regexes


def test_division_keeps_its_tokens():
    assert _kv("a/=b/c") == [
        ("name", "a"),
        ("punct", "/="),
        ("name", "b"),
        ("punct", "/"),
        ("name", "c"),
    ]


# Template literals, nested through ${ }.


def test_template_without_substitution_is_one_token():
    assert _kv("x = `a\\tb`") == [("name", "x"), ("punct", "="), ("template", "a\tb")]


def test_template_with_substitutions():
    assert _kv("`a${b}c${d}e`") == [
        ("template_head", "a"),
        ("name", "b"),
        ("template_middle", "c"),
        ("name", "d"),
        ("template_tail", "e"),
    ]


def test_nested_templates_and_depth():
    tokens = tokenize("`${ `${x}` }`")
    assert [(t.kind, t.value, t.depth) for t in tokens] == [
        ("template_head", "", 0),
        ("template_head", "", 1),
        ("name", "x", 2),
        ("template_tail", "", 1),
        ("template_tail", "", 0),
    ]


def test_braces_inside_a_substitution_do_not_end_it():
    kinds = [k for k, _ in _kv("`${ {a: `}`}.a }!`")]
    assert kinds == [
        "template_head",
        "punct",
        "name",
        "punct",
        "template",
        "punct",
        "punct",
        "name",
        "template_tail",
    ]


def test_dollar_and_escapes_in_templates():
    assert _kv("`$a $ \\${b} \\``") == [("template", "$a $ ${b} `")]


def test_template_lines_are_counted():
    tokens = tokenize("`a\nb\r\nc`\nx")
    assert [(t.kind, t.line) for t in tokens] == [("template", 1), ("name", 4)]


def test_regex_after_a_template_substitution():
    assert _regexes("`${/a/.source}`") == ["/a/"]


# Comments.


def test_line_and_block_comments():
    tokens = tokenize("a // b\n/* c\nd */ e /**/ f")
    assert [(t.value, t.line) for t in tokens] == [("a", 1), ("e", 3), ("f", 3)]


def test_hashbang_only_at_the_start():
    assert [(t.value, t.line) for t in tokenize("#!/usr/bin/env node\nx")] == [("x", 2)]
    assert _fails("x\n#!/usr/bin/env node") == "unexpected-char"


def test_html_like_comments_in_a_script():
    source = "a <!-- b\n--> c\n/*\n*/ --> d\ne"
    assert [t.value for t in tokenize(source, module=False)] == ["a", "e"]


def test_html_close_comment_only_at_line_start():
    assert [v for _, v in _kv("a-->b")] == ["a", "--", ">", "b"]


def test_html_like_comments_are_code_in_a_module():
    assert [v for _, v in _kv("a <!-- b", module=True)] == ["a", "<", "!", "--", "b"]


def test_html_like_comments_fail_closed_when_the_kind_of_file_is_unknown():
    # Node may run a .js file as either; the two readings differ, so neither is used.
    assert _fails("a <!-- b; evil()", module=None) == "html-comment"
    assert _fails("x\n--> evil()", module=None) == "html-comment"
    assert len(tokenize("a < !--b", module=None)) == 5


# Strings and escapes.


@pytest.mark.parametrize(
    "source, value",
    [
        ("'\\x41\\u0042\\u{43}'", "ABC"),
        ('"\\n\\t\\r\\b\\f\\v\\0"', "\n\t\r\b\f\v\0"),
        ("'a\\\nb'", "ab"),  # line continuation
        ("'a\\\r\nb'", "ab"),
        ("'\\u{1F600}'", "\U0001f600"),
        ("'\\uD83D\\uDE00'", "\U0001f600"),
        ("'\\101'", "A"),  # legacy octal
        ("'\\8\\q\\''", "8q'"),
        ("'a b'", "a b"),  # allowed in strings since ES2019
        ("'nul\x00here'", "nul\x00here"),
        ("'\\u{0}'", "\x00"),
    ],
)
def test_string_escapes(source, value):
    assert _kv(source) == [("string", value)]


def test_line_continuation_counts_the_line():
    assert [t.line for t in tokenize("'a\\\nb' c")] == [1, 2]


@pytest.mark.parametrize("source", ["'\\x4'", "'\\u12'", "'\\u{110000}'", "'\\u{}'"])
def test_bad_string_escape_fails_closed(source):
    assert _fails(source) == "bad-escape"


def test_identifier_escapes_are_decoded():
    # eval is eval: phase 3 must see the call.
    assert _kv("\\u0065val('x'); \\u{63}onsole") == [
        ("name", "eval"),
        ("punct", "("),
        ("string", "x"),
        ("punct", ")"),
        ("punct", ";"),
        ("name", "console"),
    ]


def test_unicode_identifiers_and_private_names():
    assert _kv("class A { #x = 1; m() { return this.#x + café } }")[3:6] == [
        ("private", "#x"),
        ("punct", "="),
        ("num", "1"),
    ]
    assert ("name", "café") in _kv("café")


# Numbers.


def test_numeric_literals():
    source = "0x1F 0o17 0b101 1_000 1.5e-3 .5 5. 10n 0xFFn 1e+10 017"
    assert _kv(source) == [("num", v) for v in source.split()]


def test_number_then_member():
    assert _kv("1..toString()")[:3] == [("num", "1."), ("punct", "."), ("name", "toString")]


# Minified input: one long line.


def test_minified_single_line():
    source = "!function(e){var t=e/2,n=/x+/g.test(e);return t?`${n}`:{a:[1,2]}}(1);" * 20_000
    tokens = tokenize(source)
    assert all(t.line == 1 for t in tokens)
    assert len(tokens) == 43 * 20_000
    assert sum(t.kind == "regex" for t in tokens) == 20_000
    assert {t.depth for t in tokens} == {0, 1, 2, 3}


# Depth and brackets.


def test_depth_of_brackets():
    tokens = tokenize("f(a[b], {c: d})")
    assert [(t.value, t.depth) for t in tokens] == [
        ("f", 0),
        ("(", 0),
        ("a", 1),
        ("[", 1),
        ("b", 2),
        ("]", 1),
        (",", 1),
        ("{", 1),
        ("c", 2),
        (":", 2),
        ("d", 2),
        ("}", 1),
        (")", 0),
    ]


@pytest.mark.parametrize("source", ["f(a))", "f(a]", "{(}", "f(", "[", "{", "}"])
def test_unbalanced_brackets_fail_closed(source):
    assert _fails(source) == "unbalanced"


# Things a phase 3 rule needs: calls with their callee, at what depth.


def test_calls_phase_3_will_look_for():
    source = (
        "const cp = require('child_process');\n"
        "require('child_process').exec('id');\n"
        "eval(s); new Function('a', b);\n"
        "child_process.exec(c); cp['exec'](d); a?.b(e);\n"
        "if (x) { y(1) } function f(z) { g() } class K { m(q) { } }\n"
        "(function () { h() })();\n"
    )
    tokens = tokenize(source)
    found = [(name, tokens[i].line, tokens[i].depth) for name, i in calls(tokens)]
    assert found == [
        ("require", 1, 0),
        ("require", 2, 0),
        ("require().exec", 2, 0),
        ("eval", 3, 0),
        ("Function", 3, 0),
        ("child_process.exec", 4, 0),
        ("cp.exec", 4, 0),
        ("a.b", 4, 0),
        ("y", 5, 1),
        ("g", 5, 1),
        ("h", 6, 2),
    ]
    first_args = [tokens[i + 1].value for name, i in calls(tokens) if name == "require"]
    assert first_args == ["child_process", "child_process"]


def test_a_call_followed_by_a_block_on_the_next_line_is_a_call():
    # No semicolon is needed there, so `{` after `)` alone is not a definition.
    tokens = tokenize("eval(payload)\n{}\nm(q) {}")
    assert [name for name, _ in calls(tokens)] == ["eval"]


def test_string_literals_are_decoded_values():
    tokens = tokenize("x = ['\\x63hild_process', `ev${'a'}l`, \"plain\"]")
    strings = [t.value for t in tokens if t.kind in ("string", "template")]
    assert strings == ["child_process", "a", "plain"]


# Hostile input: everything fails closed, fast.


@pytest.mark.parametrize(
    "source, kind",
    [
        ("x = 'abc", "unterminated-string"),
        ("x = 'abc\ndef'", "unterminated-string"),
        ('x = "abc', "unterminated-string"),
        ("x = `abc", "unterminated-template"),
        ("x = `a${b", "unterminated-template"),
        ("x = `a${b}c", "unterminated-template"),
        ("x = /abc", "unterminated-regex"),
        ("x = /abc\n/", "unterminated-regex"),
        ("x = /[/", "unterminated-regex"),
        ("x = 1 /* abc", "unterminated-comment"),
        ("x = 1 \x00", "unexpected-char"),
        ("x = 1 \\", "unexpected-char"),
        ("x = @@@ §", "unexpected-char"),
    ],
)
def test_unterminated_and_bad_input_fails_closed(source, kind):
    assert _fails(source) == kind


def test_error_carries_the_line():
    with pytest.raises(JSError) as info:
        tokenize("a\nb\n'c")
    assert info.value.line == 3


def test_invalid_utf8_fails_closed():
    with pytest.raises(JSError) as info:
        tokenize(b"var a = '\xff\xfe';")
    assert info.value.kind == "not-utf8"


def test_bytes_with_a_bom_are_read():
    assert _kv(b"\xef\xbb\xbfa") == [("name", "a")]
    with pytest.raises(JSError) as info:
        tokenize(b"\xef\xbb\xbfa\n\xff")
    assert info.value.line == 2


def test_nul_bytes_inside_strings_and_comments_are_fine():
    assert _kv(b"'\x00' /* \x00 */ // \x00") == [("string", "\x00")]


def test_too_large_fails_closed(monkeypatch):
    monkeypatch.setattr(js, "MAX_SOURCE_BYTES", 100)
    assert _fails("a;" * 51) == "too-large"
    assert _fails(b"a;" * 51) == "too-large"


def test_too_many_tokens_fails_closed(monkeypatch):
    monkeypatch.setattr(js, "MAX_TOKENS", 100)
    assert len(tokenize("a;" * 50)) == 100
    assert _fails("a;" * 51) == "too-many-tokens"


@pytest.mark.parametrize("opener", ["(", "[", "{", "`${"])
def test_deep_nesting_fails_closed(opener):
    assert _fails(opener * 200_000) == "too-deep"


def test_nesting_up_to_the_limit_is_fine():
    depth = js.MAX_DEPTH
    tokens = tokenize("(" * depth + "x" + ")" * depth)
    assert max(t.depth for t in tokens) == depth


PATHOLOGICAL = [
    "'" + "\\" * 1_000_001,  # unterminated string of escapes
    "'" + "\\a" * 500_000,
    '"' + "a" * 1_000_000,
    "`" + "$" * 1_000_000,  # $ never followed by {
    "`" + "\\`" * 500_000,
    "x = /" + "[\\[" * 300_000,  # unterminated class in a regex
    "x = /" + "\\/" * 500_000,
    "/*" + "*" * 1_000_000,
    "a" * 1_000_000 + "\\u",
    "1" + "_" * 1_000_000 + "'",  # then an unterminated string
    "\\u{" + "0" * 1_000_000,
    "<!--" * 250_000,
]


@pytest.mark.parametrize("source", PATHOLOGICAL, ids=range(len(PATHOLOGICAL)))
def test_pathological_input_is_linear(source):
    started = time.monotonic()
    with pytest.raises(JSError):
        tokenize(source, module=None)
    assert time.monotonic() - started < 5  # a backtracking regex takes minutes here


def test_huge_template_and_string_tokenize():
    source = "x = `" + "a${b}" * 100_000 + "`; y = '" + "z" * 2_000_000 + "'"
    tokens = tokenize(source)
    assert len(tokens) == 2 + 200_001 + 4
    assert len(tokens[-1].value) == 2_000_000


def test_a_regex_after_of_in_a_for_loop():
    # Read as a division, /[/*]/ would open a fake comment that hides code.
    tokens = tokenize("for (const x of /[/*]/.source) {}\nrun()\n// */ ] ) {}\n")
    assert ("regex", "/[/*]/") in [(t.kind, t.value) for t in tokens]
    assert ("name", "run") in [(t.kind, t.value) for t in tokens]
    assert [t.kind for t in tokenize("of / 2 / 1")] == ["name", "punct", "num", "punct", "num"]


def test_jsx_is_not_read():
    # JSX is not JavaScript; npm ships compiled code. Text in it fails closed
    # rather than being read as code.
    assert _fails("x = <p>it's</p>") in {"unterminated-string", "unterminated-regex"}
    assert _fails("x = <div>\n  text\n</div>") == "unterminated-regex"
