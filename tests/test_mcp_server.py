"""The MCP tools are plain functions; only the stdio round trip needs the `mcp` extra."""

import hashlib
import json
import os
import subprocess
import sys

import pytest

from buckthorn import lock
from buckthorn.mcp_server import check_release, scan_path

SHADOW = "import sys; sys.modules['collections'] = None\n"


def test_flagged_wheel(make_wheel):
    report = scan_path(str(make_wheel({"pkg.pth": SHADOW})))
    assert report["verdict"] == "flagged"
    assert report["artifacts"][0]["findings"][0]["rule_id"] == "BKT-PTH-002"


def test_clean_folder(make_wheel, tmp_path):
    make_wheel({"pkg/__init__.py": "x = 1\n"})
    assert scan_path(str(tmp_path))["verdict"] == "clean"


def test_missing_path_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="no such file"):
        scan_path(str(tmp_path / "absent.whl"))


def test_fifo_raises_value_error_instead_of_hanging(tmp_path):
    fifo = tmp_path / "x.whl"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="not a regular file"):
        scan_path(str(fifo))


def test_check_release_fetches_from_pypi(make_wheel, monkeypatch):
    data = make_wheel({"pkg.pth": SHADOW}).read_bytes()
    url = "https://files.pythonhosted.org/packages/aa/pkg-1.0-py3-none-any.whl"
    index = {
        "urls": [
            {
                "filename": "pkg-1.0-py3-none-any.whl",
                "url": url,
                "digests": {"sha256": hashlib.sha256(data).hexdigest()},
            }
        ]
    }
    responses = {url: data, "https://pypi.org/pypi/pkg/1.0/json": json.dumps(index).encode()}
    monkeypatch.setattr(lock, "fetch_url", lambda u, n: responses[u])
    report = check_release("pkg", "1.0")
    assert report["verdict"] == "flagged"
    assert report["artifacts"][0]["path"] == "pkg-1.0-py3-none-any.whl"


def test_check_release_unknown_raises_value_error(monkeypatch):
    def missing(url, max_bytes):
        raise lock.FetchError("404")

    monkeypatch.setattr(lock, "fetch_url", missing)
    with pytest.raises(ValueError, match="404"):
        check_release("nope", "1.0")


def test_core_works_without_the_sdk():
    # Importing the tool functions must not import the MCP SDK.
    code = "import sys, buckthorn.mcp_server; print('mcp' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_stdio_server_lists_tools_and_returns_the_same_json(make_wheel, tmp_path):
    pytest.importorskip("mcp")
    import anyio
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters

    evil = str(make_wheel({"pkg.pth": SHADOW}))
    params = StdioServerParameters(command=sys.executable, args=["-m", "buckthorn", "mcp"])

    async def session():
        async with Client(params) as client:
            tools = (await client.list_tools()).tools
            hit = await client.call_tool("scan_path", {"path": evil})
            miss = await client.call_tool("scan_path", {"path": str(tmp_path / "absent.whl")})
            return tools, hit, miss

    tools, hit, miss = anyio.run(session)
    assert sorted(tool.name for tool in tools) == ["check_mcp_config", "check_release", "scan_path"]
    assert not hit.is_error
    result = json.loads(hit.content[0].text)
    expected = scan_path(evil)
    assert result["artifacts"] == expected["artifacts"]
    assert miss.is_error
    assert "no such file" in miss.content[0].text
