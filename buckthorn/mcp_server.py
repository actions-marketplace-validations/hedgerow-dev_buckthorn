"""A stdio MCP server so a coding agent can check a package before installing it.

    buckthorn mcp

Three tools: `scan_path` for wheels and sdists on disk, `check_release` for
name==version on PyPI, and `check_mcp_config` for the servers an MCP config
launches. The logic is the plain functions of the same names, which need
nothing beyond the core package; only `serve()` imports the MCP SDK (the
optional `buckthorn[mcp]` extra). Nothing read is installed, imported or run.
Only `check_release` and `check_mcp_config` use the network, under the same
rules as `buckthorn check`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from buckthorn import lock, mcp_config
from buckthorn.cli import InputError, artifacts, json_report, scan_file


def scan_path(path: str) -> dict[str, Any]:
    """Scan a wheel, an sdist, or a folder of them. Same JSON as `--format json`.

    Raises ValueError for a missing path, a FIFO or device (a read would block
    the server), or a folder with no wheels or sdists in it.
    """
    target = Path(path)
    if not target.exists():
        raise ValueError(f"no such file or folder: {path}")
    if not (target.is_file() or target.is_dir()):
        raise ValueError(f"not a regular file or folder: {path}")
    try:
        return json_report([scan_file(p) for p in artifacts([target])])
    except InputError as exc:
        raise ValueError(str(exc)) from exc


def check_release(name: str, version: str) -> dict[str, Any]:
    """Fetch the file of name==version this machine would install from PyPI, check its
    sha256 and scan it. Raises ValueError when PyPI has no such release or file."""
    try:
        return json_report([lock.scan_release(name, version)])
    except lock.FetchError as exc:
        raise ValueError(str(exc)) from exc


def check_mcp_config(contents: str) -> dict[str, Any]:
    """Check every PyPI package an MCP config (its file contents) would install:
    each server, and the dependencies uvx or pipx would install with it.
    Raises ValueError for text that is not an MCP config."""
    try:
        servers = mcp_config.servers(contents)
    except ValueError as exc:
        raise ValueError(f"not an MCP config: {exc}") from exc
    if servers is None:
        raise ValueError("not an MCP config: no mcpServers or servers table")
    return json_report(mcp_config.check(servers))


def serve() -> None:
    """Run the MCP server on stdin/stdout until the client disconnects."""
    from importlib.metadata import version as package_version

    from mcp.server.mcpserver import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.types import ToolAnnotations

    server = MCPServer("buckthorn", version=package_version("buckthorn"))

    @server.tool(
        name="scan_path",
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    def scan_path_tool(path: str) -> str:
        """Check a Python wheel or sdist (or a folder of them) without installing it.

        Returns JSON with a verdict (clean, flagged or not_verified) and the
        findings: code that runs at install, start-up or import, hidden code,
        unexpected binaries. Call this before installing a package file.
        """
        try:
            return json.dumps(scan_path(path))
        except (OSError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        name="check_release",
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True),
    )
    def check_release_tool(name: str, version: str) -> str:
        """Check a PyPI release (name and exact version) before installing it.

        Fetches the file this machine would install, checks its hash, and scans
        it without installing it. Returns JSON with a verdict (clean, flagged or
        not_verified) and the findings. Call this before `pip install name==version`.
        """
        try:
            return json.dumps(check_release(name, version))
        except (OSError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        name="check_mcp_config",
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True),
    )
    def check_mcp_config_tool(contents: str) -> str:
        """Check an MCP config (the text of .mcp.json, mcp.json or
        claude_desktop_config.json) before an agent loads it.

        For each server it launches with uvx, uv or pipx, fetches the PyPI package
        that would run and the dependencies that launcher would install with it,
        checks their hashes and scans them without installing or building anything.
        npm, container and local servers are reported as not checked. Returns JSON
        with a verdict (clean, flagged or not_verified) and the findings. Values
        from the config (env, arguments, URLs) are never echoed back.
        """
        try:
            return json.dumps(check_mcp_config(contents))
        except (OSError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    server.run("stdio")
