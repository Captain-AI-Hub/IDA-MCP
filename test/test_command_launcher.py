"""Tests for HCLI companion command launcher creation."""

from __future__ import annotations

import os
from pathlib import Path

from ida_mcp.command_launcher import install_hcli_launchers


def test_install_hcli_launchers_creates_gateway_and_full_commands(tmp_path):
    hcli = tmp_path / ("hcli.exe" if os.name == "nt" else "hcli")
    python = tmp_path / ("python.exe" if os.name == "nt" else "python3")
    command = tmp_path / "plugins" / "IDA-MCP" / "ida_mcp" / "command.py"
    hcli.write_bytes(b"")
    python.write_bytes(b"")
    command.parent.mkdir(parents=True)
    command.write_text("", encoding="utf-8")

    launchers = install_hcli_launchers(
        python_executable=python,
        command_script=command,
        hcli_executable=hcli,
    )

    names = {path.name for path in launchers}
    if os.name == "nt":
        assert names == {"hcli-gateway.cmd", "hcli-ida-mcp.cmd"}
    else:
        assert names == {"hcli-gateway", "hcli-ida-mcp"}
    gateway = next(path for path in launchers if path.name.startswith("hcli-gateway"))
    content = gateway.read_text(encoding="utf-8")
    assert str(python.resolve()) in content
    assert str(command.resolve()) in content
    assert " gateway " in content


def test_install_hcli_launchers_is_idempotent(tmp_path):
    hcli = tmp_path / ("hcli.exe" if os.name == "nt" else "hcli")
    python = tmp_path / ("python.exe" if os.name == "nt" else "python3")
    command = tmp_path / "command.py"
    for path in (hcli, python, command):
        path.write_bytes(b"")

    first = install_hcli_launchers(
        python_executable=python,
        command_script=command,
        hcli_executable=hcli,
    )
    mtimes = {path: path.stat().st_mtime_ns for path in first}
    second = install_hcli_launchers(
        python_executable=python,
        command_script=command,
        hcli_executable=hcli,
    )

    assert first == second
    assert {path: path.stat().st_mtime_ns for path in second} == mtimes
