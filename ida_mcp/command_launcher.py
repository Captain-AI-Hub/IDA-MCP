"""Install companion command launchers next to the HCLI executable."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterable


def _quote_cmd(value: str | Path) -> str:
    return '"' + str(value).replace('"', '""') + '"'


def _quote_sh(value: str | Path) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def _launcher_specs(
    python_executable: Path,
    command_script: Path,
) -> dict[str, str]:
    if os.name == "nt":
        python_arg = _quote_cmd(python_executable)
        command_arg = _quote_cmd(command_script)
        return {
            "hcli-ida-mcp.cmd": (
                "@echo off\r\n"
                f"{python_arg} {command_arg} %*\r\n"
                "exit /b %errorlevel%\r\n"
            ),
            "hcli-gateway.cmd": (
                "@echo off\r\n"
                f"{python_arg} {command_arg} gateway %*\r\n"
                "exit /b %errorlevel%\r\n"
            ),
        }

    python_arg = _quote_sh(python_executable)
    command_arg = _quote_sh(command_script)
    return {
        "hcli-ida-mcp": (
            "#!/bin/sh\n"
            f"exec {python_arg} {command_arg} \"$@\"\n"
        ),
        "hcli-gateway": (
            "#!/bin/sh\n"
            f"exec {python_arg} {command_arg} gateway \"$@\"\n"
        ),
    }


def install_hcli_launchers(
    *,
    python_executable: str | Path,
    command_script: str | Path,
    hcli_executable: str | Path | None = None,
) -> list[Path]:
    """Create `hcli-gateway` and `hcli-ida-mcp` beside HCLI.

    The HCLI installation directory is already on PATH on standard standalone
    installations, so the companion commands become immediately available.
    """
    python_path = Path(python_executable).expanduser().resolve()
    command_path = Path(command_script).expanduser().resolve()
    if not python_path.is_file():
        raise FileNotFoundError(f"Python executable not found: {python_path}")
    if not command_path.is_file():
        raise FileNotFoundError(f"IDA-MCP command.py not found: {command_path}")

    if hcli_executable is None:
        detected_hcli = shutil.which("hcli")
        if not detected_hcli:
            raise FileNotFoundError("hcli executable was not found in PATH")
        hcli_path = Path(detected_hcli).resolve()
    else:
        hcli_path = Path(hcli_executable).expanduser().resolve()
    if not hcli_path.is_file():
        raise FileNotFoundError(f"hcli executable not found: {hcli_path}")

    target_dir = hcli_path.parent
    installed: list[Path] = []
    for filename, content in _launcher_specs(python_path, command_path).items():
        destination = target_dir / filename
        encoded = content.encode("utf-8")
        existing = destination.read_bytes() if destination.is_file() else None
        if existing != encoded:
            destination.write_bytes(encoded)
            if os.name != "nt":
                destination.chmod(0o755)
        installed.append(destination)
    return installed


def candidate_installed_command_paths() -> Iterable[Path]:
    """Yield common HCLI plugin installation paths for command.py."""
    home = Path.home()
    appdata = os.environ.get("APPDATA")
    if appdata:
        appdata_path = Path(appdata)
        yield appdata_path / "Hex-Rays" / "IDA Pro" / "plugins" / "IDA-MCP" / "ida_mcp" / "command.py"
        yield appdata_path / ".idapro" / "plugins" / "IDA-MCP" / "ida_mcp" / "command.py"
    yield home / ".idapro" / "plugins" / "IDA-MCP" / "ida_mcp" / "command.py"
    yield home / ".idapro" / "plugins" / "ida-mcp" / "ida_mcp" / "command.py"


def find_installed_command() -> Path | None:
    for candidate in candidate_installed_command_paths():
        if candidate.is_file():
            return candidate.resolve()
    return None
