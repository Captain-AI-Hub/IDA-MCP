"""IDA-MCP installer.

Copies the IDA plugin (ida_mcp.py + ida_mcp/ + ida-plugin.json) into IDA's
plugins directory. The in-IDA bridge is stdlib-only, so nothing is installed
into IDAPython anymore.

The standalone MCP server runs outside IDA (stdio transport) via::

    uvx idamcp stdio        # or: python -m ida_mcp stdio

Usage:
    python install.py [--ida /path/to/ida] [--plugins /path/to/plugins] [--uninstall]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
_PLUGIN_FILES = ("ida_mcp.py", "ida-plugin.json")
_PLUGIN_DIRS = ("ida_mcp",)


def _default_user_dir() -> Path | None:
    idausr = os.environ.get("IDAUSR", "").strip()
    if idausr:
        return Path(idausr.split(os.pathsep)[0].strip()).expanduser()
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "").strip()
        if appdata:
            return Path(appdata) / "Hex-Rays" / "IDA Pro"
    return Path.home() / ".idapro"


def _ida_dirs_from_config() -> list[Path]:
    """Candidate IDA install dirs recorded in ida-config.json."""
    candidates: list[Path] = []
    user_dir = _default_user_dir()
    config_path = user_dir / "ida-config.json" if user_dir else None
    if config_path is not None and config_path.is_file():
        try:
            document = json.loads(config_path.read_text(encoding="utf-8"))
            install_dir = ((document.get("Paths") or {}).get("ida-install-dir") or "").strip()
            if install_dir:
                candidates.append(Path(install_dir))
        except (OSError, ValueError):
            pass
    return candidates


def _resolve_plugins_dir(explicit: str | None, ida_executable: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    if ida_executable:
        candidate = Path(ida_executable).expanduser().parent / "plugins"
        if candidate.is_dir():
            return candidate
    user_dir = _default_user_dir()
    if user_dir:
        return user_dir / "plugins"
    raise SystemExit("Could not determine the IDA plugins directory; pass --plugins.")


def install(plugins_dir: Path) -> list[Path]:
    plugins_dir.mkdir(parents=True, exist_ok=True)
    installed: list[Path] = []
    for name in _PLUGIN_FILES:
        target = plugins_dir / name
        shutil.copy2(_REPO_ROOT / name, target)
        installed.append(target)
    for name in _PLUGIN_DIRS:
        target = plugins_dir / name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(
            _REPO_ROOT / name, target, ignore=shutil.ignore_patterns("__pycache__")
        )
        installed.append(target)
    return installed


def uninstall(plugins_dir: Path) -> list[Path]:
    removed: list[Path] = []
    for name in (*_PLUGIN_FILES, *_PLUGIN_DIRS):
        target = plugins_dir / name
        if target.is_dir():
            shutil.rmtree(target)
            removed.append(target)
        elif target.exists():
            target.unlink()
            removed.append(target)
    return removed


def _persist_detections(args) -> None:
    """Cache machine-specific detections into the user-scope config."""
    from ida_mcp.config import persist_user_setting
    from ida_mcp.lifecycle import resolve_idalib_python

    ida_executable = args.ida
    if not ida_executable:
        for install_dir in _ida_dirs_from_config():
            for name in ("ida", "ida64", "ida.exe", "ida64.exe"):
                candidate = install_dir / name
                if candidate.is_file():
                    ida_executable = str(candidate)
                    break
            if ida_executable:
                break
    if ida_executable:
        persist_user_setting("ida_path", ida_executable)
    idalib = resolve_idalib_python()
    if idalib:
        print(f"Detected idalib Python (headless workers): {idalib}")
    else:
        print(
            "No idalib-activated Python detected; headless open_database will "
            "retry and explain how to activate one when needed."
        )


def _print_client_config() -> None:
    print("\nMCP client configuration (stdio):")
    print(
        json.dumps(
            {
                "mcpServers": {
                    "ida-mcp": {"command": "uvx", "args": ["idamcp-hub", "stdio"]}
                }
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    print(
        f"\nFrom a checkout instead of PyPI:\n"
        f"  cd {_REPO_ROOT} && {sys.executable} -m ida_mcp stdio\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IDA-MCP plugin installer")
    parser.add_argument("--ida", default=None, help="IDA executable path (plugins dir next to it)")
    parser.add_argument("--plugins", default=None, help="IDA plugins directory override")
    parser.add_argument("--uninstall", action="store_true", help="Remove IDA-MCP from IDA")
    args = parser.parse_args(argv)

    plugins_dir = _resolve_plugins_dir(args.plugins, args.ida)
    print(f"IDA plugins directory: {plugins_dir}")

    if args.uninstall:
        removed = uninstall(plugins_dir)
        print(f"Removed {len(removed)} item(s).")
        return 0

    installed = install(plugins_dir)
    print(f"Installed {len(installed)} item(s):")
    for path in installed:
        print(f"  {path}")
    print("\nThe in-IDA bridge is stdlib-only; no IDAPython packages are required.")
    try:
        _persist_detections(args)
    except Exception as exc:  # noqa: BLE001 - detection is best effort
        print(f"Detection skipped: {exc}")
    _print_client_config()
    return 0


if __name__ == "__main__":
    sys.exit(main())
