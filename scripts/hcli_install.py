#!/usr/bin/env python3
"""Configure IDA-MCP for headless idalib workers.

There is no GUI plugin to install anymore: this script only finds a Python
interpreter that can ``import idapro`` — normally IDA's own bundled runtime
at ``<IDA install>/ida-python/bin/pythonX.Y`` — and caches it as
``ida_python`` in the user config. The standalone MCP server runs from any
Python >= 3.11 via ``uvx idamcp-hub stdio``.

IDA install dir resolution (only used to narrow the interpreter search):
    1. --ida argument
    2. $IDADIR
    3. <IDAUSR>/ida-config.json "Paths"."ida-install-dir" (written by HCLI)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def default_ida_user_dir() -> Path:
    idausr = os.environ.get("IDAUSR", "").strip()
    if idausr:
        return Path(idausr.split(os.pathsep)[0]).expanduser()
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "").strip()
        return Path(appdata) / "Hex-Rays" / "IDA Pro" if appdata else Path.home() / ".idapro"
    return Path.home() / ".idapro"


def resolve_install_dir(explicit: str | None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_dir():
            raise FileNotFoundError(f"IDA install dir not found: {path}")
        return path
    idadir = os.environ.get("IDADIR", "").strip()
    if idadir and Path(idadir).is_dir():
        return Path(idadir)
    config_path = default_ida_user_dir() / "ida-config.json"
    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
        configured = (document.get("Paths") or {}).get("ida-install-dir") or ""
    except (OSError, ValueError, TypeError):
        return None
    configured = str(configured).strip()
    if configured and Path(configured).is_dir():
        return Path(configured)
    return None


def bundled_python_candidates(install_dir: Path) -> list[Path]:
    """Python executables that ship inside an IDA installation."""
    ida_python_dir = install_dir / "ida-python"
    candidates: list[Path] = []
    bin_dir = ida_python_dir / "bin"
    if bin_dir.is_dir():
        for name in ("python3", "python"):
            candidates.append(bin_dir / name)
        for entry in sorted(os.listdir(bin_dir)):
            if re.match(r"^python3\.\d+$", entry):
                candidates.append(bin_dir / entry)
    for name in ("python", "python3", "python.exe", "pythonw.exe"):
        candidates.append(ida_python_dir / name)
    return candidates


def can_idalib(python: Path, install_dir: Path | None) -> bool:
    env = dict(os.environ)
    if install_dir is not None:
        env["IDADIR"] = str(install_dir)
    try:
        completed = subprocess.run(
            [str(python), "-c", "import idapro"],
            capture_output=True,
            timeout=30,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def resolve_idalib_python(
    install_dir: Path | None, explicit_python: str | None
) -> Path | None:
    candidates: list[Path] = []
    if explicit_python:
        candidate = Path(explicit_python).expanduser()
        if not candidate.is_file():
            raise FileNotFoundError(f"Python interpreter not found: {candidate}")
        candidates.append(candidate)
    if install_dir is not None:
        candidates.extend(bundled_python_candidates(install_dir))
    if sys.executable:
        candidates.append(Path(sys.executable))

    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(str(candidate.resolve()))
        if key in seen or not candidate.is_file():
            continue
        seen.add(key)
        if can_idalib(candidate, install_dir):
            return candidate
    return None


def persist_ida_python(python: Path) -> bool:
    try:
        from ida_mcp.config import persist_user_setting
    except Exception:  # noqa: BLE001 - caching is best effort
        return False
    persist_user_setting("ida_python", str(python))
    return True


def print_mcp_client_config() -> None:
    print("Copy this configuration into your MCP client's mcp.json:")
    print(
        json.dumps(
            {"mcpServers": {"ida-mcp": {"command": "uvx", "args": ["idamcp-hub", "stdio"]}}},
            ensure_ascii=False,
            indent=2,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ida",
        help="IDA installation directory; default: $IDADIR or ida-config.json",
    )
    parser.add_argument(
        "--python",
        help="Python interpreter that can 'import idapro'; default: auto-detect",
    )
    args = parser.parse_args(argv)

    try:
        install_dir = resolve_install_dir(args.ida)
        idalib_python = resolve_idalib_python(install_dir, args.python)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if install_dir is not None:
        print(f"IDA install dir: {install_dir}")
    else:
        print("IDA install dir not found; searching PATH python and sys.executable")

    if idalib_python is None:
        print(
            "error: no Python found that can 'import idapro'. Install IDA Pro 9.0+ "
            "and its idalib bindings (hcli ida install && uv pip install idapro, "
            "or use IDA's bundled ida-python runtime), then re-run.",
            file=sys.stderr,
        )
        return 1

    print(f"idalib worker python: {idalib_python}")
    if persist_ida_python(idalib_python):
        print("Saved to user config (ida_python).")
    print_mcp_client_config()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
