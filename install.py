#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime
from glob import glob
from pathlib import Path
from typing import Iterable

from ida_mcp.config import parse_config_file


REPO_ROOT = Path(__file__).resolve().parent
SOURCE_PLUGIN_FILE = REPO_ROOT / "ida_mcp.py"
SOURCE_PLUGIN_DIR = REPO_ROOT / "ida_mcp"
SOURCE_CONFIG = SOURCE_PLUGIN_DIR / "config.conf"
REQUIREMENTS_FILE = REPO_ROOT / "requirements.txt"


def detect_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    raise RuntimeError(f"Unsupported platform: {sys.platform}")


def unique_existing_paths(paths: Iterable[Path]) -> list[Path]:
    seen: OrderedDict[str, Path] = OrderedDict()
    for path in paths:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            continue
        if resolved.exists() and resolved.is_file():
            seen[str(resolved).lower() if detect_platform() == "windows" else str(resolved)] = resolved
    return list(seen.values())


def existing_windows_drives() -> list[str]:
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(drive)
    return drives


def candidate_ida_patterns(platform_name: str) -> list[str]:
    patterns: list[str] = []
    if platform_name == "windows":
        roots = []
        for env_name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            value = os.environ.get(env_name)
            if value:
                roots.append(value)
        roots.extend(existing_windows_drives())
        win_suffixes = [
            "IDA Pro*\\ida64.exe",
            "IDA Pro*\\ida.exe",
            "IDA*\\ida64.exe",
            "IDA*\\ida.exe",
            "IDAPro*\\ida64.exe",
            "IDAPro*\\ida.exe",
            "Hex-Rays*\\ida64.exe",
            "Hex-Rays*\\ida.exe",
            "safetools\\IDA*\\ida64.exe",
            "safetools\\IDA*\\ida.exe",
            "safetools\\IDAPro*\\ida64.exe",
            "safetools\\IDAPro*\\ida.exe",
            "tools\\IDA*\\ida64.exe",
            "tools\\IDA*\\ida.exe",
        ]
        for root in roots:
            for suffix in win_suffixes:
                patterns.append(str(Path(root) / suffix))
    elif platform_name == "linux":
        roots = ["/opt", "/usr/local", str(Path.home()), str(Path.home() / "tools")]
        linux_suffixes = [
            "ida*/ida64",
            "ida*/ida",
            "IDA*/ida64",
            "IDA*/ida",
            "IDA Pro*/ida64",
            "IDA Pro*/ida",
            "hex-rays*/ida64",
            "hex-rays*/ida",
        ]
        for root in roots:
            for suffix in linux_suffixes:
                patterns.append(str(Path(root) / suffix))
    else:
        roots = ["/Applications", str(Path.home() / "Applications")]
        mac_suffixes = [
            "IDA*.app/Contents/MacOS/ida64",
            "IDA*.app/Contents/MacOS/ida",
            "IDA Pro*.app/Contents/MacOS/ida64",
            "IDA Pro*.app/Contents/MacOS/ida",
            "Hex-Rays*.app/Contents/MacOS/ida64",
            "Hex-Rays*.app/Contents/MacOS/ida",
        ]
        for root in roots:
            for suffix in mac_suffixes:
                patterns.append(str(Path(root) / suffix))
    return patterns


def discover_ida_executables(platform_name: str, config: dict[str, object]) -> list[Path]:
    candidates: list[Path] = []
    for env_name in ("IDA_PATH", "IDADIR"):
        value = os.environ.get(env_name)
        if value:
            candidates.extend(resolve_ida_input(Path(value), platform_name))
    configured_path = config.get("ida_path")
    if isinstance(configured_path, str) and configured_path:
        candidates.extend(resolve_ida_input(Path(configured_path), platform_name))
    for pattern in candidate_ida_patterns(platform_name):
        candidates.extend(Path(match) for match in glob(pattern))
    return sort_ida_executables(unique_existing_paths(candidates), platform_name)


def sort_ida_executables(paths: list[Path], platform_name: str) -> list[Path]:
    def score(path: Path) -> tuple[int, str]:
        name = path.name.lower()
        path_str = str(path).lower()
        preferred = 0
        if "ida64" in name:
            preferred -= 20
        if "ida" == name or name == "ida.exe":
            preferred -= 10
        if "idapro" in path_str or "ida pro" in path_str:
            preferred -= 5
        if platform_name == "windows" and "program files" in path_str:
            preferred -= 2
        return (preferred, path_str)

    return sorted(paths, key=score)


def resolve_ida_input(path: Path, platform_name: str) -> list[Path]:
    expanded = path.expanduser()
    if not expanded.exists():
        return []
    if expanded.is_file():
        return [expanded]
    candidates = []
    if platform_name == "windows":
        names = ("ida64.exe", "ida.exe")
    else:
        names = ("ida64", "ida")
    for name in names:
        candidate = expanded / name
        if candidate.exists() and candidate.is_file():
            candidates.append(candidate)
    if platform_name == "macos" and expanded.suffix == ".app":
        for name in names:
            candidate = expanded / "Contents" / "MacOS" / name
            if candidate.exists() and candidate.is_file():
                candidates.append(candidate)
    return candidates


def find_ida_python_candidates(install_dir: Path, platform_name: str) -> list[Path]:
    explicit = []
    if platform_name == "windows":
        explicit.extend(
            [
                install_dir / "ida-python" / "python.exe",
                install_dir / "python" / "python.exe",
                install_dir / "python.exe",
            ]
        )
    else:
        explicit.extend(
            [
                install_dir / "ida-python" / "python",
                install_dir / "ida-python" / "python3",
                install_dir / "python" / "bin" / "python3",
                install_dir / "python" / "bin" / "python",
                install_dir / "python3",
                install_dir / "python",
            ]
        )

    names = {"python.exe"} if platform_name == "windows" else {"python", "python3"}
    discovered = list(explicit)
    for root, dirs, files in os.walk(install_dir):
        root_path = Path(root)
        try:
            depth = len(root_path.relative_to(install_dir).parts)
        except ValueError:
            depth = 99
        if depth > 3:
            dirs[:] = []
            continue
        for file_name in files:
            if file_name not in names:
                continue
            discovered.append(root_path / file_name)

    return sort_python_candidates(unique_existing_paths(discovered))


def sort_python_candidates(paths: list[Path]) -> list[Path]:
    def score(path: Path) -> tuple[int, str]:
        path_str = str(path).lower()
        preferred = 0
        if "ida-python" in path_str:
            preferred -= 20
        if "python/bin" in path_str.replace("\\", "/"):
            preferred -= 10
        return (preferred, path_str)

    return sorted(paths, key=score)


def prompt(message: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    response = input(f"{message}{suffix}: ").strip()
    if not response and default is not None:
        return default
    return response


def prompt_bool(message: str, default: bool) -> bool:
    default_label = "Y/n" if default else "y/N"
    while True:
        response = input(f"{message} [{default_label}]: ").strip().lower()
        if not response:
            return default
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False
        print("Please answer y or n.")


def prompt_int(message: str, default: int) -> int:
    while True:
        response = prompt(message, str(default))
        try:
            return int(response)
        except ValueError:
            print("Please enter an integer.")


def choose_path(candidates: list[Path], label: str, platform_name: str) -> Path:
    while True:
        if candidates:
            print(f"\nDiscovered {label}:")
            for idx, candidate in enumerate(candidates, start=1):
                print(f"  {idx}. {candidate}")
            response = input(
                f"Choose {label} by number, or enter a custom path (Enter for 1): "
            ).strip()
            if not response:
                return candidates[0]
            if response.isdigit():
                index = int(response)
                if 1 <= index <= len(candidates):
                    return candidates[index - 1]
            custom = Path(response).expanduser()
        else:
            custom = Path(input(f"Enter {label} path: ").strip()).expanduser()

        if label == "IDA executable":
            resolved = resolve_ida_input(custom, platform_name)
        elif label == "IDA Python executable" and custom.is_dir():
            resolved = find_ida_python_candidates(custom, platform_name)
        else:
            resolved = [custom]
        valid = unique_existing_paths(resolved)
        if valid:
            return valid[0]
        print(f"Path not valid for {label}: {custom}")


def prompt_existing_file(message: str, default: str) -> str:
    while True:
        response = prompt(message, default)
        candidate = Path(response).expanduser()
        if candidate.exists() and candidate.is_file():
            return str(candidate.resolve())
        print(f"Path does not exist or is not a file: {candidate}")


def derive_plugins_dir(ida_executable: Path) -> Path:
    plugins_dir = ida_executable.parent / "plugins"
    if plugins_dir.exists():
        return plugins_dir
    return plugins_dir


def run_command(command: list[str], cwd: Path | None = None) -> None:
    print(f"\n$ {' '.join(command)}")
    subprocess.run(command, cwd=str(cwd) if cwd else None, check=True)


def ensure_pip(ida_python: Path) -> None:
    try:
        run_command([str(ida_python), "-m", "pip", "--version"])
    except subprocess.CalledProcessError:
        print("\n`pip` was not available in the IDA Python environment. Trying ensurepip...")
        run_command([str(ida_python), "-m", "ensurepip", "--upgrade"])
        run_command([str(ida_python), "-m", "pip", "--version"])


def install_requirements(ida_python: Path) -> None:
    ensure_pip(ida_python)
    run_command([str(ida_python), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)])


def backup_file(path: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = path.with_name(f"{path.name}.bak.{timestamp}")
    shutil.copy2(path, backup_path)
    return backup_path


def copy_plugin_tree(plugins_dir: Path) -> None:
    plugins_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_PLUGIN_FILE, plugins_dir / SOURCE_PLUGIN_FILE.name)
    shutil.copytree(
        SOURCE_PLUGIN_DIR,
        plugins_dir / SOURCE_PLUGIN_DIR.name,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".pytest_cache"),
    )


def quote_config_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value).replace("\\", "\\").replace('"', '\\"')
    return f'"{text}"'


def render_config(config: dict[str, object]) -> str:
    return "\n".join(
        [
            "# IDA-MCP configuration file",
            f"# Generated by install.py on {datetime.now().isoformat(timespec='seconds')}",
            "",
            "# Transport switches",
            f"enable_stdio = {quote_config_value(config['enable_stdio'])}",
            f"enable_http = {quote_config_value(config['enable_http'])}",
            f"enable_unsafe = {quote_config_value(config['enable_unsafe'])}",
            "",
            "# Coordinator settings (host is fixed to 127.0.0.1 in code)",
            f"coordinator_port = {quote_config_value(config['coordinator_port'])}",
            "",
            "# HTTP proxy settings",
            f"http_host = {quote_config_value(config['http_host'])}",
            f"http_port = {quote_config_value(config['http_port'])}",
            f"http_path = {quote_config_value(config['http_path'])}",
            "",
            "# IDA instance settings",
            f"ida_default_port = {quote_config_value(config['ida_default_port'])}",
            f"ida_path = {quote_config_value(config['ida_path'])}",
            "",
            "# General settings",
            f"request_timeout = {quote_config_value(config['request_timeout'])}",
            f"debug = {quote_config_value(config['debug'])}",
            "",
        ]
    )


def build_config_interactively(defaults: dict[str, object], ida_executable: Path) -> dict[str, object]:
    config = {
        "enable_stdio": bool(defaults.get("enable_stdio", False)),
        "enable_http": bool(defaults.get("enable_http", True)),
        "enable_unsafe": bool(defaults.get("enable_unsafe", True)),
        "coordinator_port": int(defaults.get("coordinator_port", 11337)),
        "http_host": str(defaults.get("http_host", "127.0.0.1")),
        "http_port": int(defaults.get("http_port", 11338)),
        "http_path": str(defaults.get("http_path", "/mcp")),
        "ida_default_port": int(defaults.get("ida_default_port", 10000)),
        "ida_path": str(ida_executable),
        "request_timeout": int(defaults.get("request_timeout", 30)),
        "debug": bool(defaults.get("debug", False)),
    }

    print("\nConfigure ida_mcp/config.conf")
    config["enable_http"] = prompt_bool("Enable HTTP proxy mode", bool(config["enable_http"]))
    config["enable_stdio"] = prompt_bool("Enable stdio proxy mode", bool(config["enable_stdio"]))
    config["enable_unsafe"] = prompt_bool("Enable unsafe tools", bool(config["enable_unsafe"]))
    config["coordinator_port"] = prompt_int("Coordinator port", int(config["coordinator_port"]))
    config["http_host"] = prompt("HTTP proxy host", str(config["http_host"]))
    config["http_port"] = prompt_int("HTTP proxy port", int(config["http_port"]))
    config["http_path"] = prompt("HTTP proxy path", str(config["http_path"]))
    config["ida_default_port"] = prompt_int(
        "Per-instance default starting port",
        int(config["ida_default_port"]),
    )
    config["ida_path"] = prompt_existing_file(
        "IDA executable path for open_in_ida",
        str(config["ida_path"]),
    )
    config["request_timeout"] = prompt_int("Request timeout (seconds)", int(config["request_timeout"]))
    config["debug"] = prompt_bool("Enable debug logging", bool(config["debug"]))

    if not config["enable_http"] and not config["enable_stdio"]:
        print("\nWarning: both HTTP and stdio modes are disabled. The plugin will not start transports.")
        if not prompt_bool("Keep both modes disabled", False):
            config["enable_http"] = True

    return config


def print_summary(
    ida_executable: Path,
    ida_python: Path,
    plugins_dir: Path,
    config: dict[str, object],
) -> None:
    print("\nInstallation summary")
    print(f"  IDA executable : {ida_executable}")
    print(f"  IDA Python     : {ida_python}")
    print(f"  Plugins dir    : {plugins_dir}")
    print(f"  enable_http    : {config['enable_http']}")
    print(f"  enable_stdio   : {config['enable_stdio']}")
    print(f"  enable_unsafe  : {config['enable_unsafe']}")
    print(f"  http endpoint  : {config['http_host']}:{config['http_port']}{config['http_path']}")
    print(f"  coordinator    : 127.0.0.1:{config['coordinator_port']}")
    print(f"  ida_default_port: {config['ida_default_port']}")
    print(f"  request_timeout: {config['request_timeout']}")
    print(f"  debug          : {config['debug']}")


def validate_repo_layout() -> None:
    missing = [
        path for path in (SOURCE_PLUGIN_FILE, SOURCE_PLUGIN_DIR, SOURCE_CONFIG, REQUIREMENTS_FILE) if not path.exists()
    ]
    if missing:
        raise FileNotFoundError(f"Repository is missing required files: {', '.join(str(p) for p in missing)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install IDA-MCP into an IDA Pro installation and configure config.conf interactively."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover paths and collect config, but do not install requirements or copy files.",
    )
    args = parser.parse_args()

    validate_repo_layout()
    platform_name = detect_platform()
    defaults = parse_config_file(str(SOURCE_CONFIG))

    print(f"Detected platform: {platform_name}")
    ida_executable = choose_path(
        discover_ida_executables(platform_name, defaults),
        "IDA executable",
        platform_name,
    )
    install_dir = ida_executable.parent
    plugins_dir = derive_plugins_dir(ida_executable)
    ida_python = choose_path(
        find_ida_python_candidates(install_dir, platform_name),
        "IDA Python executable",
        platform_name,
    )
    config = build_config_interactively(defaults, ida_executable)
    print_summary(ida_executable, ida_python, plugins_dir, config)

    if not prompt_bool("Continue with installation", True):
        print("Installation cancelled.")
        return 1

    if args.dry_run:
        print("Dry run finished. No changes were made.")
        return 0

    install_requirements(ida_python)

    destination_config = plugins_dir / "ida_mcp" / "config.conf"
    if destination_config.exists():
        backup_path = backup_file(destination_config)
        print(f"Backed up existing config to: {backup_path}")

    copy_plugin_tree(plugins_dir)
    destination_config.parent.mkdir(parents=True, exist_ok=True)
    destination_config.write_text(render_config(config), encoding="utf-8")

    print("\nInstallation completed successfully.")
    print(f"Plugin files installed to: {plugins_dir}")
    print(f"Config written to: {destination_config}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInstallation interrupted.")
        raise SystemExit(130)
