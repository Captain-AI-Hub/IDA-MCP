#!/usr/bin/env python3
"""Install IDA-MCP with HCLI after detecting the local IDAPython interpreter."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ida_python_detection import detect_ida_python as _detect_ida_python
from ida_python_detection import parse_idapyswitch_output as _parse_idapyswitch_output
from package_hcli import ROOT, build_archive

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))



def _ida_executable_name() -> str:
    return "ida.exe" if os.name == "nt" else "ida"


def _normalize_ida_executable(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        if sys.platform == "darwin" and path.suffix == ".app":
            path = path / "Contents" / "MacOS" / "ida"
        else:
            names = ("ida.exe", "ida64.exe") if os.name == "nt" else ("ida", "ida64")
            path = next((path / name for name in names if (path / name).is_file()), path / names[0])
    return path.resolve()


def _ida_executable_from_hcli_config() -> Path | None:
    """Read HCLI/IDA's selected installation from $IDAUSR/ida-config.json."""
    roots: list[Path] = []
    for value in (os.environ.get("HCLI_IDAUSR"), os.environ.get("IDAUSR")):
        if value:
            roots.append(Path(value.split(os.pathsep)[0]).expanduser())
    roots.append(Path.home() / ".idapro")

    for root in roots:
        config_path = root / "ida-config.json"
        try:
            document = json.loads(config_path.read_text(encoding="utf-8"))
            configured = document.get("Paths", {}).get("ida-install-dir")
        except (OSError, ValueError, TypeError):
            continue
        if configured:
            candidate = _normalize_ida_executable(configured)
            if candidate.is_file():
                return candidate
    return None


def _candidate_ida_executables() -> list[Path]:
    candidates: list[Path] = []
    configured = os.environ.get("HCLI_CURRENT_IDA_INSTALL_DIR")
    if configured:
        candidates.append(_normalize_ida_executable(configured))
    configured_from_file = _ida_executable_from_hcli_config()
    if configured_from_file is not None:
        candidates.append(configured_from_file)

    if os.name == "nt":
        for drive in ("D:/", "C:/"):
            root = Path(drive)
            if root.exists():
                candidates.extend(sorted(root.glob("IDAPro*/ida.exe"), reverse=True))
                candidates.extend(sorted(root.glob("IDA*/ida.exe"), reverse=True))
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(variable)
            if not base:
                continue
            root = Path(base)
            candidates.extend(sorted(root.glob("IDA*/ida.exe"), reverse=True))
            candidates.extend(sorted(root.glob("Hex-Rays/IDA*/ida.exe"), reverse=True))
    elif sys.platform == "darwin":
        candidates.extend(
            [
                Path("/Applications/IDA Professional 9.4.app/Contents/MacOS/ida"),
                Path("/Applications/IDA Professional.app/Contents/MacOS/ida"),
                Path("/Applications/IDA Pro.app/Contents/MacOS/ida"),
            ]
        )
    else:
        candidates.extend(sorted(Path("/opt").glob("ida*/ida"), reverse=True))
        candidates.extend(sorted(Path("/opt").glob("IDA*/ida"), reverse=True))
        candidates.extend(sorted(Path.home().glob("ida*/ida"), reverse=True))
        candidates.extend(sorted(Path.home().glob(".local/share/applications/IDA*/ida"), reverse=True))
        candidates.extend(sorted(Path.home().glob(".local/share/applications/ida*/ida"), reverse=True))

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = os.path.normcase(str(candidate.resolve()))
        if normalized in seen or not candidate.is_file():
            continue
        seen.add(normalized)
        unique.append(candidate.resolve())
    return unique


def choose_ida_executable(explicit: str | None) -> Path:
    if explicit:
        selected = _normalize_ida_executable(explicit)
        if not selected.is_file():
            raise FileNotFoundError(f"IDA executable not found: {selected}")
        return selected

    candidates = _candidate_ida_executables()
    guess = candidates[0] if candidates else None
    prompt = "IDA executable"
    if guess:
        prompt += f" [{guess}]"
    prompt += ": "
    answer = input(prompt).strip().strip('"').strip("'")
    if answer:
        selected = _normalize_ida_executable(answer)
    elif guess:
        selected = guess
    else:
        raise ValueError("IDA executable is required")
    if not selected.is_file():
        raise FileNotFoundError(f"IDA executable not found: {selected}")
    return selected


# Compatibility re-exports for callers that imported these helpers from this module.
def parse_idapyswitch_output(output: str, *, windows: bool) -> list[dict[str, str]]:
    return _parse_idapyswitch_output(output, windows=windows)


def detect_ida_python(ida_executable: Path) -> Path | None:
    return _detect_ida_python(ida_executable)


def build_hcli_environment(ida_python: Path, base: dict[str, str] | None = None) -> dict[str, str]:
    """Build an HCLI environment that cannot fall back to its own Python."""
    env = dict(os.environ if base is None else base)
    env["HCLI_CURRENT_IDA_PYTHON_EXE"] = str(ida_python)
    return env


def personalize_archive(
    source: Path,
    destination: Path,
    *,
    ida_executable: Path,
    ida_python: Path | None,
    gateway_token: str | None = None,
) -> None:
    """Inject machine-specific defaults into a temporary HCLI install archive."""
    with zipfile.ZipFile(source, "r") as input_zip:
        members = [(info, input_zip.read(info.filename)) for info in input_zip.infolist()]

    manifest_info = next((info for info, _ in members if info.filename == "ida-plugin.json"), None)
    if manifest_info is None:
        raise ValueError("archive does not contain ida-plugin.json at its root")

    manifest_bytes = next(data for info, data in members if info.filename == "ida-plugin.json")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    settings = {item["key"]: item for item in manifest["plugin"].get("settings", [])}

    ida_path_setting = settings["ida_path"]
    ida_path_setting["default"] = str(ida_executable)
    ida_path_setting["name"] = f"IDA executable path ({ida_executable})"

    if gateway_token is not None:
        settings["gateway_token"]["default"] = gateway_token

    python_setting = settings["ida_python"]
    if ida_python is not None:
        python_setting["default"] = str(ida_python)
        python_setting["name"] = f"IDAPython interpreter path ({ida_python})"
    else:
        python_setting["default"] = "auto"
        python_setting["name"] = "IDAPython interpreter path (not detected; resolve on first IDA launch)"

    updated_manifest = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w") as output_zip:
        for info, data in members:
            if info.filename == "ida-plugin.json":
                data = updated_manifest
            output_zip.writestr(info, data)


def mcp_client_config(gateway_token: str) -> dict[str, object]:
    return {
        "mcpServers": {
            "ida-mcp": {
                "url": "http://127.0.0.1:11338/mcp",
                "headers": {
                    "Authorization": f"Bearer {gateway_token}",
                    "X-IDA-MCP-Token": gateway_token,
                },
            }
        }
    }


def print_mcp_client_config(gateway_token: str) -> None:
    print("Copy this configuration into your MCP client's mcp.json:")
    print(json.dumps(mcp_client_config(gateway_token), ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "archive",
        nargs="?",
        type=Path,
        default=ROOT / "dist" / "main.zip",
        help="HCLI archive to install (default: dist/main.zip)",
    )
    parser.add_argument(
        "--ida",
        help="IDA executable or installation directory; otherwise detected and confirmed interactively",
    )
    parser.add_argument(
        "--prepare-only",
        type=Path,
        help="write the personalized archive here instead of invoking HCLI",
    )
    args = parser.parse_args()

    archive = args.archive if args.archive.is_absolute() else ROOT / args.archive
    if not archive.is_file():
        print(f"Building missing archive: {archive}")
        build_archive(archive)

    try:
        ida_executable = choose_ida_executable(args.ida)
        ida_python = detect_ida_python(ida_executable)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    gateway_token = secrets.token_urlsafe(32)

    print(f"Detected IDA executable: {ida_executable}")
    if ida_python is None:
        print("error: IDAPython was not detected; refusing to use the system Python", file=sys.stderr)
        return 1
    print(f"Detected IDAPython interpreter: {ida_python}")

    if args.prepare_only:
        destination = args.prepare_only if args.prepare_only.is_absolute() else ROOT / args.prepare_only
        personalize_archive(
            archive,
            destination,
            ida_executable=ida_executable,
            ida_python=ida_python,
            gateway_token=gateway_token,
        )
        print(f"Prepared personalized HCLI archive: {destination}")
        print_mcp_client_config(gateway_token)
        return 0

    hcli = shutil.which("hcli")
    if not hcli:
        print("error: hcli was not found in PATH", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="ida-mcp-hcli-") as temporary_dir:
        personalized = Path(temporary_dir) / "main.zip"
        personalize_archive(
            archive,
            personalized,
            ida_executable=ida_executable,
            ida_python=ida_python,
            gateway_token=gateway_token,
        )
        print("Starting HCLI with the detected IDAPython interpreter for dependency installation...")
        # HCLI 0.19 honors this override before probing or falling back.
        env = build_hcli_environment(ida_python)
        return_code = subprocess.run(
            [hcli, "plugin", "install", str(personalized)],
            env=env,
            check=False,
        ).returncode
        if return_code == 0:
            print_mcp_client_config(gateway_token)
        return return_code


if __name__ == "__main__":
    raise SystemExit(main())
