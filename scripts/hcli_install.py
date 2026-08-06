#!/usr/bin/env python3
"""Install IDA-MCP with HCLI after detecting the local IDAPython interpreter."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from package_hcli import ROOT, build_archive

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_mcp.command_launcher import find_installed_command, install_hcli_launchers


def _ida_executable_name() -> str:
    return "ida.exe" if os.name == "nt" else "ida"


def _normalize_ida_executable(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        path /= _ida_executable_name()
    return path.resolve()


def _candidate_ida_executables() -> list[Path]:
    candidates: list[Path] = []
    configured = os.environ.get("HCLI_CURRENT_IDA_INSTALL_DIR")
    if configured:
        candidates.append(_normalize_ida_executable(configured))

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
        candidates.extend(sorted(Path.home().glob("ida*/ida"), reverse=True))

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


def parse_idapyswitch_output(output: str, *, windows: bool) -> list[dict[str, str]]:
    """Parse idapyswitch output, placing IDA's previous interpreter first."""
    results: list[dict[str, str]] = []
    for match in re.finditer(
        r"#(\d+):\s+([\d.]+)\s+\([^)]+\)\s+\((.+?)(?:python3\d*\.dll)?\)",
        output,
    ):
        index, version, raw_dir = match.group(1), match.group(2), match.group(3)
        raw_dir = raw_dir.rstrip("\\/")
        executable = Path(raw_dir) / ("python.exe" if windows else "bin/python3")
        if executable.is_file():
            results.append(
                {
                    "index": index,
                    "version": version,
                    "dir": raw_dir,
                    "exe": str(executable.resolve()),
                }
            )

    preferred = re.search(
        r"IDA previously used:\s+.+?\((.+?)(?:python3\d*\.dll)?\)",
        output,
    )
    if preferred:
        preferred_dir = os.path.normcase(preferred.group(1).rstrip("\\/"))
        for position, result in enumerate(results):
            if os.path.normcase(result["dir"]) == preferred_dir:
                results.insert(0, results.pop(position))
                break
    return results


def detect_ida_python(ida_executable: Path) -> Path | None:
    ida_dir = ida_executable.parent
    switch_name = "idapyswitch.exe" if os.name == "nt" else "idapyswitch"
    switch_path = ida_dir / switch_name
    if switch_path.is_file():
        try:
            process = subprocess.run(
                [str(switch_path)],
                cwd=str(ida_dir),
                input=b"\n",
                capture_output=True,
                timeout=15,
                check=False,
            )
            raw_output = (process.stdout or b"") + (process.stderr or b"")
            output = raw_output.decode("utf-8", errors="replace")
            installations = parse_idapyswitch_output(
                output,
                windows=os.name == "nt",
            )
            if installations:
                return Path(installations[0]["exe"])
        except (OSError, subprocess.SubprocessError):
            pass

    fallback_candidates = []
    if os.name == "nt":
        fallback_candidates.extend(
            [
                ida_dir / "ida-python" / "python.exe",
                ida_dir / "python" / "python.exe",
            ]
        )
    else:
        fallback_candidates.extend(
            [
                ida_dir / "ida-python" / "bin" / "python3",
                ida_dir / "python" / "bin" / "python3",
            ]
        )
    return next((path.resolve() for path in fallback_candidates if path.is_file()), None)


def personalize_archive(
    source: Path,
    destination: Path,
    *,
    ida_executable: Path,
    ida_python: Path | None,
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

    print(f"Detected IDA executable: {ida_executable}")
    if ida_python:
        print(f"Detected IDAPython interpreter: {ida_python}")
    else:
        print("IDAPython interpreter was not detected; first-launch auto-detection will be used.")

    if args.prepare_only:
        destination = args.prepare_only if args.prepare_only.is_absolute() else ROOT / args.prepare_only
        personalize_archive(
            archive,
            destination,
            ida_executable=ida_executable,
            ida_python=ida_python,
        )
        print(f"Prepared personalized HCLI archive: {destination}")
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
        )
        print("Starting HCLI with detected paths as the prompt defaults...")
        result = subprocess.run(
            [hcli, "plugin", "install", str(personalized)],
            check=False,
        )
        if result.returncode == 0 and ida_python is not None:
            installed_command = find_installed_command()
            if installed_command is not None:
                try:
                    launchers = install_hcli_launchers(
                        python_executable=ida_python,
                        command_script=installed_command,
                        hcli_executable=hcli,
                    )
                    print(
                        "Installed gateway control commands: "
                        + ", ".join(path.name for path in launchers)
                    )
                    print("Examples: hcli-gateway status | start | stop | restart")
                except OSError as exc:
                    print(f"warning: could not install HCLI companion commands: {exc}")
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
