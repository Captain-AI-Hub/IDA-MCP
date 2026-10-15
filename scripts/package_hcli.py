#!/usr/bin/env python3
"""Build a deterministic HCLI-compatible IDA-MCP plugin archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT_FILES = (
    "ida-plugin.json",
    "ida_mcp.py",
    "README.md",
    "LICENSE",
    "requirements.txt",
)
EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
FIXED_TIMESTAMP = (2020, 1, 1, 0, 0, 0)


def _validate_manifest() -> dict:
    manifest_path = ROOT / "ida-plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    plugin = manifest.get("plugin")
    if not isinstance(plugin, dict):
        raise ValueError("ida-plugin.json is missing the plugin object")

    for key in ("name", "version", "entryPoint", "urls"):
        if not plugin.get(key):
            raise ValueError(f"ida-plugin.json is missing plugin.{key}")

    entry_point = ROOT / str(plugin["entryPoint"])
    if not entry_point.is_file():
        raise ValueError(f"plugin entry point does not exist: {entry_point}")
    return plugin


def _iter_package_files() -> list[tuple[Path, PurePosixPath]]:
    files: list[tuple[Path, PurePosixPath]] = []
    for relative in PLUGIN_ROOT_FILES:
        source = ROOT / relative
        if not source.is_file():
            raise FileNotFoundError(f"required package file not found: {source}")
        files.append((source, PurePosixPath(relative)))

    package_dir = ROOT / "ida_mcp"
    for source in sorted(package_dir.rglob("*")):
        relative = source.relative_to(ROOT)
        if not source.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if source.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        files.append((source, PurePosixPath(relative.as_posix())))

    archive_names = [archive_name.as_posix() for _, archive_name in files]
    if len(archive_names) != len(set(archive_names)):
        raise ValueError("duplicate archive paths detected")
    return sorted(files, key=lambda item: item[1].as_posix())


def _local_machine_defaults() -> dict[str, str]:
    """Best-effort local detection so install prompts come pre-filled.

    Reads <IDAUSR>/ida-config.json for the install dir, then derives the IDA
    executable and the ida-python runtime. Returns {} on CI/unknown machines,
    leaving the packaged manifest untouched.
    """
    import os

    from ida_python_detection import default_ida_user_dir

    idausr = os.environ.get("IDAUSR", "").strip()
    user_root = (
        Path(idausr.split(os.pathsep)[0]).expanduser() if idausr else default_ida_user_dir()
    )
    try:
        document = json.loads((user_root / "ida-config.json").read_text(encoding="utf-8"))
        install_dir = Path(
            ((document.get("Paths") or {}).get("ida-install-dir") or "").strip()
        )
    except (OSError, ValueError):
        return {}
    if not install_dir.is_dir():
        return {}

    defaults: dict[str, str] = {}
    exe_name = "ida.exe" if os.name == "nt" else "ida"
    if (install_dir / exe_name).is_file():
        defaults["ida_path"] = str(install_dir / exe_name)
    bin_dir = install_dir / "ida-python" / "bin"
    if bin_dir.is_dir():
        versioned = [
            p for p in bin_dir.glob("python3.*")
            if p.is_file() and "-" not in p.name
        ]
        versioned.sort(reverse=True)
        python = versioned[0] if versioned else (bin_dir / "python3" if (bin_dir / "python3").is_file() else None)
        if python is None and os.name == "nt" and (install_dir / "ida-python" / "python.exe").is_file():
            python = install_dir / "ida-python" / "python.exe"
        if python is not None:
            defaults["ida_python"] = str(python)
    return defaults


def _personalize_manifest_bytes(data: bytes) -> bytes:
    """Fill settings defaults with locally detected paths (no-op on CI)."""
    defaults = _local_machine_defaults()
    if not defaults:
        return data
    manifest = json.loads(data.decode("utf-8"))
    changed = False
    for item in manifest.get("plugin", {}).get("settings", []):
        value = defaults.get(item.get("key", ""))
        if value and item.get("default", "") in ("", "auto"):
            item["default"] = value
            changed = True
    if not changed:
        return data
    return (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _write_member(zf: zipfile.ZipFile, source: Path, archive_name: PurePosixPath) -> None:
    info = zipfile.ZipInfo(archive_name.as_posix(), FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    data = source.read_bytes()
    if archive_name.as_posix() == "ida-plugin.json":
        data = _personalize_manifest_bytes(data)
    zf.writestr(info, data, compresslevel=9)


def build_archive(output: Path) -> tuple[dict, int, str]:
    plugin = _validate_manifest()
    files = _iter_package_files()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.unlink(missing_ok=True)

    try:
        with zipfile.ZipFile(temporary, "w") as zf:
            for source, archive_name in files:
                _write_member(zf, source, archive_name)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return plugin, len(files), digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "main.zip",
        help="archive output path (default: dist/main.zip)",
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output

    try:
        plugin, file_count, digest = build_archive(output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Built {output}")
    print(f"Plugin: {plugin['name']}=={plugin['version']}")
    print(f"Files: {file_count}")
    print(f"SHA256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
