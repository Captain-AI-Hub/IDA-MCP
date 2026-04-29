from __future__ import annotations

import importlib.util
import platform
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "build_helpers" / "build_nuitka.py"
_SPEC = importlib.util.spec_from_file_location(
    "ide_packaging_build_nuitka", _MODULE_PATH
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
build_command = _MODULE.build_command

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"
_IS_MACOS = platform.system() == "Darwin"


def test_build_command_defaults_to_standalone() -> None:
    command = build_command()

    assert "--standalone" in command
    assert "--enable-plugin=pyside6" in command


def test_build_command_platform_compiler_flags() -> None:
    command = build_command()

    if _IS_WINDOWS:
        assert "--clang" in command
        assert "--windows-console-mode=disable" in command
    elif _IS_MACOS:
        assert "--msvc=latest" not in command
        assert "--macos-disable-console" in command


def test_build_command_supports_onefile() -> None:
    command = build_command(onefile=True)

    assert "--onefile" in command
    assert "--standalone" not in command


def test_build_command_includes_resources_directory() -> None:
    command = build_command()

    assert any("resources" in item for item in command)
