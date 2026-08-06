"""Tests for the machine-aware HCLI installer wrapper."""

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "hcli_install.py"
SPEC = importlib.util.spec_from_file_location("hcli_install", MODULE_PATH)
assert SPEC and SPEC.loader
hcli_install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hcli_install)


def test_parse_idapyswitch_output_prefers_previous_interpreter(tmp_path):
    py311 = tmp_path / "Python311"
    py312 = tmp_path / "Python312"
    py311.mkdir()
    py312.mkdir()
    (py311 / "python.exe").write_bytes(b"")
    (py312 / "python.exe").write_bytes(b"")
    output = (
        f"#1: 3.11.9 ('3.11') ({py311}\\python311.dll)\n"
        f"#2: 3.12.7 ('3.12') ({py312}\\python312.dll)\n"
        f"IDA previously used: 3.12.7 ({py312}\\python312.dll)\n"
    )

    installations = hcli_install.parse_idapyswitch_output(output, windows=True)

    assert [item["version"] for item in installations] == ["3.12.7", "3.11.9"]
    assert installations[0]["exe"] == str((py312 / "python.exe").resolve())


def test_personalize_archive_puts_detected_paths_in_prompt(tmp_path):
    source = tmp_path / "source.zip"
    destination = tmp_path / "personalized.zip"
    manifest = {
        "plugin": {
            "settings": [
                {"key": "ida_path", "name": "IDA executable path", "default": ""},
                {"key": "ida_python", "name": "IDAPython interpreter path", "default": "auto"},
            ]
        }
    }
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("ida-plugin.json", json.dumps(manifest))
        archive.writestr("ida_mcp.py", "")

    ida_executable = Path(r"D:\IDAPro9.4\ida.exe")
    ida_python = Path(r"C:\Users\tester\AppData\Local\Python\python.exe")
    hcli_install.personalize_archive(
        source,
        destination,
        ida_executable=ida_executable,
        ida_python=ida_python,
    )

    with zipfile.ZipFile(destination) as archive:
        personalized = json.loads(archive.read("ida-plugin.json"))["plugin"]["settings"]
    settings = {item["key"]: item for item in personalized}
    assert str(ida_executable) in settings["ida_path"]["name"]
    assert settings["ida_path"]["default"] == str(ida_executable)
    assert str(ida_python) in settings["ida_python"]["name"]
    assert settings["ida_python"]["default"] == str(ida_python)
