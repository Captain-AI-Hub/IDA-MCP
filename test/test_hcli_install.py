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


def test_parse_idapyswitch_output_handles_linux_libpython_path(tmp_path):
    prefix = tmp_path / "python-3.12"
    bindir = prefix / "bin"
    libdir = prefix / "lib"
    bindir.mkdir(parents=True)
    libdir.mkdir()
    python = bindir / "python3"
    python.write_bytes(b"")
    output = f"#1: 3.12.7 ('3.12') ({libdir / 'libpython3.12.so.1.0'})\n"

    installations = hcli_install.parse_idapyswitch_output(output, windows=False)

    assert installations == [
        {
            "index": "1",
            "version": "3.12.7",
            "dir": str(prefix),
            "exe": str(python.resolve()),
        }
    ]


def test_detect_ida_python_prefers_idat_runtime_probe(tmp_path, monkeypatch):
    import ida_python_detection

    ida = tmp_path / "ida"
    idat = tmp_path / "idat"
    ida.write_bytes(b"")
    idat.write_bytes(b"")
    prefix = tmp_path / "python-3.12"
    python = prefix / "python.exe" if hcli_install.os.name == "nt" else prefix / "bin" / "python3.12"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")

    monkeypatch.setattr(ida_python_detection, "_idat_candidates", lambda _ida: [idat])
    monkeypatch.setattr(
        ida_python_detection,
        "_probe_idat",
        lambda _idat, ida_user_dir=None: {
            "prefix": str(prefix),
            "base_prefix": str(prefix),
            "executable": str(idat),
            "version_major": 3,
            "version_minor": 12,
        },
    )

    assert hcli_install.detect_ida_python(ida) == python.resolve()


def test_build_hcli_environment_forces_detected_idapython():
    python = Path("/opt/python-3.12/bin/python3")

    environment = hcli_install.build_hcli_environment(python, {"PATH": "/usr/bin"})

    assert environment["PATH"] == "/usr/bin"
    assert environment["HCLI_CURRENT_IDA_PYTHON_EXE"] == str(python)


def test_personalize_archive_sets_per_install_gateway_token(tmp_path):
    source = tmp_path / "source.zip"
    destination = tmp_path / "personalized.zip"
    manifest = {
        "plugin": {
            "settings": [
                {"key": "gateway_token", "default": "__AUTO_GENERATE_GATEWAY_TOKEN__"},
                {"key": "ida_path", "name": "IDA executable path", "default": ""},
                {"key": "ida_python", "name": "IDAPython interpreter path", "default": "auto"},
            ]
        }
    }
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("ida-plugin.json", json.dumps(manifest))

    hcli_install.personalize_archive(
        source,
        destination,
        ida_executable=Path("/opt/ida/ida"),
        ida_python=Path("/opt/python/bin/python3"),
        gateway_token="per-install-secret",
    )

    with zipfile.ZipFile(destination) as archive:
        settings = json.loads(archive.read("ida-plugin.json"))["plugin"]["settings"]
    values = {item["key"]: item for item in settings}
    assert values["gateway_token"]["default"] == "per-install-secret"


def test_mcp_client_config_contains_generated_token():
    value = hcli_install.mcp_client_config("per-install-secret")

    server = value["mcpServers"]["ida-mcp"]
    assert server["url"] == "http://127.0.0.1:11338/mcp"
    assert server["headers"]["Authorization"] == "Bearer per-install-secret"


def test_reads_selected_ida_from_hcli_config(tmp_path, monkeypatch):
    idausr = tmp_path / "idausr"
    ida_dir = tmp_path / "ida-install"
    idausr.mkdir()
    ida_dir.mkdir()
    executable_name = "ida.exe" if hcli_install.os.name == "nt" else "ida"
    ida_executable = ida_dir / executable_name
    ida_executable.write_bytes(b"")
    (idausr / "ida-config.json").write_text(
        json.dumps({"Paths": {"ida-install-dir": str(ida_dir)}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("HCLI_IDAUSR", str(idausr))
    monkeypatch.delenv("IDAUSR", raising=False)

    assert hcli_install._ida_executable_from_hcli_config() == ida_executable.resolve()
