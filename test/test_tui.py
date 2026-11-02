"""Unit tests for the host-side TUI data layer (no textual, no live IDA).

The BridgeUI/parse helpers are plain functions over bridge_client results;
these tests exercise them against recorded tool outputs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ida_mcp.tui import dump as dump_mod


class FakeClient(dump_mod.DumpClient):
    """DumpClient with a canned call() table."""

    def __init__(self, table: Dict[str, Any]):
        # no super().__init__: we never touch the bridge
        self.table = table
        self.calls: List[str] = []

    def call(self, tool: str, params: Optional[dict] = None, timeout: float = 120.0) -> Any:
        self.calls.append(tool)
        result = self.table.get(tool)
        if callable(result):
            return result(params or {})
        return result


def test_function_entries_parses_list_functions_lines():
    client = FakeClient(
        {
            "list_functions": {
                "total": 2,
                "items": (
                    "0x1000-0x101B  .init_proc\n"
                    "0x1141-0x115A  main\n"
                    "garbage line\n"
                ),
            }
        }
    )
    entries = dump_mod._function_entries(client, None)
    assert entries == [
        {"start_ea": 0x1000, "end_ea": 0x101B, "name": ".init_proc"},
        {"start_ea": 0x1141, "end_ea": 0x115A, "name": "main"},
    ]


def test_function_entries_applies_name_regex():
    client = FakeClient(
        {
            "list_functions": {
                "items": "0x1000-0x101B  parse_config\n0x2000-0x2010  main\n"
            }
        }
    )
    entries = dump_mod._function_entries(client, r"^parse_")
    assert len(entries) == 1 and entries[0]["name"] == "parse_config"


def test_render_function_asm_and_pseudo():
    client = FakeClient(
        {
            "disasm": [
                {
                    "name": "main",
                    "start_ea": "0x1141",
                    "end_ea": "0x115A",
                    "disasm": "0x1141  endbr64\n0x1145  push rbp",
                }
            ],
            "decompile": "// main\nint main() { return 0; }",
        }
    )
    text = dump_mod.render_function(
        client,
        {"start_ea": 0x1141, "end_ea": 0x115A, "name": "main"},
        asm=True,
        pseudo=True,
    )
    assert text.startswith("// main  0x1141-0x115A")
    assert "endbr64" in text
    assert "int main() { return 0; }" in text


def test_render_function_flags_failures():
    client = FakeClient(
        {
            "disasm": [{"name": "f", "error": "no func"}],
            "decompile": "",
        }
    )
    text = dump_mod.render_function(
        client, {"start_ea": 0, "end_ea": 0, "name": "f"}
    )
    assert "disassembly failed" in text
    assert "decompilation failed" in text


def test_run_dump_writes_output_and_counts(monkeypatch, tmp_path, capsys):
    lifecycle_calls = {}

    def fake_open(path, **kwargs):
        lifecycle_calls["path"] = path
        return {"instance": {"instance_id": "i-x", "port": 1}, "status": "ok"}

    monkeypatch.setattr(dump_mod.lifecycle, "open_database", fake_open)
    monkeypatch.setattr(
        dump_mod,
        "_function_entries",
        lambda client, flt: [
            {"start_ea": 0x1000, "end_ea": 0x101B, "name": "main"}
        ],
    )
    monkeypatch.setattr(
        dump_mod,
        "render_function",
        lambda client, entry, asm=True, pseudo=True: "// main ok",
    )
    out = tmp_path / "dump.txt"
    code = dump_mod.run_dump(
        "/bin/ls", name_filter=None, asm=True, pseudo=True, output=str(out)
    )
    assert code == 0
    assert out.read_text() == "// main ok\n"
    assert lifecycle_calls["path"] == "/bin/ls"
    assert "dumped 1 functions" in capsys.readouterr().err
