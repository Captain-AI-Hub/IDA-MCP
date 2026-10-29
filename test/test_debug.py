"""Tests for debugger-related tools.

The dbg_* tools run inside a headless idalib worker on a locally built ELF
sample with an explicit call chain (main → level1 → level2 → level3, compiled
with frame pointers). dbg_start loads the platform's local debugger itself.

Debugging requires an ELF target on Linux (the PE sample used by the other
test files cannot be debugged by the local linux debugger); the fixture
compiles one with cc and skips when no compiler is available.

Run with:
    pytest -m debug         # Run only debug module tests
    pytest test_debug.py    # Run all tests in this file
"""
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
import time

from ida_mcp import api_debug, bridge_client, lifecycle

pytestmark = pytest.mark.debug

_SAMPLE_SOURCE = textwrap.dedent(
    """
    static volatile int sink;
    static void level3(void) { sink += 3; }
    static void level2(void) { level3(); sink += 2; }
    static void level1(void) { level2(); sink += 1; }
    int main(void) { level1(); return 0; }
    """
)


@pytest.fixture(scope="session")
def debug_sample(tmp_path_factory) -> Path:
    """Build a tiny frame-pointer ELF with a known call chain."""
    workdir = tmp_path_factory.mktemp("ida-mcp-debug")
    source = workdir / "chain.c"
    binary = workdir / "chain"
    source.write_text(_SAMPLE_SOURCE, encoding="utf-8")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler available to build the ELF debug sample")
    completed = subprocess.run(
        [cc, "-O0", "-g", "-fno-omit-frame-pointer", "-o", str(binary), str(source)],
        capture_output=True,
        timeout=60,
    )
    if completed.returncode != 0 or not binary.is_file():
        pytest.skip(f"failed to compile debug sample: {completed.stderr!r}")
    return binary


@pytest.fixture(scope="session")
def debug_ida_instance(debug_sample, request) -> Dict[str, Any]:
    """Open the ELF sample in its own headless worker."""
    result = lifecycle.open_database(
        str(debug_sample),
        wait_for_analysis=True,
        timeout=request.config.getoption("--ida-open-timeout"),
    )
    if "error" in result:
        pytest.skip(f"headless open of debug sample failed: {result['error']}")
    entry = result["instance"]
    yield entry
    try:
        lifecycle.close_database(entry, terminate=True, save=False)
    except Exception:  # noqa: BLE001 - teardown is best effort
        pass


@pytest.fixture
def debug_tool_caller(debug_ida_instance):
    """Call backend tools directly on the debug-sample worker."""

    def caller(tool_name: str, params: Optional[dict] = None, **kwargs) -> Any:
        call_params = {**(params or {}), **kwargs}
        timeout = call_params.pop("timeout", None)
        call_params.pop("instance_id", None)
        try:
            return bridge_client.call_tool(
                debug_ida_instance, tool_name, call_params, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001 - tests expect error dicts
            described = bridge_client.describe_error(exc)
            if "error" in described:
                return described
            raise

    return caller


class DebugState:
    """Debugger state tracking."""
    breakpoint_address: Optional[int] = None
    breakpoint_name: Optional[str] = None
    debugger_started: bool = False


class TestDebug0_Breakpoints:
    """Phase 0: Breakpoint management."""

    def test_00_list_breakpoints(self, debug_tool_caller):
        """List breakpoints."""
        result = debug_tool_caller("dbg_list_bps")
        assert isinstance(result, dict)
        print(f"Breakpoints: {result}")

    def test_01_set_breakpoint(self, debug_tool_caller):
        """Set breakpoint on level3 (symbolic address resolution)."""
        DebugState.breakpoint_name = "level3"
        result = debug_tool_caller("dbg_add_bp", {"addr": "level3"})
        assert isinstance(result, list), result
        item = result[0] if result else {}
        assert not item.get("error"), item
        DebugState.breakpoint_address = item.get("ea")

    def test_02_list_breakpoints_after_set(self, debug_tool_caller):
        """List breakpoints after setting."""
        result = debug_tool_caller("dbg_list_bps")
        assert isinstance(result, dict)
        assert DebugState.breakpoint_address is None or result.get("breakpoints") or result.get("items") or result
        print(f"Breakpoints: {result}")

    def test_03_enable_breakpoint(self, debug_tool_caller):
        """Enable breakpoint."""
        if not DebugState.breakpoint_address:
            pytest.skip("No breakpoint")

        result = debug_tool_caller("dbg_enable_bp", {
            "items": [{"address": DebugState.breakpoint_address, "enable": True}]
        })
        assert isinstance(result, list)
        print(f"Enable: {result}")


class TestDebug1_Start:
    """Phase 1: Start debugger."""

    def test_10_start_debugger(self, debug_tool_caller):
        """Start debugger; suspends at the level3 breakpoint."""
        result = debug_tool_caller("dbg_start")
        assert isinstance(result, dict), result
        assert result.get("started") is True, result
        assert result.get("suspended") is True, result
        DebugState.debugger_started = True
        print(f"Start: {result}")

    def test_11_verify_state(self, debug_tool_caller):
        """Verify debugger state."""
        result = debug_tool_caller("dbg_regs")
        assert isinstance(result, dict)
        print(f"Registers: {result}")


class TestDebug2_Inspection:
    """Phase 2: State inspection."""

    def test_20_get_registers(self, debug_tool_caller):
        """Get registers."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = debug_tool_caller("dbg_regs")
        assert isinstance(result, dict)
        print(f"Registers: {result}")

    def test_21_get_call_stack(self, debug_tool_caller):
        """Frame-pointer chain must rebuild the known call chain."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = debug_tool_caller("dbg_callstack")
        assert isinstance(result, (dict, list)), result
        frames = result.get("frames") if isinstance(result, dict) else result
        assert frames, "call stack should contain at least the current frame"
        funcs = [str(f.get("func")) for f in frames]
        # innermost first: level3 <- level2 <- level1 <- main
        assert "level3" in funcs[0], funcs
        assert any(f.startswith("level2") for f in funcs), funcs
        assert any(f.startswith("level1") for f in funcs), funcs
        assert any(f.startswith("main") for f in funcs), funcs
        print(f"Call stack: {frames}")

    def test_22_read_mem(self, debug_tool_caller):
        """Read memory at the current instruction pointer."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")
        regs = debug_tool_caller("dbg_regs")
        rip = None
        if isinstance(regs, dict):
            for item in regs.get("registers") or []:
                if str(item.get("name", "")).upper() in ("RIP", "EIP", "PC"):
                    rip = item.get("value")
                    break
        if rip is None:
            pytest.skip("no instruction pointer in regs")
        result = debug_tool_caller("dbg_read_mem", {"regions": [{"address": rip, "size": 16}]})
        assert isinstance(result, list)
        assert not result[0].get("error"), result[0]
        assert result[0]["size"] == 16


class TestDebug3_Stepping:
    """Phase 3: Stepping."""

    def test_30_step_into(self, debug_tool_caller):
        """Step into."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = debug_tool_caller("dbg_step_into")
        assert isinstance(result, dict)
        print(f"Step into: {result}")
        time.sleep(0.1)

    def test_31_step_over(self, debug_tool_caller):
        """Step over."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = debug_tool_caller("dbg_step_over")
        assert isinstance(result, dict)
        print(f"Step over: {result}")
        time.sleep(0.1)


class TestDebug9_Cleanup:
    """Phase 9: Cleanup."""

    def test_90_delete_breakpoint(self, debug_tool_caller):
        """Delete breakpoint."""
        if not DebugState.breakpoint_address:
            pytest.skip("No breakpoint")

        result = debug_tool_caller("dbg_delete_bp", {
            "addr": DebugState.breakpoint_address
        })
        assert isinstance(result, list)
        print(f"Delete: {result}")

    def test_99_exit_debugger(self, debug_tool_caller):
        """Exit debugger."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = debug_tool_caller("dbg_exit")
        assert isinstance(result, dict)
        print(f"Exit: {result}")

        DebugState.debugger_started = False
        DebugState.breakpoint_address = None


class TestDebugHelpers:
    def test_walk_fp_chain_reconstructs_frames(self, monkeypatch):
        """On IDA 9 the stack is rebuilt from RBP: [fp]=saved fp, [fp+8]=ret."""
        ptr = 8
        memory = {
            # Frame pointers ascend toward callers (stack grows down).
            # [sp]: return into the direct caller, used when stopped at a
            # function's entry instruction (prologue not executed yet).
            0x7000: (0x400f00).to_bytes(ptr, "little"),
            0x7ff0: (0x8f00).to_bytes(ptr, "little"),   # saved fp
            0x7ff8: (0x401010).to_bytes(ptr, "little"),  # return -> frame 1
            0x8f00: (0x9f00).to_bytes(ptr, "little"),
            0x8f08: (0x402020).to_bytes(ptr, "little"),  # return -> frame 2
            # [0x9f00] unreadable -> chain ends after frame 2
        }

        class FakeDbg:
            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def get_reg_val(name):
                return {"RIP": 0x400000, "RBP": 0x7ff0, "RSP": 0x7000}[name]

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())
        monkeypatch.setattr(
            api_debug, "_arch_frame_regs", lambda: ("RIP", "RBP", "RSP", ptr)
        )
        monkeypatch.setattr(
            api_debug, "_read_dbg_memory", lambda ea, size: memory.get(ea)
        )
        monkeypatch.setattr(api_debug, "idaapi", type("F", (), {"BADADDR": -1, "get_func_name": staticmethod(lambda ea: f"sub_{ea:x}")})())
        monkeypatch.setattr(api_debug.ida_shims, "func_start", lambda ea: ea)

        frames = api_debug._walk_fp_chain()
        assert [f["ea"].lower() for f in frames] == [
            "0x400000",  # pc at the entry instruction
            "0x400f00",  # [sp]: direct caller (prologue not executed)
            "0x401010",  # fp chain frame 1
            "0x402020",  # fp chain frame 2
        ]
        assert frames[0]["func"] == "sub_400000"

    def test_walk_fp_chain_rejects_non_monotonic_chain(self, monkeypatch):
        """A garbage (non-ascending) fp chain must stop instead of looping."""
        ptr = 8
        memory = {
            0x7ff0: (0x7ff0).to_bytes(ptr, "little"),  # fp points to itself
            0x7ff8: (0x401010).to_bytes(ptr, "little"),
        }

        class FakeDbg:
            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def get_reg_val(name):
                return {"RIP": 0x400000, "RBP": 0x7ff0, "RSP": 0x7000}[name]

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())
        monkeypatch.setattr(
            api_debug, "_arch_frame_regs", lambda: ("RIP", "RBP", "RSP", ptr)
        )
        monkeypatch.setattr(
            api_debug, "_read_dbg_memory", lambda ea, size: memory.get(ea)
        )
        monkeypatch.setattr(api_debug, "idaapi", type("F", (), {"BADADDR": -1})())

        frames = api_debug._walk_fp_chain()
        assert [f["ea"] for f in frames] == ["0x400000", "0x401010"]

    def test_dbg_start_loads_debugger_and_entry_bpt(self, monkeypatch):
        calls = {"load": [], "bpt": [], "start": 0}

        class FakeDbg:
            @staticmethod
            def is_debugger_on():
                return False

            @staticmethod
            def load_debugger(name, remote):
                calls["load"].append((name, remote))
                return True

            @staticmethod
            def get_bpt_qty():
                return 0

            @staticmethod
            def add_bpt(ea, *args):
                calls["bpt"].append(ea)
                return True

            @staticmethod
            def start_process(path, args, sdir):
                calls["start"] += 1
                return 1

            @staticmethod
            def get_process_state():
                return None

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())
        monkeypatch.setattr(api_debug, "idaapi", type("F", (), {
            "BADADDR": -1, "get_input_file_path": staticmethod(lambda: "/tmp/t"),
        })())
        monkeypatch.setattr(api_debug, "_entry_point_ea", lambda: 0x4017a0)
        monkeypatch.setattr(api_debug, "_wait_for_debugger_event", lambda *_a, **_k: True)
        monkeypatch.setattr(api_debug, "_default_debugger_name", lambda: "linux")

        result = api_debug.dbg_start.__wrapped__()

        assert result["started"] is True
        assert result["debugger"] == "linux"
        assert result["entry_breakpoint"] is True
        assert calls["load"] == [("linux", False)]
        assert calls["bpt"] == [0x4017a0]
        assert calls["start"] == 1

    def test_dbg_run_to_cleans_temporary_breakpoint(self, monkeypatch):
        calls = {"added": 0, "deleted": 0, "continued": 0}

        class FakeDbg:
            BPT_DEFAULT = 0

            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def add_bpt(_addr, *_args):
                calls["added"] += 1
                return True

            @staticmethod
            def continue_process():
                calls["continued"] += 1
                return True

            @staticmethod
            def del_bpt(_addr):
                calls["deleted"] += 1
                return True

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())
        monkeypatch.setattr(api_debug, "idaapi", type("FakeIdaApi", (), {"BADADDR": -1})())
        monkeypatch.setattr(api_debug, "_wait_for_debugger_event", lambda _timeout=1000: True)
        monkeypatch.setattr(api_debug, "_breakpoint_exists", lambda _addr: False)

        result = api_debug.dbg_run_to.__wrapped__("0x401000")

        assert result["used_temp_bpt"] is True
        assert result["cleaned_temp_bpt"] is True
        assert calls == {"added": 1, "deleted": 1, "continued": 1}

    def test_dbg_read_mem_reports_integer_size(self, monkeypatch):
        class FakeDbg:
            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def read_dbg_memory(_addr, _size):
                return b"\x90\x91"

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())

        result = api_debug.dbg_read_mem.__wrapped__([{"address": "0x401000", "size": 2}])

        assert result[0]["size"] == 2
        assert isinstance(result[0]["size"], int)

    def test_dbg_write_mem_reports_integer_size(self, monkeypatch):
        class FakeDbg:
            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def write_dbg_memory(_addr, data):
                return len(data)

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())

        result = api_debug.dbg_write_mem.__wrapped__([{"address": "0x401000", "bytes": [0x90, 0x91]}])

        assert result[0]["size"] == 2
        assert isinstance(result[0]["size"], int)
