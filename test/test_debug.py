"""Tests for debugger-related tools.

Prerequisites:
1. Debugger type must be manually configured in IDA
2. If a PDB dialog pops up, close it manually
3. A GUI IDA instance (idalib workers have no debugger backend)

Test order:
1. Phase 0: Breakpoint management (no running debugger required)
2. Phase 1: Start debugger
3. Phase 2: State inspection
4. Phase 3: Stepping
5. Phase 9: Cleanup

Run with:
    pytest -m debug         # Run only debug module tests
    pytest test_debug.py    # Run all tests in this file
"""
import pytest
import time
from typing import Optional

from ida_mcp import api_debug

pytestmark = pytest.mark.debug


@pytest.fixture(autouse=True)
def _require_gui_instance(ida_instance):
    if ida_instance.get("headless"):
        pytest.skip("dbg_* tools need a GUI IDA instance with a configured debugger")


class DebugState:
    """Debugger state tracking."""
    breakpoint_address: Optional[int] = None
    debugger_started: bool = False


class TestDebug0_Breakpoints:
    """Phase 0: Breakpoint management."""

    def test_00_list_breakpoints(self, tool_caller):
        """List breakpoints."""
        result = tool_caller("dbg_list_bps")
        assert isinstance(result, dict)
        print(f"Breakpoints: {result}")

    def test_01_set_breakpoint(self, tool_caller, main_function, first_function_address):
        """Set breakpoint."""
        if main_function:
            addr = int(main_function["start_ea"], 16) if isinstance(main_function["start_ea"], str) else main_function["start_ea"]
        else:
            addr = first_function_address

        DebugState.breakpoint_address = addr

        result = tool_caller("dbg_add_bp", {"addr": addr})
        assert isinstance(result, list)
        print(f"Set breakpoint at {hex(addr)}: {result}")

    def test_02_list_breakpoints_after_set(self, tool_caller):
        """List breakpoints after setting."""
        result = tool_caller("dbg_list_bps")
        assert isinstance(result, dict)
        print(f"Breakpoints: {result}")

    def test_03_enable_breakpoint(self, tool_caller):
        """Enable breakpoint."""
        if not DebugState.breakpoint_address:
            pytest.skip("No breakpoint")

        result = tool_caller("dbg_enable_bp", {
            "items": [{"address": DebugState.breakpoint_address, "enable": True}]
        })
        assert isinstance(result, list)
        print(f"Enable: {result}")


class TestDebug1_Start:
    """Phase 1: Start debugger."""

    def test_10_start_debugger(self, tool_caller):
        """Start debugger."""
        result = tool_caller("dbg_start")
        assert isinstance(result, dict)
        print(f"Start: {result}")

        if result.get("ok") or result.get("started"):
            DebugState.debugger_started = True

    def test_11_verify_state(self, tool_caller):
        """Verify debugger state."""
        result = tool_caller("dbg_regs")
        assert isinstance(result, dict)
        print(f"Registers: {result}")


class TestDebug2_Inspection:
    """Phase 2: State inspection."""

    def test_20_get_registers(self, tool_caller):
        """Get registers."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = tool_caller("dbg_regs")
        assert isinstance(result, dict)
        print(f"Registers: {result}")

    def test_21_get_call_stack(self, tool_caller):
        """Get call stack."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = tool_caller("dbg_callstack")
        assert isinstance(result, (dict, list))
        print(f"Call stack: {result}")


class TestDebug3_Stepping:
    """Phase 3: Stepping."""

    def test_30_step_into(self, tool_caller):
        """Step into."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = tool_caller("dbg_step_into")
        assert isinstance(result, dict)
        print(f"Step into: {result}")
        time.sleep(0.1)

    def test_31_step_over(self, tool_caller):
        """Step over."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = tool_caller("dbg_step_over")
        assert isinstance(result, dict)
        print(f"Step over: {result}")
        time.sleep(0.1)


class TestDebug9_Cleanup:
    """Phase 9: Cleanup."""

    def test_90_delete_breakpoint(self, tool_caller):
        """Delete breakpoint."""
        if not DebugState.breakpoint_address:
            pytest.skip("No breakpoint")

        result = tool_caller("dbg_delete_bp", {
            "addr": DebugState.breakpoint_address
        })
        assert isinstance(result, list)
        print(f"Delete: {result}")

    def test_99_exit_debugger(self, tool_caller):
        """Exit debugger."""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")

        result = tool_caller("dbg_exit")
        assert isinstance(result, dict)
        print(f"Exit: {result}")

        DebugState.debugger_started = False
        DebugState.breakpoint_address = None


class TestDebugHelpers:
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
