"""Tests for stack-related tools.

Test logic:
1. Use fixtures to get valid function addresses
2. Test stack frame info retrieval
3. Test stack variable declaration

API parameter mappings:
- stack_frame: addr (comma-separated)
- declare_stack: items (List of {function_address, offset, name, type?, size?})
- delete_stack: items (List of {function_address, name})

Notes:
- 64-bit code and simple functions may not have explicit stack-frame definitions
- Stack frame retrieval may come from: ida9_frame, classic_frame, hexrays_lvars

Run with:
    pytest -m stack         # Run only stack module tests
    pytest test_stack.py    # Run all tests in this file
"""
import pytest

from ida_mcp import api_stack

pytestmark = pytest.mark.stack


class TestStackFrame:
    """Stack frame info tests."""

    def test_stack_frame(self, tool_caller, first_function_address):
        """Test getting stack frame info."""
        # API param name is addr
        result = tool_caller("stack_frame", {
            "addr": hex(first_function_address)
        })

        # API 返回 List[dict]
        assert isinstance(result, list)
        if result and "error" not in result[0]:
            # 应该返回栈帧信息
            assert "variables" in result[0]

    def test_stack_frame_by_name(self, tool_caller, first_function_name):
        """Test getting stack frame info by name."""
        result = tool_caller("stack_frame", {
            "addr": first_function_name
        })

        assert isinstance(result, list)

    def test_stack_frame_invalid_address(self, tool_caller):
        """Test invalid address."""
        result = tool_caller("stack_frame", {
            "addr": "0xDEADBEEF"
        })
        assert isinstance(result, list)
        if result:
            assert "error" in result[0]

    def test_stack_frame_batch(self, tool_caller, functions_cache):
        """Test batch stack frame retrieval (comma-separated)."""
        if len(functions_cache) < 2:
            pytest.skip("Not enough functions")

        addr_list = ",".join(f["start_ea"] for f in functions_cache[:2])
        result = tool_caller("stack_frame", {"addr": addr_list})

        assert isinstance(result, list)
        assert len(result) == 2

    def test_stack_frame_main(self, tool_caller, main_function_address):
        """Test main function stack frame."""
        result = tool_caller("stack_frame", {
            "addr": hex(main_function_address)
        })

        # main usually has a stack frame
        assert isinstance(result, list)

    def test_stack_frame_complex_function(self, tool_caller, complex_baseline):
        """Test stack frame for the complex fixture stack-heavy function."""
        target = complex_baseline["functions"]["ida_mcp_stack_heavy_transform"]
        result = tool_caller("stack_frame", {
            "addr": target["start_ea"]
        })

        assert isinstance(result, list)
        assert len(result) == 1

        # Verify result structure
        frame_info = result[0]
        if "error" in frame_info:
            pytest.skip(f"Stack frame unavailable for selected function: {frame_info['error']}")
        assert "name" in frame_info
        assert "start_ea" in frame_info
        assert "variables" in frame_info
        assert frame_info.get("method") == "ida_frame"
        assert frame_info.get("frame_variables") == frame_info["variables"]
        assert isinstance(frame_info.get("local_variables", []), list)
        variables = {var["name"]: var for var in frame_info["variables"]}
        expected = complex_baseline["stack_frame"]["ida_mcp_stack_heavy_transform"]
        for name in expected["required_variables"]:
            assert name in variables
        for name, offset in expected["variable_offsets"].items():
            assert variables[name]["offset"] == offset

        # If variables exist, verify variable structure
        if frame_info.get("variables"):
            for var in frame_info["variables"]:
                assert "name" in var
                # Variable may be on stack (has offset) or in register (has location)
                assert "offset" in var or var.get("location") == "register"


class TestDeclareStack:
    """Stack variable declaration tests."""

    def test_declare_stack(self, tool_caller, first_function_address):
        """Test declaring a stack variable."""
        # API params: items (List of {function_address, offset, name, type?, size?})
        result = tool_caller("declare_stack", {
            "items": [{
                "function_address": hex(first_function_address),
                "offset": -8,
                "name": "test_local",
                "type": "int",
                "size": 4
            }]
        })

        # 可能成功或失败
        assert isinstance(result, list)

    def test_declare_stack_batch(self, tool_caller, first_function_address):
        """Test batch stack variable declaration."""
        result = tool_caller("declare_stack", {
            "items": [
                {"function_address": hex(first_function_address), "offset": -16, "name": "test_local2", "size": 4},
                {"function_address": hex(first_function_address), "offset": -24, "name": "test_local3", "size": 8},
            ]
        })

        assert isinstance(result, list)
        assert len(result) == 2


class TestDeclareStackHelpers:
    def test_declare_stack_rejects_invalid_name(self):
        result = api_stack.declare_stack.__wrapped__([{
            "function_address": "0x401000",
            "offset": -8,
            "name": "123bad",
            "size": 4,
        }])

        assert result[0]["error"] == "name is not a valid C identifier"

    def test_declare_stack_uses_explicit_type(self, monkeypatch):
        calls: dict[str, object] = {}

        monkeypatch.setattr(api_stack, "wait_for_auto_analysis", lambda: None)
        monkeypatch.setattr(
            api_stack.ida_shims, "func_bounds", lambda _ea: (0x401000, 0x401100)
        )
        monkeypatch.setattr(api_stack, "_frame_member_by_name", lambda _func, _name: None)

        def fake_parse(type_text):
            calls["declared_type"] = type_text
            return object(), None

        monkeypatch.setattr(api_stack, "_parse_stack_tinfo", fake_parse)
        monkeypatch.setattr(api_stack, "_define_stack_member", lambda _f, _off, _name, _tif: (True, None))

        result = api_stack.declare_stack.__wrapped__([{
            "function_address": "0x401000",
            "offset": -8,
            "name": "typed_local",
            "type": "int",
            "size": 1,
        }])

        assert result[0]["changed"] is True
        assert result[0]["declared_type"] == "int"
        assert calls["declared_type"] == "int"

    def test_declare_stack_uses_size_based_fallback_type(self, monkeypatch):
        calls: dict[str, object] = {}

        monkeypatch.setattr(api_stack, "wait_for_auto_analysis", lambda: None)
        monkeypatch.setattr(
            api_stack.ida_shims, "func_bounds", lambda _ea: (0x401000, 0x401100)
        )
        monkeypatch.setattr(api_stack, "_frame_member_by_name", lambda _func, _name: None)

        def fake_parse(type_text):
            calls["declared_type"] = type_text
            return object(), None

        monkeypatch.setattr(api_stack, "_parse_stack_tinfo", fake_parse)
        monkeypatch.setattr(api_stack, "_define_stack_member", lambda _f, _off, _name, _tif: (True, None))

        result = api_stack.declare_stack.__wrapped__([{
            "function_address": "0x401000",
            "offset": -16,
            "name": "sized_local",
            "size": 16,
        }])

        assert result[0]["changed"] is True
        assert result[0]["declared_type"] == "char[16]"
        assert calls["declared_type"] == "char[16]"


class TestDeleteStack:
    """Stack variable deletion tests."""

    def test_delete_stack(self, tool_caller, first_function_address):
        """Test deleting a stack variable."""
        addr = hex(first_function_address)
        # First declare a stack variable
        tool_caller("declare_stack", {
            "items": [{"function_address": addr, "offset": -128, "name": "to_be_deleted", "size": 4}]
        })

        # Then delete - API params: items (List of {function_address, name})
        result = tool_caller("delete_stack", {
            "items": [{"function_address": addr, "name": "to_be_deleted"}]
        })

        # 可能成功或失败
        assert isinstance(result, list)
