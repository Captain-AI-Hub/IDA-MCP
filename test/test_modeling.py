"""Tests for api_modeling.py tools."""
from __future__ import annotations

import pytest

from ida_mcp import api_modeling

pytestmark = pytest.mark.modeling


def _restore_string(tool_caller, address: str, length: int | None = None) -> None:
    params = {"address": address, "string_type": "c"}
    if length is not None and length > 0:
        params["length"] = length
    tool_caller("make_string", params)


def _make_string_params(address: str, length: int | None = None) -> dict:
    params = {"address": address, "string_type": "c"}
    if length is not None and length > 0:
        params["length"] = length
    return params


class TestModelingHelpers:
    """Unit-style tests for modeling helpers."""

    def test_pointer_kind_uses_database_bitness(self, monkeypatch):
        class FakeIda:
            @staticmethod
            def inf_is_64bit():
                return True

        monkeypatch.setattr(api_modeling, "ida_ida", FakeIda())
        assert api_modeling._normalize_data_kind("pointer") == "qword"

    def test_string_type_lookup_rejects_unknown_name(self):
        class FakeNalt:
            STRTYPE_C = 0

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(api_modeling, "ida_nalt", FakeNalt())
        _value, error = api_modeling._string_type_value("utf8z")
        assert error == "unsupported string_type"
        monkeypatch.undo()

    def test_undefine_items_rejects_non_positive_size(self):
        result = api_modeling.undefine_items.__wrapped__(0x401000, 0)
        assert result["error"] == "size must be greater than zero"

class TestModelingToolBehavior:
    """Behavioral tests using monkeypatched IDA APIs."""

    def test_create_function_is_idempotent_for_existing_start(self, monkeypatch):
        monkeypatch.setattr(api_modeling, "wait_for_auto_analysis", lambda: None)
        monkeypatch.setattr(api_modeling, "ida_funcs", object())
        monkeypatch.setattr(api_modeling, "idaapi", object())
        monkeypatch.setattr(
            api_modeling,
            "_describe_function",
            lambda ea: {"name": "sub_401000", "start_ea": "0x401000", "end_ea": "0x401010"},
        )

        result = api_modeling.create_function.__wrapped__(0x401000)

        assert result["changed"] is False
        assert result["note"] == "function already exists"

    def test_make_code_undefines_current_item_before_creating(self, monkeypatch):
        calls = {"undefine": [], "create_insn": []}

        class FakeBytes:
            @staticmethod
            def get_full_flags(_ea):
                return 1

            @staticmethod
            def is_code(_flags):
                return False

            @staticmethod
            def is_unknown(_flags):
                return False

            @staticmethod
            def get_item_head(ea):
                return ea

            @staticmethod
            def get_item_size(_ea):
                return 4

            @staticmethod
            def del_items(ea, _flags, size):
                calls["undefine"].append((ea, size))
                return True

            @staticmethod
            def is_strlit(_ea):
                return False

            @staticmethod
            def is_data(_flags):
                return True

            @staticmethod
            def is_tail(_flags):
                return False

        class FakeUa:
            @staticmethod
            def create_insn(ea):
                calls["create_insn"].append(ea)
                return 1

        monkeypatch.setattr(api_modeling, "ida_bytes", FakeBytes())
        monkeypatch.setattr(api_modeling, "ida_ua", FakeUa())
        monkeypatch.setattr(api_modeling, "wait_for_auto_analysis", lambda: None)

        states = iter(
            [
                {"ea": "0x401000", "head": "0x401000", "size": 4, "kind": "data"},
                {"ea": "0x401000", "head": "0x401000", "size": 1, "kind": "code"},
            ]
        )
        monkeypatch.setattr(api_modeling, "_describe_item", lambda _ea: next(states))

        result = api_modeling.make_code.__wrapped__(0x401000)

        assert result["changed"] is True
        assert calls["undefine"] == [(0x401000, 4)]
        assert calls["create_insn"] == [0x401000]

    def test_make_data_reports_invalid_type(self, monkeypatch):
        monkeypatch.setattr(api_modeling, "wait_for_auto_analysis", lambda: None)
        monkeypatch.setattr(api_modeling, "_describe_item", lambda _ea: {"kind": "unknown", "head": "0x401000", "size": 1})
        monkeypatch.setattr(api_modeling, "_create_numeric_items", lambda _ea, _kind, _count: (False, 0))

        result = api_modeling.make_data.__wrapped__(0x401000, "matrix4", 1)

        assert result["error"] == "unsupported or failed data_type"

    def test_make_string_rejects_invalid_length(self):
        result = api_modeling.make_string.__wrapped__(0x401000, "c", -1)
        assert result["error"] == "length must be zero or greater"

    def test_make_code_invalidates_string_cache_on_success(self, monkeypatch):
        calls = {"invalidate": 0}

        monkeypatch.setattr(api_modeling, "wait_for_auto_analysis", lambda: None)
        monkeypatch.setattr(api_modeling, "_ensure_code", lambda _ea: True)
        monkeypatch.setattr(api_modeling, "_invalidate_strings_cache", lambda: calls.__setitem__("invalidate", calls["invalidate"] + 1))

        states = iter(
            [
                {"ea": "0x401000", "head": "0x401000", "size": 4, "kind": "data"},
                {"ea": "0x401000", "head": "0x401000", "size": 1, "kind": "code"},
            ]
        )
        monkeypatch.setattr(api_modeling, "_describe_item", lambda _ea: next(states))

        result = api_modeling.make_code.__wrapped__(0x401000)

        assert result["changed"] is True
        assert calls["invalidate"] == 1

    def test_make_data_invalidates_string_cache_on_success(self, monkeypatch):
        calls = {"invalidate": 0}

        monkeypatch.setattr(api_modeling, "wait_for_auto_analysis", lambda: None)
        monkeypatch.setattr(api_modeling, "_invalidate_strings_cache", lambda: calls.__setitem__("invalidate", calls["invalidate"] + 1))
        monkeypatch.setattr(api_modeling, "_create_numeric_items", lambda _ea, _kind, _count: (True, 1))
        monkeypatch.setattr(api_modeling, "_undefine_range", lambda _ea, _size: True)

        states = iter(
            [
                {"ea": "0x401000", "head": "0x401000", "size": 4, "kind": "string"},
                {"ea": "0x401000", "head": "0x401000", "size": 4, "kind": "data"},
            ]
        )
        monkeypatch.setattr(api_modeling, "_describe_item", lambda _ea: next(states))

        result = api_modeling.make_data.__wrapped__(0x401000, "byte", 4)

        assert result["changed"] is True
        assert calls["invalidate"] == 1

    def test_make_string_invalidates_string_cache_on_success(self, monkeypatch):
        calls = {"invalidate": 0}

        class FakeBytes:
            @staticmethod
            def create_strlit(_ea, _length, _strtype):
                return True

        monkeypatch.setattr(api_modeling, "ida_bytes", FakeBytes())
        monkeypatch.setattr(api_modeling, "wait_for_auto_analysis", lambda: None)
        monkeypatch.setattr(api_modeling, "_invalidate_strings_cache", lambda: calls.__setitem__("invalidate", calls["invalidate"] + 1))
        monkeypatch.setattr(api_modeling, "_string_type_value", lambda _kind: (0, None))
        monkeypatch.setattr(api_modeling, "_undefine_range", lambda _ea, _size: True)

        states = iter(
            [
                {"ea": "0x401000", "head": "0x401000", "size": 4, "kind": "data"},
                {"ea": "0x401000", "head": "0x401000", "size": 4, "kind": "string"},
            ]
        )
        monkeypatch.setattr(api_modeling, "_describe_item", lambda _ea: next(states))

        result = api_modeling.make_string.__wrapped__(0x401000, "c", 4)

        assert result["changed"] is True
        assert calls["invalidate"] == 1


class TestModelingIntegration:
    """Integration tests that exercise the proxy/direct tool path."""

    def test_delete_and_recreate_function(self, tool_caller, first_function):
        start_ea = first_function["start_ea"]

        delete_result = tool_caller("delete_function", {"address": start_ea})
        assert isinstance(delete_result, dict)
        assert "error" not in delete_result
        assert delete_result.get("changed") is True

        try:
            missing = tool_caller("disasm", {"addr": start_ea})
            assert isinstance(missing, list)
            assert missing
            assert "error" in missing[0]

            create_result = tool_caller("create_function", {"address": start_ea})
            assert isinstance(create_result, dict)
            assert "error" not in create_result
            assert create_result.get("function") is not None

            recreated = tool_caller("disasm", {"addr": start_ea})
            assert isinstance(recreated, list)
            assert recreated
            assert "error" not in recreated[0]
            assert str(recreated[0].get("start_ea", "")).lower() == str(start_ea).lower()
        finally:
            restored = tool_caller("disasm", {"addr": start_ea})
            if isinstance(restored, list) and restored and "error" in restored[0]:
                tool_caller("create_function", {"address": start_ea})

    def test_undefine_and_make_code_round_trip(self, tool_caller, first_function_address):
        address = hex(first_function_address)

        undef_result = tool_caller("undefine_items", {"address": address, "size": 1})
        assert isinstance(undef_result, dict)
        assert "error" not in undef_result
        assert undef_result.get("changed") is True
        assert undef_result.get("new_item", {}).get("kind") == "unknown"

        try:
            code_result = tool_caller("make_code", {"address": address})
            assert isinstance(code_result, dict)
            assert "error" not in code_result
            assert code_result.get("new_item", {}).get("kind") == "code"
        finally:
            tool_caller("make_code", {"address": address})

    def test_make_data_success_and_restore_string(self, tool_caller, first_string):
        address = first_string["ea"]
        address = hex(address) if isinstance(address, int) else address
        string_len = int(first_string.get("length") or 0)

        result = tool_caller("make_data", {"address": address, "data_type": "byte", "count": 4})
        assert isinstance(result, dict)
        assert "error" not in result
        assert result.get("normalized_type") == "byte"
        assert result.get("new_item", {}).get("kind") == "data"

        try:
            restored = tool_caller("make_string", _make_string_params(address, string_len))
            assert isinstance(restored, dict)
            assert "error" not in restored
            assert restored.get("new_item", {}).get("kind") == "string"
        finally:
            _restore_string(tool_caller, address, string_len)

    def test_make_string_success_after_data(self, tool_caller, first_string):
        address = first_string["ea"]
        address = hex(address) if isinstance(address, int) else address
        string_len = int(first_string.get("length") or 0)

        data_result = tool_caller("make_data", {"address": address, "data_type": "byte", "count": 2})
        assert isinstance(data_result, dict)
        assert "error" not in data_result

        try:
            string_result = tool_caller("make_string", _make_string_params(address, string_len))
            assert isinstance(string_result, dict)
            assert "error" not in string_result
            assert string_result.get("new_item", {}).get("kind") == "string"

            read_result = tool_caller("get_string", {"addr": address, "max_len": max(string_len, 1) if string_len else 32})
            assert isinstance(read_result, list)
            assert read_result
            assert "error" not in read_result[0]
            assert read_result[0].get("text") or read_result[0].get("value")
        finally:
            _restore_string(tool_caller, address, string_len)
