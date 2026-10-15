"""Tests for tools in api_core.py.

Test logic:
1. Basic connection and instance management
2. Metadata retrieval
3. Function / global / string lists
4. Entry points and types
5. Import / export tables, segment info, cursor position

Run with:
    pytest -m core          # Run only core module tests
    pytest test_core.py     # Run all tests in this file
"""
import pytest

from ida_mcp import api_core

pytestmark = pytest.mark.core


class TestConnection:
    """Connection and instance management tests."""

    def test_wait_for_analysis(self, tool_caller):
        """Analysis must be complete after the session instance opens."""
        result = tool_caller("wait_for_analysis")
        assert result.get("analyzed") is True

    def test_save_idb_roundtrip(self, tool_caller):
        """save_idb keeps the current database path."""
        result = tool_caller("save_idb", {"path": ""})
        assert result.get("saved") is True


class TestMetadata:
    """IDB metadata tests."""

    def test_get_metadata_uses_ida9_bitness_api(self, monkeypatch):
        """Unit guard for x64 IDBs: metapc + 64-bit must normalize to x86_64."""
        class FakeIdaApi:
            @staticmethod
            def get_input_file_path():
                return "C:\\samples\\complex.exe"

        class FakeIdaIda:
            @staticmethod
            def inf_get_procname():
                return "metapc"

            @staticmethod
            def inf_get_app_bitness():
                return 64

            @staticmethod
            def inf_is_64bit():
                return True

            @staticmethod
            def inf_is_be():
                return False

        monkeypatch.setattr(api_core, "idaapi", FakeIdaApi())
        monkeypatch.setattr(api_core, "ida_ida", FakeIdaIda())
        monkeypatch.setattr(api_core.os.path, "isfile", lambda _path: False)

        result = api_core.get_metadata.__wrapped__()

        assert result["arch"] == "x86_64"
        assert result["bits"] == 64
        assert result["endian"] == "little"

    def test_get_metadata(self, tool_caller, metadata, complex_baseline):
        """Test getting metadata."""
        # metadata fixture already retrieved the metadata
        assert "input_file" in metadata
        assert "arch" in metadata
        assert "bits" in metadata
        assert metadata["hash"] == complex_baseline["sample"]["sha256"]
        assert metadata["bits"] == complex_baseline["sample"]["bits"]
        assert metadata["arch"] == complex_baseline["sample"]["arch"]
        assert metadata["endian"] == complex_baseline["sample"]["endian"]
        assert metadata["input_file"].lower().endswith("complex.exe")

    def test_metadata_arch(self, metadata, complex_baseline):
        """Test architecture info."""
        assert metadata["arch"] == complex_baseline["sample"]["arch"]

    def test_metadata_bits(self, metadata, complex_baseline):
        """Test bit-width info."""
        assert metadata["bits"] == complex_baseline["sample"]["bits"]


class TestFunctions:
    """Function list tests."""

    def test_list_functions_default(self, tool_caller):
        """Test listing functions with default parameters."""
        # Explicitly pass all parameters to avoid signature compatibility issues
        result = tool_caller("list_functions", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
        assert "total" in result

    def test_list_functions_pagination(self, tool_caller):
        """Test pagination parameters."""
        result = tool_caller("list_functions", {"offset": 0, "count": 10})
        assert "error" not in result
        assert "items" in result
        assert len(result["items"]) <= 10

    def test_list_functions_offset(self, tool_caller, functions_cache):
        """Test offset parameter."""
        if len(functions_cache) < 5:
            pytest.skip("Not enough functions")

        result1 = tool_caller("list_functions", {"offset": 0, "count": 3})
        result2 = tool_caller("list_functions", {"offset": 2, "count": 3})

        # The first item of the second query should equal the third item of the first query
        if result1["items"] and result2["items"]:
            assert result1["items"][2]["start_ea"] == result2["items"][0]["start_ea"]

    def test_list_functions_pattern(self, tool_caller, complex_baseline):
        """Test pattern filtering."""
        result = tool_caller("list_functions", {"offset": 0, "count": 100, "pattern": "ida_mcp"})
        assert "error" not in result
        names = {item["name"] for item in result.get("items", [])}
        assert set(complex_baseline["functions"]).intersection(names)

    def test_list_functions_invalid_offset(self, tool_caller):
        """Test invalid offset."""
        result = tool_caller("list_functions", {"offset": -1})
        assert "error" in result

    def test_list_functions_invalid_count(self, tool_caller):
        """Test invalid count."""
        result = tool_caller("list_functions", {"offset": 0, "count": 0})
        assert "error" in result

    def test_list_functions_count_too_large(self, tool_caller):
        """Test count too large."""
        result = tool_caller("list_functions", {"offset": 0, "count": 10000})
        assert "error" in result


class TestGlobals:
    """Global variable tests."""

    def test_list_globals_default(self, tool_caller):
        """Test listing globals with default parameters."""
        result = tool_caller("list_globals", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result

    def test_list_globals_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_globals", {"offset": 0, "count": 5})
        assert "error" not in result
        assert len(result.get("items", [])) <= 5

    def test_list_globals_pattern(self, tool_caller, complex_baseline):
        """Test pattern filtering."""
        result = tool_caller("list_globals", {"offset": 0, "count": 100, "pattern": "ida_mcp"})
        assert "error" not in result
        names = {item["name"] for item in result.get("items", [])}
        assert set(complex_baseline["globals"]).issubset(names)


class TestStrings:
    """String tests."""

    def test_list_strings_regex_filter_unit(self, monkeypatch):
        """Unit guard for regex content filtering."""
        monkeypatch.setattr(
            api_core,
            "_get_strings_cache",
            lambda: [
                (0x1000, 6, 0, "alpha1"),
                (0x1008, 5, 0, "alpha"),
                (0x1010, 5, 0, "bravo2"),
            ],
        )

        result = api_core.list_strings.__wrapped__(
            pattern=r"^alpha[0-9]+$",
            regex=True,
        )

        assert "error" not in result
        assert [item["text"] for item in result["items"]] == ["alpha1"]

    def test_list_strings_invalid_regex_unit(self, monkeypatch):
        """Unit guard for invalid regex reporting."""
        monkeypatch.setattr(api_core, "_get_strings_cache", lambda: [])

        result = api_core.list_strings.__wrapped__(pattern="[", regex=True)

        assert "error" in result
        assert "invalid regex" in result["error"]

    def test_list_strings_default(self, tool_caller):
        """Test listing strings with default parameters."""
        result = tool_caller("list_strings", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result

    def test_list_strings_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_strings", {"offset": 0, "count": 10})
        assert "error" not in result
        assert len(result.get("items", [])) <= 10

    def test_list_strings_pattern(self, tool_caller, strings_cache, complex_baseline):
        """Test content filtering."""
        result = tool_caller("list_strings", {"offset": 0, "count": 100, "pattern": "IDA_MCP_COMPLEX_SENTINEL"})
        assert "error" not in result
        texts = {item["text"] for item in result.get("items", [])}
        expected = {
            text
            for text in complex_baseline["strings"]
            if text.startswith("IDA_MCP_COMPLEX_SENTINEL")
        }
        assert expected.issubset(texts)

    def test_list_strings_regex(self, tool_caller):
        """Test regex content filtering."""
        result = tool_caller(
            "list_strings",
            {
                "offset": 0,
                "count": 100,
                "pattern": r"^IDA_MCP_COMPLEX_SENTINEL_(ENTRY|RECT)$",
                "regex": True,
            },
        )
        assert "error" not in result
        texts = {item["text"] for item in result.get("items", [])}
        expected = {
            "IDA_MCP_COMPLEX_SENTINEL_ENTRY",
            "IDA_MCP_COMPLEX_SENTINEL_RECT",
        }
        assert expected.issubset(texts)

    def test_list_strings_invalid_regex(self, tool_caller):
        """Test invalid regex reporting."""
        result = tool_caller("list_strings", {"pattern": "[", "regex": True})
        assert "error" in result
        assert "invalid regex" in result["error"]


class TestLocalTypes:
    """Local type tests."""

    def test_list_local_types(self, tool_caller):
        """Test listing local types."""
        result = tool_caller("list_local_types")
        assert "error" not in result
        assert "items" in result or "total" in result


class TestEntryPoints:
    """Entry point tests."""

    def test_get_entry_points(self, tool_caller):
        """Test getting entry points."""
        result = tool_caller("get_entry_points")
        assert "error" not in result
        assert "items" in result


class TestConvertNumber:
    """Number conversion tests."""

    def test_convert_number(self, tool_caller):
        result = tool_caller("convert_number", {"text": "401000h", "size": 32})

        assert isinstance(result, dict)
        assert "error" not in result
        assert result["hex"] == "0x00401000"
        assert result["unsigned"] == 0x401000




class TestImports:
    """Import table tests."""

    def test_list_imports_default(self, tool_caller, complex_baseline):
        """Test listing imports with default parameters."""
        result = tool_caller("list_imports", {"offset": 0, "count": 20})
        assert isinstance(result, dict)
        assert "items" in result or "error" in result

        if "items" in result and result["items"]:
            item = result["items"][0]
            assert "name" in item
            assert "module" in item
            assert "ea" in item
            names = {entry["name"] for entry in result["items"]}
            assert set(complex_baseline["imports"]["required_names"]).intersection(names)

    def test_list_imports_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_imports", {"offset": 0, "count": 5})
        assert isinstance(result, dict)
        if "items" in result:
            assert len(result["items"]) <= 5

    def test_list_imports_pattern(self, tool_caller):
        """Test filtering by pattern."""
        result = tool_caller("list_imports", {"pattern": "kernel32", "count": 10})
        assert isinstance(result, dict)


class TestExports:
    """Export table tests."""

    def test_list_exports_default(self, tool_caller):
        """Test listing exports with default parameters."""
        result = tool_caller("list_exports", {"offset": 0, "count": 20})
        assert isinstance(result, dict)
        assert "items" in result or "error" in result

        if "items" in result and result["items"]:
            item = result["items"][0]
            assert "name" in item
            assert "ea" in item

    def test_list_exports_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_exports", {"offset": 0, "count": 5})
        assert isinstance(result, dict)
        if "items" in result:
            assert len(result["items"]) <= 5


class TestSegments:
    """Segment info tests."""

    def test_list_segments(self, tool_caller):
        """Test listing memory segments."""
        result = tool_caller("list_segments")
        assert isinstance(result, dict)
        assert "items" in result

        if result["items"]:
            seg = result["items"][0]
            assert "name" in seg
            assert "start_ea" in seg
            assert "end_ea" in seg
            assert "perm" in seg  # Permission string rwx
            assert "size" in seg

    def test_segments_have_code(self, tool_caller, complex_baseline):
        """Verify executable segments exist."""
        result = tool_caller("list_segments")
        assert isinstance(result, dict)

        segments = result.get("items", [])
        code_segs = [s for s in segments if 'x' in s.get('perm', '')]
        # Most binaries have executable segments
        print(f"Executable segments: {len(code_segs)}")
        text = next((s for s in segments if s.get("name") == ".text"), None)
        assert text is not None
        assert text["start_ea"] == complex_baseline["segments"][".text"]["start_ea"]
        assert text["end_ea"] == complex_baseline["segments"][".text"]["end_ea"]

    def test_add_segment(self, tool_caller, metadata):
        """Test adding a new segment."""
        bitness = metadata.get("bits", 64)
        tool_caller("delete_segment", address="0xDEAD0000")
        try:
            result = tool_caller("add_segment",
                                start_ea="0xDEAD0000",
                                size=0x1000,
                                name="test_seg",
                                seg_class="DATA",
                                perm="rw-",
                                bitness=bitness)
            assert isinstance(result, dict)
            assert "error" not in result, f"add_segment failed: {result}"
            assert result["name"] == "test_seg"
            assert result["size"] == 0x1000
        finally:
            tool_caller("delete_segment", address="0xDEAD0000")

    def test_add_segment_invalid_address(self, tool_caller):
        """Test adding segment with invalid address."""
        result = tool_caller("add_segment",
                            start_ea="not_an_address",
                            size=0x1000,
                            name="bad_seg")
        assert "error" in result

    def test_add_segment_invalid_size(self, tool_caller):
        """Test adding segment with zero size."""
        result = tool_caller("add_segment",
                            start_ea="0xBEEF0000",
                            size=0,
                            name="zero_seg")
        assert "error" in result

    def test_delete_segment(self, tool_caller, metadata):
        """Test deleting a segment."""
        bitness = metadata.get("bits", 64)
        add_result = tool_caller("add_segment",
                                start_ea="0xCAFE0000",
                                size=0x1000,
                                name="del_test",
                                seg_class="DATA",
                                perm="rw-",
                                bitness=bitness)
        if "error" in add_result:
            pytest.skip(f"could not create segment for deletion test: {add_result}")

        result = tool_caller("delete_segment", address="0xCAFE0000")
        assert isinstance(result, dict)
        assert result.get("deleted") is True
        assert result["name"] == "del_test"

    def test_delete_segment_invalid_address(self, tool_caller):
        """Test deleting segment with invalid address."""
        result = tool_caller("delete_segment", address="not_valid")
        assert "error" in result

    def test_delete_segment_no_segment(self, tool_caller):
        """Test deleting at address with no segment."""
        result = tool_caller("delete_segment", address="0xFFFFFFFFFF")
        assert "error" in result


class TestCursor:
    """Cursor position tests."""

    def test_get_cursor(self, tool_caller):
        """Test getting current cursor position."""
        result = tool_caller("get_cursor")
        assert isinstance(result, dict)
        assert "ea" in result
        assert "function" in result
        assert "selection" in result
