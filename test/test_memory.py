"""Tests for tools in api_memory.py.

Test logic:
1. Use fixtures to get valid addresses (functions / strings)
2. Test reading bytes / integers / strings

API parameter mappings (IDA API tool names):
- get_bytes: addr (comma-separated), size
- read_scalar: addr (comma-separated), width, signed
- get_string: addr (comma-separated), max_len

Run with:
    pytest -m memory        # Run only memory module tests
    pytest test_memory.py   # Run all tests in this file
"""
import pytest

pytestmark = pytest.mark.memory


class TestGetBytes:
    """Byte read tests."""

    def test_get_bytes_from_function(self, tool_caller, first_function_address):
        """Test reading bytes from a function address."""
        result = tool_caller("get_bytes", {
            "addr": hex(first_function_address),
            "size": 16
        })

        # API returns list format [{"address": ..., "size": ..., "hex": ...}]
        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "hex" in result[0]
            assert "bytes" not in result[0]

    def test_get_bytes_different_sizes(self, tool_caller, first_function_address):
        """Test different sizes."""
        for size in [1, 4, 16, 64, 256]:
            result = tool_caller("get_bytes", {
                "addr": hex(first_function_address),
                "size": size
            })
            assert isinstance(result, list)
            if result and "error" not in result[0]:
                # API returns hex field in "XX XX XX" format (space-separated)
                hex_str = result[0].get("hex", "")
                # After removing spaces, each byte is 2 hex chars
                hex_clean = hex_str.replace(" ", "")
                assert len(hex_clean) == size * 2

    def test_get_bytes_batch(self, tool_caller, functions_cache):
        """Test batch byte read (comma-separated)."""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")

        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("get_bytes", {
            "addr": addr_list,
            "size": 8
        })

        assert isinstance(result, list)
        assert len(result) == 3

    def test_get_complex_patch_bytes(self, tool_caller, complex_baseline):
        patch_bytes = complex_baseline["globals"]["ida_mcp_patch_bytes"]
        result = tool_caller("get_bytes", {"addr": patch_bytes["ea"], "size": patch_bytes["size"]})

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["hex"] == patch_bytes["initial_hex"]


class TestReadScalar:
    """Scalar read tests."""

    def test_read_scalar_u32(self, tool_caller, first_function_address):
        """Test reading 4-byte unsigned integer."""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 4})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert "hex" in result[0]
            assert 0 <= result[0]["value"] <= 0xFFFFFFFF

    def test_read_scalar_u64(self, tool_caller, first_function_address):
        """Test reading 8-byte unsigned integer."""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 8})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert "hex" in result[0]

    def test_read_scalar_u8(self, tool_caller, first_function_address):
        """Test reading 1-byte unsigned integer."""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 1})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert 0 <= result[0]["value"] <= 255

    def test_read_scalar_u16(self, tool_caller, first_function_address):
        """Test reading 2-byte unsigned integer."""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 2})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert 0 <= result[0]["value"] <= 0xFFFF

    def test_read_scalar_rejects_invalid_width(self, tool_caller, first_function_address):
        """Test rejecting unsupported width."""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 3})

        assert isinstance(result, list)
        assert len(result) >= 1
        assert "error" in result[0]

    def test_read_complex_global_counter(self, tool_caller, complex_baseline):
        counter = complex_baseline["globals"]["ida_mcp_global_counter"]
        result = tool_caller("read_scalar", {"addr": counter["ea"], "width": counter["size"], "signed": True})

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["value"] == counter["initial_value"]


class TestGetString:
    """String read tests."""

    def test_get_string(self, tool_caller, first_string_address):
        """Test reading a string."""
        result = tool_caller("get_string", {"addr": hex(first_string_address)})

        # API returns list format
        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "text" in result[0] or "value" in result[0]

    def test_get_string_with_max_length(self, tool_caller, first_string_address):
        """Test reading with max length limit."""
        result = tool_caller("get_string", {
            "addr": hex(first_string_address),
            "max_len": 5
        })

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            text = result[0].get("text") or result[0].get("value", "")
            # max_len limits returned length
            if text:
                assert len(text) <= 5

    def test_get_string_from_code(self, tool_caller, first_function_address):
        """Test reading from a code address (may return non-empty but garbled)."""
        result = tool_caller("get_string", {"addr": hex(first_function_address)})

        assert isinstance(result, list)
        # Code areas are usually not valid strings, but the API will try to read

    def test_get_string_batch(self, tool_caller, strings_cache):
        """Test batch string read (comma-separated)."""
        if len(strings_cache) < 3:
            pytest.skip("Not enough strings")

        # ea in strings_cache may be int or string
        addr_list = ",".join(
            hex(s["ea"]) if isinstance(s["ea"], int) else s["ea"]
            for s in strings_cache[:3]
        )
        result = tool_caller("get_string", {"addr": addr_list})

        assert isinstance(result, list)
        assert len(result) == 3

    def test_get_complex_sentinel_string(self, tool_caller, complex_baseline):
        sentinel = complex_baseline["strings"]["IDA_MCP_COMPLEX_SENTINEL_ENTRY"]
        result = tool_caller("get_string", {"addr": sentinel["ea"], "max_len": 64})

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["text"] == "IDA_MCP_COMPLEX_SENTINEL_ENTRY"
