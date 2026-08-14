"""Tests for tools in api_analysis.py.

Test logic:
1. Use fixtures to pre-fetch prerequisite info (functions, strings, etc.)
2. Call analysis tools based on this info
3. Verify result format and content

API parameter mappings:
- decompile: addr (comma-separated addresses or name strings)
- disasm: addr (comma-separated addresses or name strings)
- linear_disasm: start_address, count
- get_callers: addr
- get_callees: addr
- get_function_signature: addr
- xrefs_to: addr (comma-separated address strings)
- find_bytes: pattern, start, end, limit
- get_basic_blocks: addr

Run with:
    pytest -m analysis      # Run only analysis module tests
    pytest test_analysis.py # Run all tests in this file
"""
import pytest

pytestmark = pytest.mark.analysis


class TestDecompile:
    """Decompilation tests."""

    def test_decompile_by_address(self, tool_caller, first_function_address):
        """Test decompilation by address."""
        result = tool_caller("decompile", {"addr": hex(first_function_address)})

        assert isinstance(result, str)
        assert "// error" not in result
        assert "{" in result  # has a function body

    def test_decompile_by_name(self, tool_caller, first_function_name):
        """Test decompilation by name."""
        result = tool_caller("decompile", {"addr": first_function_name})

        assert isinstance(result, str)
        assert "// error" not in result
        assert first_function_name in result

    def test_decompile_batch(self, tool_caller, complex_baseline):
        """Test batch decompilation (comma-separated)."""
        names = [
            "ida_mcp_point_make",
            "ida_mcp_rect_init",
            "ida_mcp_complex_dispatch",
        ]
        addr_list = ",".join(complex_baseline["functions"][name]["start_ea"] for name in names)
        result = tool_caller("decompile", {"addr": addr_list})

        assert isinstance(result, str)
        assert "// error" not in result
        for name in names:
            assert f"// {name} " in result

    def test_decompile_invalid_address(self, tool_caller):
        """Test decompilation with invalid address."""
        result = tool_caller("decompile", {"addr": "0xDEADBEEF"})

        assert isinstance(result, str)
        assert "// error" in result

    def test_decompile_main(self, tool_caller, main_function_address):
        """Test decompiling the main function."""
        result = tool_caller("decompile", {"addr": hex(main_function_address)})

        assert isinstance(result, str)
        assert "// error" not in result
        assert len(result) > 0


class TestDisasm:
    """Disassembly tests."""

    def test_disasm_by_address(self, tool_caller, first_function_address):
        """Test disassembly by address."""
        result = tool_caller("disasm", {"addr": hex(first_function_address)})

        assert isinstance(result, list)
        assert len(result) == 1
        if "error" not in result[0]:
            assert "instructions" in result[0]
            assert len(result[0]["instructions"]) > 0
            inst = result[0]["instructions"][0]
            # addresses are hex strings and text has no IDA color tags
            assert isinstance(inst["ea"], str) and inst["ea"].startswith("0x")
            assert "\x01" not in inst["text"] and "\x02" not in inst["text"]
            assert "bytes" not in inst

    def test_disasm_by_name(self, tool_caller, first_function_name):
        """Test disassembly by name."""
        result = tool_caller("disasm", {"addr": first_function_name})

        assert isinstance(result, list)
        assert len(result) == 1

    def test_disasm_batch(self, tool_caller, functions_cache):
        """Test batch disassembly (comma-separated)."""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")

        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("disasm", {"addr": addr_list})

        assert isinstance(result, list)
        assert len(result) == 3

    def test_disasm_invalid_address(self, tool_caller):
        """Test disassembly with invalid address."""
        result = tool_caller("disasm", {"addr": "0xDEADBEEF"})

        assert isinstance(result, list)
        assert len(result) == 1
        assert "error" in result[0]


class TestLinearDisasm:
    """Linear disassembly tests."""

    def test_linear_disasm(self, tool_caller, first_function_address):
        """Test linear disassembly."""
        result = tool_caller("linear_disasm", {
            "start_address": hex(first_function_address),
            "count": 10
        })

        if "error" not in result:
            assert "instructions" in result
            assert len(result["instructions"]) <= 10

    def test_linear_disasm_more(self, tool_caller, first_function_address):
        """Test linear disassembly with more instructions."""
        result = tool_caller("linear_disasm", {
            "start_address": hex(first_function_address),
            "count": 50
        })

        if "error" not in result:
            assert "instructions" in result
            # Verify instruction format
            if result["instructions"]:
                inst = result["instructions"][0]
                assert "ea" in inst  # API returns ea

    def test_linear_disasm_invalid_count(self, tool_caller, first_function_address):
        """Test invalid count."""
        result = tool_caller("linear_disasm", {
            "start_address": hex(first_function_address),
            "count": 0
        })
        assert "error" in result

    def test_linear_disasm_count_too_large(self, tool_caller, first_function_address):
        """Test count too large (max 64)."""
        result = tool_caller("linear_disasm", {
            "start_address": hex(first_function_address),
            "count": 100
        })
        assert "error" in result


class TestStructuredAnalysis:
    """Structured analysis tool tests."""

    def test_get_callers_by_address(self, tool_caller, first_function_address):
        result = tool_caller("get_callers", {"addr": hex(first_function_address)})
        assert isinstance(result, dict)
        if "error" not in result:
            assert "items" in result
            assert "total" in result
            assert isinstance(result["items"], list)
            for item in result["items"]:
                assert "address" in item
                assert "call_sites" in item

    def test_get_callees_by_name(self, tool_caller, first_function_name):
        result = tool_caller("get_callees", {"addr": first_function_name})
        assert isinstance(result, dict)
        if "error" not in result:
            assert "items" in result
            assert "total" in result
            assert isinstance(result["items"], list)
            for item in result["items"]:
                assert "address" in item
                assert "call_sites" in item

    def test_get_function_signature(self, tool_caller, first_function_address):
        result = tool_caller("get_function_signature", {"addr": hex(first_function_address)})
        assert isinstance(result, dict)
        if "error" not in result:
            assert "signature" in result
            assert isinstance(result["signature"], str)
            assert result.get("source") in {"typeinfo", "pseudocode", "fallback_name"}

    def test_complex_dispatch_callees_match_baseline(self, tool_caller, complex_baseline):
        result = tool_caller("get_callees", {"addr": "ida_mcp_complex_dispatch"})
        assert isinstance(result, dict)
        assert "error" not in result
        names = {item["name"] for item in result["items"]}
        assert result["total"] == complex_baseline["functions"]["ida_mcp_complex_dispatch"]["callee_count"]
        assert set(complex_baseline["relationships"]["complex_dispatch_callees"]) == names

    def test_patch_target_callers_match_baseline(self, tool_caller, complex_baseline):
        result = tool_caller("get_callers", {"addr": "ida_mcp_patch_target"})
        assert isinstance(result, dict)
        assert "error" not in result
        names = {item["name"] for item in result["items"]}
        assert names == set(complex_baseline["relationships"]["patch_target_callers"])

    def test_stack_heavy_signature_matches_baseline(self, tool_caller, complex_baseline):
        result = tool_caller("get_function_signature", {"addr": "ida_mcp_stack_heavy_transform"})
        assert isinstance(result, dict)
        assert "error" not in result
        assert result["signature"] == complex_baseline["functions"]["ida_mcp_stack_heavy_transform"]["signature"]

    def test_structured_analysis_not_found(self, tool_caller):
        for tool_name in [
            "get_callers",
            "get_callees",
            "get_function_signature",
        ]:
            result = tool_caller(tool_name, {"addr": "__nonexistent_func__"})
            assert isinstance(result, dict)
            assert "error" in result


class TestXrefsTo:
    """Cross-reference (to) tests."""

    def test_xrefs_to_function(self, tool_caller, first_function_address):
        """Test cross-references to a function."""
        result = tool_caller("xrefs_to", {"addr": hex(first_function_address)})

        assert isinstance(result, list)
        assert len(result) == 1
        if "error" not in result[0]:
            assert "xrefs" in result[0]

    def test_xrefs_to_decimal_address(self, tool_caller, first_function_address):
        """Test decimal address format."""
        # xrefs_to API only supports address format, not names
        result = tool_caller("xrefs_to", {"addr": str(first_function_address)})

        assert isinstance(result, list)
        assert len(result) == 1

    def test_xrefs_to_batch(self, tool_caller, functions_cache):
        """Test batch cross-reference query (comma-separated)."""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")

        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("xrefs_to", {"addr": addr_list})

        assert isinstance(result, list)
        assert len(result) == 3

    def test_xrefs_to_string(self, tool_caller, first_string_address):
        """Test cross-references to a string."""
        result = tool_caller("xrefs_to", {"addr": hex(first_string_address)})

        assert isinstance(result, list)
        assert len(result) == 1
        # Strings usually have references
        if "error" not in result[0]:
            assert "xrefs" in result[0]


class TestXrefsFrom:
    """Cross-reference (from) tests."""

    def test_xrefs_from_function(self, tool_caller, first_function_address):
        """Test outgoing cross-references from a function."""
        result = tool_caller("xrefs_from", {"addr": hex(first_function_address)})

        assert isinstance(result, list)
        assert len(result) == 1
        if "error" not in result[0]:
            assert "xrefs" in result[0]

    def test_xrefs_from_batch(self, tool_caller, functions_cache):
        """Test batch cross-reference query."""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")

        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("xrefs_from", {"addr": addr_list})

        assert isinstance(result, list)
        assert len(result) == 3

    def test_xrefs_from_invalid_address(self, tool_caller):
        """Test invalid address."""
        result = tool_caller("xrefs_from", {"addr": "invalid_addr"})

        assert isinstance(result, list)
        assert len(result) == 1
        assert "error" in result[0]


class TestXrefsToField:
    """Struct field reference tests."""

    def test_xrefs_to_field_nonexistent(self, tool_caller):
        """Test cross-references to a nonexistent struct field."""
        result = tool_caller("xrefs_to_field", {
            "struct_name": "nonexistent_struct_xyz",
            "field_name": "field"
        })
        # Should return error or empty result
        assert isinstance(result, dict)

    def test_xrefs_to_field_with_types(self, tool_caller):
        """Test field references for known types."""
        declare_result = tool_caller("declare_struct", {
            "decl": "struct IdaMcpFieldXrefFixture { int field; int other; };"
        })
        assert isinstance(declare_result, dict)

        result = tool_caller("xrefs_to_field", {
            "struct_name": "IdaMcpFieldXrefFixture",
            "field_name": "field"
        })
        assert isinstance(result, dict)


class TestFindBytes:
    """Byte search tests."""

    def test_find_bytes_simple(self, tool_caller, first_function_address):
        """Test simple byte search."""
        # First read the first few bytes at the function start
        bytes_result = tool_caller("get_bytes", {
            "addr": hex(first_function_address),
            "size": 4
        })

        if isinstance(bytes_result, list) and bytes_result:
            hex_bytes = bytes_result[0].get("hex", "")
            if hex_bytes:
                # Use the first few bytes as the search pattern
                pattern = hex_bytes[:11]  # "XX XX XX XX"
                result = tool_caller("find_bytes", {"pattern": pattern, "limit": 5})
                assert isinstance(result, dict)
                if "matches" in result:
                    assert isinstance(result["matches"], list)

    def test_find_bytes_with_wildcard(self, tool_caller):
        """Test byte search with wildcard."""
        # Search for a common pattern
        result = tool_caller("find_bytes", {
            "pattern": "55 48 ?? ??",
            "limit": 10
        })
        assert isinstance(result, dict)

    def test_find_bytes_invalid_pattern(self, tool_caller):
        """Test invalid pattern."""
        result = tool_caller("find_bytes", {"pattern": "ZZ XX"})
        assert isinstance(result, dict)
        assert "error" in result

    def test_find_bytes_empty_pattern(self, tool_caller):
        """Test empty pattern."""
        result = tool_caller("find_bytes", {"pattern": ""})
        assert isinstance(result, dict)
        assert "error" in result


class TestBasicBlocks:
    """Basic block tests."""

    def test_get_basic_blocks_by_address(self, tool_caller, first_function_address):
        """Test getting basic blocks by address."""
        result = tool_caller("get_basic_blocks", {"addr": hex(first_function_address)})
        assert isinstance(result, dict)

        if "error" not in result:
            assert "blocks" in result
            assert "total" in result
            assert isinstance(result["blocks"], list)

            if result["blocks"]:
                block = result["blocks"][0]
                assert "start_ea" in block
                assert "end_ea" in block
                assert "predecessors" in block
                assert "successors" in block

    def test_get_basic_blocks_by_name(self, tool_caller, first_function_name):
        """Test getting basic blocks by function name."""
        result = tool_caller("get_basic_blocks", {"addr": first_function_name})
        assert isinstance(result, dict)

    def test_complex_basic_blocks_match_baseline(self, tool_caller, complex_baseline):
        result = tool_caller("get_basic_blocks", {"addr": "ida_mcp_complex_dispatch"})
        assert isinstance(result, dict)
        assert "error" not in result
        assert result["total"] == complex_baseline["functions"]["ida_mcp_complex_dispatch"]["basic_block_count"]
        assert any(block["successors"] for block in result["blocks"])
        assert any(block["predecessors"] for block in result["blocks"])

    def test_get_basic_blocks_not_found(self, tool_caller):
        """Test nonexistent function."""
        result = tool_caller("get_basic_blocks", {"addr": "__nonexistent_func__"})
        assert isinstance(result, dict)
        assert "error" in result
