"""Tests for tools in api_modify.py.

Test logic:
1. Use fixtures to get valid function / global variable addresses
2. Test comments, renames, and other modification operations
3. Note: these tests modify the IDB database

Proxy parameter mappings:
- set_comment: items (List of {address, comment})
- rename_function: address (str), new_name
- rename_local_variable: function_address (str), old_name, new_name
- rename_global_variable: old_name, new_name
- patch_bytes: items (List of {address, bytes})
- apply_patch: output_path, overwrite

Run with:
    pytest -m modify        # Run only modify module tests
    pytest test_modify.py   # Run all tests in this file
"""
import pytest

from ida_mcp import api_modify

pytestmark = pytest.mark.modify


class TestSetComment:
    """Comment setting tests."""

    def test_set_comment_single(self, tool_caller, first_function_address):
        """Test setting a single comment."""
        test_comment = "Test comment from pytest"
        # API accepts items: List[{address, comment}]
        result = tool_caller("set_comment", {
            "items": [{"address": hex(first_function_address), "comment": test_comment}]
        })

        assert isinstance(result, list)
        assert len(result) == 1
        if "error" not in result[0]:
            # API 返回 changed 字段
            assert "changed" in result[0]

    def test_set_comment_batch(self, tool_caller, functions_cache):
        """Test batch comment setting."""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions")

        items = [
            {"address": f["start_ea"], "comment": f"Batch comment {i}"}
            for i, f in enumerate(functions_cache[:3])
        ]
        result = tool_caller("set_comment", {"items": items})

        assert isinstance(result, list)
        assert len(result) == 3

    def test_set_comment_clear(self, tool_caller, first_function_address):
        """Test clearing a comment."""
        addr = hex(first_function_address)
        # First set a comment
        tool_caller("set_comment", {
            "items": [{"address": addr, "comment": "To be cleared"}]
        })

        # Then clear it
        result = tool_caller("set_comment", {
            "items": [{"address": addr, "comment": ""}]
        })

        assert isinstance(result, list)

    def test_set_comment_multiple_different(self, tool_caller, functions_cache):
        """Test setting different comments at different addresses."""
        if len(functions_cache) < 2:
            pytest.skip("Not enough functions")

        items = [
            {"address": functions_cache[0]["start_ea"], "comment": "Comment A"},
            {"address": functions_cache[1]["start_ea"], "comment": "Comment B"},
        ]
        result = tool_caller("set_comment", {"items": items})

        assert isinstance(result, list)
        assert len(result) == 2


class TestRenameFunction:
    """Function rename tests."""

    def test_rename_function(self, tool_caller, first_function):
        """Test renaming a function."""
        old_name = first_function["name"]
        # start_ea is a hex string; strip 0x prefix for the name
        addr_str = first_function['start_ea'].replace('0x', '').replace('0X', '')
        new_name = f"test_renamed_{addr_str}"

        # Proxy params: address (str), new_name
        result = tool_caller("rename_function", {
            "address": first_function["start_ea"],
            "new_name": new_name
        })

        if "error" not in result:
            assert "changed" in result
            # 恢复原名
            tool_caller("rename_function", {
                "address": first_function["start_ea"],
                "new_name": old_name
            })
        else:
            # If it fails, print debug info
            print(f"rename_function failed: {result}")
            # Might be a database state issue; try by function name
            result2 = tool_caller("rename_function", {
                "address": old_name,
                "new_name": new_name
            })
            if "error" not in result2:
                # 恢复原名
                tool_caller("rename_function", {
                    "address": new_name,
                    "new_name": old_name
                })

    def test_rename_function_by_name(self, tool_caller, first_function):
        """Test renaming by function name (fallback test)."""
        old_name = first_function["name"]
        new_name = f"test_by_name_{old_name[:8]}"

        result = tool_caller("rename_function", {
            "address": old_name,
            "new_name": new_name
        })

        # 恢复原名（无论成功与否都尝试）
        if "error" not in result:
            tool_caller("rename_function", {
                "address": new_name,
                "new_name": old_name
            })

    def test_rename_function_invalid_name(self, tool_caller, first_function):
        """Test using an invalid name (starting with a digit)."""
        result = tool_caller("rename_function", {
            "address": first_function["start_ea"],
            "new_name": "123invalid"
        })
        # Proxy forwards to API to validate C identifier; should return error
        assert "error" in result

    def test_rename_function_empty_name(self, tool_caller, first_function):
        """Test empty name."""
        result = tool_caller("rename_function", {
            "address": first_function["start_ea"],
            "new_name": ""
        })
        assert "error" in result


class TestRenameLocalVariable:
    """Local variable rename tests."""

    def test_rename_local_variable(self, tool_caller, first_function_address):
        """Test renaming a local variable."""
        # API params: function_address (str), old_name, new_name
        result = tool_caller("rename_local_variable", {
            "function_address": hex(first_function_address),
            "old_name": "v1",
            "new_name": "test_var"
        })
        # 可能成功或失败（取决于是否有该变量）
        assert isinstance(result, dict)


class TestRenameGlobalVariable:
    """Global variable rename tests."""

    def test_rename_global_variable(self, tool_caller, first_global):
        """Test renaming a global variable."""
        old_name = first_global["name"]
        # ea is a hex string; strip 0x prefix for the name
        addr_str = first_global['ea'].replace('0x', '').replace('0X', '')
        new_name = f"test_global_{addr_str}"

        # API params: old_name, new_name
        result = tool_caller("rename_global_variable", {
            "old_name": old_name,
            "new_name": new_name
        })

        if "error" not in result and result.get("changed"):
            # 恢复原名
            tool_caller("rename_global_variable", {
                "old_name": new_name,
                "new_name": old_name
            })

    def test_rename_global_variable_not_found(self, tool_caller):
        """Test renaming a nonexistent global variable."""
        result = tool_caller("rename_global_variable", {
            "old_name": "nonexistent_global_xyz123",
            "new_name": "new_name"
        })
        assert "error" in result


class TestPatchBytes:
    """Byte patch tests.

    Note: these tests modify the database; use read-then-restore strategy.
    """

    @pytest.fixture(autouse=True)
    def require_patch_bytes_enabled(self, tool_caller, complex_baseline):
        result = tool_caller("patch_bytes", {
            "items": [{"address": complex_baseline["modify"]["safe_patch_address"], "bytes": []}]
        })
        if isinstance(result, dict) and "error" in result:
            pytest.skip(f"Unsafe patch_bytes tool unavailable: {result['error']}")

    def test_patch_bytes_and_restore(self, tool_caller, complex_baseline):
        """Test patching and restoring bytes."""
        addr = complex_baseline["modify"]["safe_patch_address"]

        # 1. Read original bytes (hex string, space-separated)
        read_result = tool_caller("get_bytes", {
            "addr": addr,
            "size": 4
        })

        if not isinstance(read_result, list) or not read_result:
            pytest.skip("Cannot read bytes")

        original_hex = read_result[0].get("hex", "")
        if not original_hex:
            pytest.skip("No bytes read")

        # 2. Patch (NOP: 0x90)
        nop_bytes = [0x90] * len(original_hex.split())
        patch_result = tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": nop_bytes}]
        })

        assert isinstance(patch_result, list)
        assert len(patch_result) == 1

        # 3. Restore original bytes
        restore_result = tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": original_hex}]
        })

        assert isinstance(restore_result, list)

    def test_patch_bytes_hex_string(self, tool_caller, complex_baseline):
        """Test patching with a hex string."""
        addr = complex_baseline["modify"]["safe_patch_address"]

        # Read original
        read_result = tool_caller("get_bytes", {
            "addr": addr,
            "size": 2
        })

        if not isinstance(read_result, list) or not read_result:
            pytest.skip("Cannot read bytes")

        original = read_result[0].get("hex", "")

        # Patch using hex string format
        result = tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": "90 90"}]
        })

        assert isinstance(result, list)

        # 恢复
        tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": original}]
        })

    def test_patch_bytes_invalid_address(self, tool_caller):
        """Test invalid address."""
        result = tool_caller("patch_bytes", {
            "items": [{"address": "invalid", "bytes": [0x90]}]
        })

        assert isinstance(result, list)
        assert result[0].get("error") is not None

    def test_patch_bytes_empty_bytes(self, tool_caller, complex_baseline):
        """Test empty bytes."""
        result = tool_caller("patch_bytes", {
            "items": [{"address": complex_baseline["modify"]["safe_patch_address"], "bytes": []}]
        })

        assert isinstance(result, list)
        assert result[0].get("error") is not None


class TestPatchBytesHelpers:
    def test_patch_bytes_invalidates_string_cache_on_partial_success(self, monkeypatch):
        calls = {"invalidate": 0}

        class FakeBytes:
            @staticmethod
            def get_bytes(_ea, _size):
                return b"\x90\x90"

            @staticmethod
            def patch_byte(ea, _value):
                if ea == 0x401001:
                    raise RuntimeError("boom")

        monkeypatch.setattr(api_modify, "ida_bytes", FakeBytes())
        monkeypatch.setattr(api_modify, "_invalidate_strings_cache", lambda: calls.__setitem__("invalidate", calls["invalidate"] + 1))

        result = api_modify.patch_bytes.__wrapped__([{"address": "0x401000", "bytes": [0x90, 0x91]}])

        assert result[0]["patched"] == 1
        assert calls["invalidate"] == 1


class TestApplyPatchHelpers:
    def _patch_ida(self, monkeypatch, input_file, visits):
        class FakeIdaApi:
            BADADDR = -1

            @staticmethod
            def get_input_file_path():
                return str(input_file)

        class FakeBytes:
            @staticmethod
            def visit_patched_bytes(start, end, callback):
                assert start == 0
                assert end == FakeIdaApi.BADADDR
                for args in visits:
                    callback(*args)

        monkeypatch.setattr(api_modify, "idaapi", FakeIdaApi())
        monkeypatch.setattr(api_modify, "ida_bytes", FakeBytes())

    def test_apply_patch_writes_default_export_file(self, monkeypatch, tmp_path):
        input_file = tmp_path / "sample.exe"
        input_file.write_bytes(b"ABCD")
        self._patch_ida(
            monkeypatch,
            input_file,
            [
                (0x401001, 1, ord("B"), ord("Z")),
                (0x401003, 3, ord("D"), ord("Y")),
            ],
        )

        result = api_modify.apply_patch.__wrapped__()

        assert "error" not in result
        assert result["applied"] == 2
        output_file = tmp_path / "sample.patched.exe"
        assert result["output_file"] == str(output_file)
        assert output_file.read_bytes() == b"AZCY"
        assert input_file.read_bytes() == b"ABCD"

    def test_apply_patch_rejects_existing_output_without_overwrite(self, monkeypatch, tmp_path):
        input_file = tmp_path / "sample.bin"
        output_file = tmp_path / "out.bin"
        input_file.write_bytes(b"ABCD")
        output_file.write_bytes(b"old")
        self._patch_ida(monkeypatch, input_file, [(0x401000, 0, ord("A"), ord("X"))])

        result = api_modify.apply_patch.__wrapped__(str(output_file))

        assert result["error"] == "output file already exists"
        assert output_file.read_bytes() == b"old"

    def test_apply_patch_overwrites_existing_output_when_requested(self, monkeypatch, tmp_path):
        input_file = tmp_path / "sample.bin"
        output_file = tmp_path / "out.bin"
        input_file.write_bytes(b"ABCD")
        output_file.write_bytes(b"old")
        self._patch_ida(monkeypatch, input_file, [(0x401000, 0, ord("A"), ord("X"))])

        result = api_modify.apply_patch.__wrapped__(str(output_file), overwrite=True)

        assert "error" not in result
        assert output_file.read_bytes() == b"XBCD"

    def test_apply_patch_reports_skipped_non_file_backed_patches(self, monkeypatch, tmp_path):
        input_file = tmp_path / "sample.bin"
        input_file.write_bytes(b"ABCD")
        self._patch_ida(monkeypatch, input_file, [(0x500000, -1, ord("A"), ord("X"))])

        result = api_modify.apply_patch.__wrapped__()

        assert result["error"] == "no file-backed patches to apply"
        assert result["skipped"] == 1
        assert not (tmp_path / "sample.patched.bin").exists()

    def test_apply_patch_resolves_relative_output_next_to_input(self, monkeypatch, tmp_path):
        input_file = tmp_path / "sample.bin"
        input_file.write_bytes(b"ABCD")
        self._patch_ida(monkeypatch, input_file, [(0x401002, 2, ord("C"), ord("Q"))])

        result = api_modify.apply_patch.__wrapped__("exports/patched.bin")

        output_file = tmp_path / "exports" / "patched.bin"
        assert "error" not in result
        assert result["output_file"] == str(output_file)
        assert output_file.read_bytes() == b"ABQD"

    def test_apply_patch_rejects_input_file_as_output(self, monkeypatch, tmp_path):
        input_file = tmp_path / "sample.bin"
        input_file.write_bytes(b"ABCD")
        self._patch_ida(monkeypatch, input_file, [(0x401000, 0, ord("A"), ord("X"))])

        result = api_modify.apply_patch.__wrapped__(str(input_file), overwrite=True)

        assert result["error"] == "output_path must not be the input file"
        assert input_file.read_bytes() == b"ABCD"


class TestAddBookmark:
    """Bookmark tests (IDA 9.x compatible path)."""

    def test_add_bookmark(self, tool_caller, first_function_address):
        """Add a bookmark and verify slot allocation, then erase it."""
        addr = hex(first_function_address)
        result = tool_caller("add_bookmark", {"address": addr, "description": "mcp-pytest-bookmark"})

        assert isinstance(result, dict)
        if "error" in result:
            pytest.skip(f"bookmarks unavailable: {result['error']}")
        assert result["address"].lower() == addr.lower()
        slot = result["slot"]
        assert isinstance(slot, int) and slot >= 0

        # cleanup: erase the bookmark we just created
        tool_caller("py_eval", {"code": (
            "import ida_kernwin, ida_moves\n"
            "try:\n"
            "    pid = ida_kernwin.get_place_class_id('idaplace_t')\n"
            "    place = ida_kernwin.get_place_class_template(pid).clone()\n"
            "    ida_kernwin.place_t.as_idaplace_t(place).ea = " + str(first_function_address) + "\n"
            "except AttributeError:\n"
            "    place = ida_kernwin.ea2place(" + str(first_function_address) + ")\n"
            "entry = ida_moves.lochist_entry_t()\n"
            "entry.set_place(place)\n"
            "ida_moves.bookmarks_t.erase(entry, " + str(slot) + ", None)\n"
        )})
