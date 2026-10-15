"""Tests for tools in api_types.py.

Test logic:
1. Test type declarations
2. Test function prototype setting
3. Test variable type setting
4. Test struct list and details

Proxy parameter mappings:
- declare_struct: decl
- declare_enum: decl
- declare_typedef: decl
- set_function_prototype: function_address (str), prototype
- set_local_variable_type: function_address (str), variable_name, new_type
- set_global_variable_type: variable_name, new_type
- list_structs: pattern (optional)
- get_struct_info: name

Run with:
    pytest -m types         # Run only types module tests
    pytest test_types.py    # Run all tests in this file
"""
import pytest

from ida_mcp import api_types

pytestmark = pytest.mark.types


IDA_MCP_FIXTURE_TYPE_DECLS = [
    """
    struct IdaMcpPoint {
        int x;
        int y;
    };
    """,
    """
    struct IdaMcpRect {
        struct IdaMcpPoint top_left;
        struct IdaMcpPoint bottom_right;
        unsigned int color;
        char name[32];
    };
    """,
    """
    struct IdaMcpNode {
        int id;
        int value;
        struct IdaMcpNode *next;
        struct IdaMcpNode *prev;
    };
    """,
    """
    struct IdaMcpList {
        struct IdaMcpNode *head;
        struct IdaMcpNode *tail;
        int count;
    };
    """,
    """
    struct IdaMcpPayload {
        unsigned long long raw;
        double scalar;
        char text[8];
    };
    """,
    """
    struct IdaMcpRecord {
        unsigned int magic;
        int status;
        struct IdaMcpRect bounds;
        struct IdaMcpPayload payload;
        int scores[8];
    };
    """,
]


@pytest.fixture
def declared_complex_fixture_types(tool_caller, complex_baseline):
    for decl in IDA_MCP_FIXTURE_TYPE_DECLS:
        result = tool_caller("declare_struct", {"decl": decl})
        assert isinstance(result, dict)
        assert "error" not in result
        assert result.get("success") is True
    return complex_baseline["types"]["fixture_structs"]


class TestDeclareTypes:
    """Type declaration tests."""

    def test_build_temp_variable_decl_supports_array_fragments(self):
        decl = api_types._build_temp_variable_decl("webs_post_rewrite_entry[18]", "__tmp")
        assert decl == "webs_post_rewrite_entry __tmp[18];"

    def test_build_temp_variable_decl_supports_plain_fragments(self):
        decl = api_types._build_temp_variable_decl("int *", "__tmp")
        assert decl == "int * __tmp;"

    def test_declare_named_decl_uses_python_parser_only(self, monkeypatch):
        """By default it should prefer the IDAPython parse_decls path."""
        calls = {"python": 0, "fallback": 0}

        class FakeTinfo:
            def empty(self):
                return False

            def is_struct(self):
                return False

            def is_enum(self):
                return False

            def is_typedef(self):
                return True

            def is_union(self):
                return False

            def get_named_type(self, _til, _name):
                return True

        def fake_python(decls, hti_flags):
            calls["python"] += 1
            return (0, [])

        def fake_parse_decl(decl_text):
            return (FakeTinfo(), "SafeType", [])

        monkeypatch.setattr(api_types, "_parse_decls_python", fake_python)
        monkeypatch.setattr(api_types, "_parse_decl_tinfo", fake_parse_decl)
        monkeypatch.setattr(api_types, "_named_type_exists", lambda _name: False)
        monkeypatch.setattr(api_types, "_load_named_type", lambda _name: FakeTinfo())
        monkeypatch.setattr(api_types, "_apply_named_type", lambda _name, _tinfo, _existed: (calls.__setitem__("fallback", calls["fallback"] + 1) or True, []))

        result = api_types.declare_typedef.__wrapped__("typedef int SafeType;")

        assert result.get("success") is True
        assert calls == {"python": 1, "fallback": 0}

    def test_declare_struct(self, tool_caller):
        """Test declaring a struct."""
        result = tool_caller("declare_struct", {
            "decl": "struct TestStruct { int field1; char field2; };"
        })

        if "error" not in result:
            assert result.get("success") is True
            assert result.get("kind") == "struct"

    def test_declare_typedef(self, tool_caller):
        """Test declaring a typedef."""
        result = tool_caller("declare_typedef", {
            "decl": "typedef unsigned int UINT32;"
        })

        if "error" not in result:
            assert result.get("success") is True
            assert result.get("kind") == "typedef"

    def test_declare_enum(self, tool_caller):
        """Test declaring an enum."""
        result = tool_caller("declare_enum", {
            "decl": "enum TestEnum { VALUE_A = 0, VALUE_B = 1, VALUE_C = 2 };"
        })

        if "error" not in result:
            assert result.get("success") is True
            assert result.get("kind") == "enum"

    def test_declare_complex_struct(self, tool_caller):
        """Test declaring a complex struct."""
        result = tool_caller("declare_struct", {
            "decl": """
                struct ComplexStruct {
                    int id;
                    char name[32];
                    struct {
                        int x;
                        int y;
                    } position;
                    void* data;
                };
            """
        })
        assert isinstance(result, dict)

    def test_declare_invalid(self, tool_caller):
        """Test invalid declaration."""
        result = tool_caller("declare_struct", {
            "decl": "invalid syntax here {"
        })
        assert "error" in result

    def test_declare_empty(self, tool_caller):
        """Test empty declaration."""
        result = tool_caller("declare_struct", {
            "decl": ""
        })
        assert "error" in result

    def test_declare_struct_rejects_enum_decl(self, tool_caller):
        """Test that declare_struct rejects an enum declaration."""
        result = tool_caller("declare_struct", {
            "decl": "enum WrongKind { VALUE = 1 };"
        })
        assert "error" in result


class TestSetFunctionPrototype:
    """Function prototype setting tests."""

    def test_set_function_prototype(self, tool_caller, first_function_address):
        """Test setting function prototype."""
        # Proxy params: function_address (str), prototype
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": "int __cdecl func(int a, int b)"
        })

        # 可能成功或失败
        assert isinstance(result, dict)

    def test_set_function_prototype_invalid_address(self, tool_caller):
        """Test invalid address."""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(0xDEADBEEF),
            "prototype": "int func(void)"
        })
        assert "error" in result

    def test_set_function_prototype_empty(self, tool_caller, first_function_address):
        """Test empty prototype."""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": ""
        })
        assert "error" in result

    def test_set_function_prototype_invalid_syntax(self, tool_caller, first_function_address):
        """Test invalid prototype syntax."""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": "invalid prototype syntax"
        })
        assert "error" in result


class TestSetLocalVariableType:
    """Local variable type setting tests."""

    def test_set_local_variable_type(self, tool_caller, first_function_address):
        """Test setting local variable type."""
        # Proxy params: function_address (str), variable_name, new_type
        result = tool_caller("set_local_variable_type", {
            "function_address": hex(first_function_address),
            "variable_name": "v1",
            "new_type": "int"
        })

        # 可能成功或失败（取决于是否有该变量）
        assert isinstance(result, dict)

    def test_set_local_variable_type_pointer(self, tool_caller, first_function_address):
        """Test setting pointer type."""
        result = tool_caller("set_local_variable_type", {
            "function_address": hex(first_function_address),
            "variable_name": "v1",
            "new_type": "char*"
        })

        assert isinstance(result, dict)


class TestSetGlobalVariableType:
    """Global variable type setting tests."""

    def test_set_global_variable_type(self, tool_caller, first_global):
        """Test setting global variable type."""
        # API params: variable_name, new_type
        result = tool_caller("set_global_variable_type", {
            "variable_name": first_global["name"],
            "new_type": "int"
        })

        # 可能成功或失败
        assert isinstance(result, dict)

    def test_set_global_variable_type_not_found(self, tool_caller):
        """Test nonexistent global variable."""
        result = tool_caller("set_global_variable_type", {
            "variable_name": "nonexistent_global_xyz123",
            "new_type": "int"
        })
        assert "error" in result

    def test_set_global_variable_type_struct(self, tool_caller, first_global):
        """Test setting struct type."""
        # First declare the struct
        tool_caller("declare_struct", {
            "decl": "struct TestGlobalType { int a; int b; };"
        })

        result = tool_caller("set_global_variable_type", {
            "variable_name": first_global["name"],
            "new_type": "struct TestGlobalType"
        })

        assert isinstance(result, dict)


class TestListStructs:
    """Struct list tests."""

    def test_list_structs_uses_ida9_ordinal_limit(self, monkeypatch):
        """IDA 9 exposes sparse local type ordinals via get_ordinal_limit."""
        class FakeUdt(list):
            def size(self):
                return len(self)

        class FakeTinfo:
            def __init__(self):
                self.ordinal = None

            def is_struct(self):
                return self.ordinal == 2

            def is_union(self):
                return self.ordinal == 3

            def get_udt_details(self, udt):
                if self.ordinal == 2:
                    udt.extend([object(), object()])
                    return True
                if self.ordinal == 3:
                    udt.append(object())
                    return True
                return False

            def get_size(self):
                return {2: 8, 3: 4}.get(self.ordinal, 0)

        class FakeTypeInf:
            def get_ordinal_limit(self):
                return 4

            def get_numbered_type_name(self, til, ordinal):
                return {1: "AliasType", 2: "TestStruct", 3: "TestUnion"}.get(ordinal)

            def tinfo_t(self):
                return FakeTinfo()

            def get_numbered_type(self, til, ordinal, tif):
                tif.ordinal = ordinal

            def udt_type_data_t(self):
                return FakeUdt()

        fake_typeinf = FakeTypeInf()
        fake_idaapi = type("FakeIdaApi", (), {"cvar": type("CVar", (), {"idati": object()})()})()

        monkeypatch.setattr(api_types, "ida_typeinf", fake_typeinf)
        monkeypatch.setattr(api_types, "idaapi", fake_idaapi)

        result = api_types.list_structs.__wrapped__()

        assert result["total"] == 2
        assert result["items"] == (
            "TestStruct  size=8 members=2\n[union] TestUnion  size=4 members=1"
        )

    def test_list_structs_uses_tinfo_numbered_type_method(self, monkeypatch):
        """IDA 9.3 loads numbered types through tinfo_t.get_numbered_type."""
        class FakeUdt(list):
            def size(self):
                return len(self)

        class FakeTinfo:
            def __init__(self):
                self.ordinal = None

            def get_numbered_type(self, til, ordinal):
                self.ordinal = ordinal
                return True

            def is_struct(self):
                return self.ordinal == 2

            def is_union(self):
                return False

            def get_udt_details(self, udt):
                udt.append(object())
                return True

            def get_size(self):
                return 8

        class FakeTypeInf:
            def get_ordinal_limit(self):
                return 3

            def get_numbered_type_name(self, til, ordinal):
                return {1: "AliasType", 2: "MethodStruct"}.get(ordinal)

            def tinfo_t(self):
                return FakeTinfo()

            def get_numbered_type(self, til, ordinal, tif):
                raise TypeError("get_numbered_type() takes 2 positional arguments but 3 were given")

            def udt_type_data_t(self):
                return FakeUdt()

        fake_typeinf = FakeTypeInf()
        fake_idaapi = type("FakeIdaApi", (), {"cvar": type("CVar", (), {"idati": object()})()})()

        monkeypatch.setattr(api_types, "ida_typeinf", fake_typeinf)
        monkeypatch.setattr(api_types, "idaapi", fake_idaapi)

        result = api_types.list_structs.__wrapped__()

        assert result["items"] == "MethodStruct  size=8 members=1"

    def test_list_structs(self, tool_caller, declared_complex_fixture_types):
        """Test listing structs."""
        result = tool_caller("list_structs")
        assert isinstance(result, dict)
        assert "items" in result
        names = {line.split("  ")[0] for line in result["items"].splitlines()}
        assert set(declared_complex_fixture_types).issubset(names)

        if result["items"]:
            first = result["items"].splitlines()[0]
            assert first.split("  ")[0] and "size=" in first
            assert "members=" in first

    def test_list_structs_with_pattern(self, tool_caller, declared_complex_fixture_types):
        """Test filtering structs by pattern."""
        result = tool_caller("list_structs", {"pattern": "IdaMcp"})
        assert isinstance(result, dict)
        assert "items" in result
        names = {line.split("  ")[0] for line in result["items"].splitlines()}
        assert set(declared_complex_fixture_types).issubset(names)


class TestGetStructInfo:
    """Struct detail tests."""

    def test_get_struct_info(self, tool_caller, declared_complex_fixture_types, complex_baseline):
        """Test getting struct info."""
        result = tool_caller("get_struct_info", {"name": "IdaMcpRecord"})
        assert isinstance(result, dict)

        assert "error" not in result
        assert result["name"] == "IdaMcpRecord"
        expected = complex_baseline["types"]["struct_details"]["IdaMcpRecord"]
        assert result["size"] == expected["size"]
        assert result["member_count"] == expected["member_count"]
        assert "members" in result
        assert isinstance(result["members"], list)
        members = {member["name"]: member for member in result["members"]}
        assert set(expected["members"]).issubset(members)
        for name, expected_member in expected["members"].items():
            assert members[name]["offset"] == expected_member["offset"]
            assert members[name]["size"] == expected_member["size"]

    def test_get_struct_info_not_found(self, tool_caller):
        """Test getting a nonexistent struct."""
        result = tool_caller("get_struct_info", {"name": "__nonexistent_struct_12345__"})
        assert isinstance(result, dict)
        assert "error" in result

    def test_get_struct_info_empty_name(self, tool_caller):
        """Test empty name."""
        result = tool_caller("get_struct_info", {"name": ""})
        assert isinstance(result, dict)
        assert "error" in result
