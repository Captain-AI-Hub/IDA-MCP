"""测试 api_types.py 中的工具。

测试逻辑：
1. 测试类型声明
2. 测试函数原型设置
3. 测试变量类型设置
4. 测试结构体列表和详情

Proxy 参数对应：
- declare_struct: decl
- declare_enum: decl
- declare_typedef: decl
- set_function_prototype: function_address (str), prototype
- set_local_variable_type: function_address (str), variable_name, new_type
- set_global_variable_type: variable_name, new_type
- list_structs: pattern (可选)
- get_struct_info: name

运行方式：
    pytest -m types         # 只运行 types 模块测试
    pytest test_types.py    # 运行此文件所有测试
"""
import pytest

from ida_mcp import api_types

pytestmark = pytest.mark.types


class TestDeclareTypes:
    """声明类型测试。"""

    def test_build_temp_variable_decl_supports_array_fragments(self):
        decl = api_types._build_temp_variable_decl("webs_post_rewrite_entry[18]", "__tmp")
        assert decl == "webs_post_rewrite_entry __tmp[18];"

    def test_build_temp_variable_decl_supports_plain_fragments(self):
        decl = api_types._build_temp_variable_decl("int *", "__tmp")
        assert decl == "int * __tmp;"

    def test_declare_named_decl_uses_python_parser_only(self, monkeypatch):
        """默认应优先走 IDAPython parse_decls 路径。"""
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
        """测试声明结构体。"""
        result = tool_caller("declare_struct", {
            "decl": "struct TestStruct { int field1; char field2; };"
        })

        if "error" not in result:
            assert result.get("success") is True
            assert result.get("kind") == "struct"

    def test_declare_typedef(self, tool_caller):
        """测试声明 typedef。"""
        result = tool_caller("declare_typedef", {
            "decl": "typedef unsigned int UINT32;"
        })

        if "error" not in result:
            assert result.get("success") is True
            assert result.get("kind") == "typedef"

    def test_declare_enum(self, tool_caller):
        """测试声明枚举。"""
        result = tool_caller("declare_enum", {
            "decl": "enum TestEnum { VALUE_A = 0, VALUE_B = 1, VALUE_C = 2 };"
        })

        if "error" not in result:
            assert result.get("success") is True
            assert result.get("kind") == "enum"

    def test_declare_complex_struct(self, tool_caller):
        """测试声明复杂结构体。"""
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
        """测试无效声明。"""
        result = tool_caller("declare_struct", {
            "decl": "invalid syntax here {"
        })
        assert "error" in result

    def test_declare_empty(self, tool_caller):
        """测试空声明。"""
        result = tool_caller("declare_struct", {
            "decl": ""
        })
        assert "error" in result

    def test_declare_struct_rejects_enum_decl(self, tool_caller):
        """测试结构体工具拒绝枚举声明。"""
        result = tool_caller("declare_struct", {
            "decl": "enum WrongKind { VALUE = 1 };"
        })
        assert "error" in result


class TestSetFunctionPrototype:
    """设置函数原型测试。"""
    
    def test_set_function_prototype(self, tool_caller, first_function_address):
        """测试设置函数原型。"""
        # Proxy 参数: function_address (str), prototype
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": "int __cdecl func(int a, int b)"
        })
        
        # 可能成功或失败
        assert isinstance(result, dict)
    
    def test_set_function_prototype_invalid_address(self, tool_caller):
        """测试无效地址。"""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(0xDEADBEEF),
            "prototype": "int func(void)"
        })
        assert "error" in result
    
    def test_set_function_prototype_empty(self, tool_caller, first_function_address):
        """测试空原型。"""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": ""
        })
        assert "error" in result
    
    def test_set_function_prototype_invalid_syntax(self, tool_caller, first_function_address):
        """测试无效原型语法。"""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": "invalid prototype syntax"
        })
        assert "error" in result


class TestSetLocalVariableType:
    """设置局部变量类型测试。"""
    
    def test_set_local_variable_type(self, tool_caller, first_function_address):
        """测试设置局部变量类型。"""
        # Proxy 参数: function_address (str), variable_name, new_type
        result = tool_caller("set_local_variable_type", {
            "function_address": hex(first_function_address),
            "variable_name": "v1",
            "new_type": "int"
        })
        
        # 可能成功或失败（取决于是否有该变量）
        assert isinstance(result, dict)
    
    def test_set_local_variable_type_pointer(self, tool_caller, first_function_address):
        """测试设置指针类型。"""
        result = tool_caller("set_local_variable_type", {
            "function_address": hex(first_function_address),
            "variable_name": "v1",
            "new_type": "char*"
        })
        
        assert isinstance(result, dict)


class TestSetGlobalVariableType:
    """设置全局变量类型测试。"""
    
    def test_set_global_variable_type(self, tool_caller, first_global):
        """测试设置全局变量类型。"""
        # API 参数: variable_name, new_type
        result = tool_caller("set_global_variable_type", {
            "variable_name": first_global["name"],
            "new_type": "int"
        })
        
        # 可能成功或失败
        assert isinstance(result, dict)
    
    def test_set_global_variable_type_not_found(self, tool_caller):
        """测试不存在的全局变量。"""
        result = tool_caller("set_global_variable_type", {
            "variable_name": "nonexistent_global_xyz123",
            "new_type": "int"
        })
        assert "error" in result
    
    def test_set_global_variable_type_struct(self, tool_caller, first_global):
        """测试设置结构体类型。"""
        # 先声明结构体
        tool_caller("declare_struct", {
            "decl": "struct TestGlobalType { int a; int b; };"
        })
        
        result = tool_caller("set_global_variable_type", {
            "variable_name": first_global["name"],
            "new_type": "struct TestGlobalType"
        })
        
        assert isinstance(result, dict)


class TestListStructs:
    """结构体列表测试。"""

    def test_list_structs_uses_bounded_ordinal_scan(self, monkeypatch):
        """默认应按 ordinal 数量遍历，而不是扫描 ordinal limit。"""
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
            def get_ordinal_qty(self):
                return 3

            def get_ordinal_limit(self):
                raise AssertionError("list_structs should not use get_ordinal_limit")

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
        assert result["items"] == [
            {"ordinal": 2, "name": "TestStruct", "kind": "struct", "size": 8, "members": 2},
            {"ordinal": 3, "name": "TestUnion", "kind": "union", "size": 4, "members": 1},
        ]

    def test_list_structs(self, tool_caller):
        """测试列出结构体。"""
        result = tool_caller("list_structs")
        assert isinstance(result, dict)
        assert "items" in result
        
        if result["items"]:
            s = result["items"][0]
            assert "name" in s
            assert "kind" in s
            assert "size" in s
            assert "members" in s
    
    def test_list_structs_with_pattern(self, tool_caller):
        """测试按模式过滤结构体。"""
        result = tool_caller("list_structs", {"pattern": "test"})
        assert isinstance(result, dict)
        assert "items" in result


class TestGetStructInfo:
    """结构体详情测试。"""
    
    def test_get_struct_info(self, tool_caller):
        """测试获取结构体详情。"""
        # 先创建一个测试结构体
        tool_caller("declare_struct", {
            "decl": "struct TestStructInfo { int field1; char field2; void* field3; };"
        })
        
        result = tool_caller("get_struct_info", {"name": "TestStructInfo"})
        assert isinstance(result, dict)
        
        if "error" not in result:
            assert "name" in result
            assert "members" in result
            assert isinstance(result["members"], list)
    
    def test_get_struct_info_not_found(self, tool_caller):
        """测试获取不存在的结构体。"""
        result = tool_caller("get_struct_info", {"name": "__nonexistent_struct_12345__"})
        assert isinstance(result, dict)
        assert "error" in result
    
    def test_get_struct_info_empty_name(self, tool_caller):
        """测试空名称。"""
        result = tool_caller("get_struct_info", {"name": ""})
        assert isinstance(result, dict)
        assert "error" in result
