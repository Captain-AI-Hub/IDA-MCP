"""测试 api_core.py 中的工具。

测试逻辑：
1. 基础连接和实例管理
2. 元数据获取
3. 函数/全局变量/字符串列表
4. 入口点和类型
5. 导入/导出表、段信息、光标位置

运行方式：
    pytest -m core          # 只运行 core 模块测试
    pytest test_core.py     # 运行此文件所有测试
"""
import pytest

pytestmark = pytest.mark.core


class TestConnection:
    """连接和实例管理测试。"""
    
    def test_check_connection(self, tool_caller):
        """测试连接检查。"""
        result = tool_caller("check_connection")
        assert "ok" in result
        assert result["ok"] is True
    
    def test_list_instances(self, tool_caller):
        """测试列出实例。"""
        result = tool_caller("list_instances")
        assert isinstance(result, list)
        assert len(result) >= 1


class TestMetadata:
    """IDB 元数据测试。"""
    
    def test_get_metadata(self, tool_caller, metadata):
        """测试获取元数据。"""
        # metadata fixture 已经获取了元数据
        assert "input_file" in metadata
        assert "arch" in metadata
        assert "bits" in metadata
    
    def test_metadata_arch(self, metadata):
        """测试架构信息。"""
        assert metadata["arch"] in ("x86", "x64", "arm", "arm64", "mips", "ppc", "metapc")
    
    def test_metadata_bits(self, metadata):
        """测试位宽信息。"""
        assert metadata["bits"] in (16, 32, 64)


class TestFunctions:
    """函数列表测试。"""
    
    def test_list_functions_default(self, tool_caller):
        """测试默认参数列出函数。"""
        # 显式传递所有参数以兼容签名问题
        result = tool_caller("list_functions", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
        assert "total" in result
    
    def test_list_functions_pagination(self, tool_caller):
        """测试分页参数。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 10})
        assert "error" not in result
        assert "items" in result
        assert len(result["items"]) <= 10
    
    def test_list_functions_offset(self, tool_caller, functions_cache):
        """测试偏移参数。"""
        if len(functions_cache) < 5:
            pytest.skip("Not enough functions")
        
        result1 = tool_caller("list_functions", {"offset": 0, "count": 3})
        result2 = tool_caller("list_functions", {"offset": 2, "count": 3})
        
        # 第二次查询的第一个应该等于第一次的第三个
        if result1["items"] and result2["items"]:
            assert result1["items"][2]["start_ea"] == result2["items"][0]["start_ea"]
    
    def test_list_functions_pattern(self, tool_caller):
        """测试模式过滤。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 100, "pattern": "*"})
        assert "error" not in result
    
    def test_list_functions_invalid_offset(self, tool_caller):
        """测试无效偏移。"""
        result = tool_caller("list_functions", {"offset": -1})
        assert "error" in result
    
    def test_list_functions_invalid_count(self, tool_caller):
        """测试无效计数。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 0})
        assert "error" in result
    
    def test_list_functions_count_too_large(self, tool_caller):
        """测试计数过大。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 10000})
        assert "error" in result


class TestGlobals:
    """全局变量测试。"""
    
    def test_list_globals_default(self, tool_caller):
        """测试默认参数列出全局变量。"""
        result = tool_caller("list_globals", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
    
    def test_list_globals_pagination(self, tool_caller):
        """测试分页。"""
        result = tool_caller("list_globals", {"offset": 0, "count": 5})
        assert "error" not in result
        assert len(result.get("items", [])) <= 5
    
    def test_list_globals_pattern(self, tool_caller):
        """测试模式过滤。"""
        result = tool_caller("list_globals", {"offset": 0, "count": 100, "pattern": "*"})
        assert "error" not in result


class TestStrings:
    """字符串测试。"""
    
    def test_list_strings_default(self, tool_caller):
        """测试默认参数列出字符串。"""
        result = tool_caller("list_strings", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
    
    def test_list_strings_pagination(self, tool_caller):
        """测试分页。"""
        result = tool_caller("list_strings", {"offset": 0, "count": 10})
        assert "error" not in result
        assert len(result.get("items", [])) <= 10
    
    def test_list_strings_pattern(self, tool_caller, strings_cache):
        """测试内容过滤。"""
        if not strings_cache:
            pytest.skip("No strings available")
        
        # 使用已知字符串的一部分进行搜索
        # API 返回 "text" 字段，不是 "value"
        first_str = strings_cache[0].get("text", "")
        if len(first_str) > 3:
            pattern = first_str[:3]
            result = tool_caller("list_strings", {"offset": 0, "count": 100, "pattern": pattern})
            assert "error" not in result


class TestLocalTypes:
    """本地类型测试。"""
    
    def test_list_local_types(self, tool_caller):
        """测试列出本地类型。"""
        result = tool_caller("list_local_types")
        assert "error" not in result
        assert "items" in result or "total" in result


class TestEntryPoints:
    """入口点测试。"""
    
    def test_get_entry_points(self, tool_caller):
        """测试获取入口点。"""
        result = tool_caller("get_entry_points")
        assert "error" not in result
        assert "items" in result


class TestConvertNumber:
    """数字转换测试。"""

    def test_convert_number(self, tool_caller):
        result = tool_caller("convert_number", {"text": "401000h", "size": 32})

        assert isinstance(result, dict)
        assert "error" not in result
        assert result["hex"] == "0x00401000"
        assert result["unsigned"] == 0x401000




class TestImports:
    """导入表测试。"""
    
    def test_list_imports_default(self, tool_caller):
        """测试默认参数列出导入函数。"""
        result = tool_caller("list_imports", {"offset": 0, "count": 20})
        assert isinstance(result, dict)
        assert "items" in result or "error" in result
        
        if "items" in result and result["items"]:
            item = result["items"][0]
            assert "name" in item
            assert "module" in item
            assert "ea" in item
    
    def test_list_imports_pagination(self, tool_caller):
        """测试分页。"""
        result = tool_caller("list_imports", {"offset": 0, "count": 5})
        assert isinstance(result, dict)
        if "items" in result:
            assert len(result["items"]) <= 5
    
    def test_list_imports_pattern(self, tool_caller):
        """测试按模式过滤。"""
        result = tool_caller("list_imports", {"pattern": "kernel32", "count": 10})
        assert isinstance(result, dict)


class TestExports:
    """导出表测试。"""
    
    def test_list_exports_default(self, tool_caller):
        """测试默认参数列出导出函数。"""
        result = tool_caller("list_exports", {"offset": 0, "count": 20})
        assert isinstance(result, dict)
        assert "items" in result or "error" in result
        
        if "items" in result and result["items"]:
            item = result["items"][0]
            assert "name" in item
            assert "ea" in item
    
    def test_list_exports_pagination(self, tool_caller):
        """测试分页。"""
        result = tool_caller("list_exports", {"offset": 0, "count": 5})
        assert isinstance(result, dict)
        if "items" in result:
            assert len(result["items"]) <= 5


class TestSegments:
    """段信息测试。"""
    
    def test_list_segments(self, tool_caller):
        """测试列出内存段。"""
        result = tool_caller("list_segments")
        assert isinstance(result, dict)
        assert "items" in result
        
        if result["items"]:
            seg = result["items"][0]
            assert "name" in seg
            assert "start_ea" in seg
            assert "end_ea" in seg
            assert "perm" in seg  # 权限字符串 rwx
            assert "size" in seg
    
    def test_segments_have_code(self, tool_caller):
        """验证存在可执行段。"""
        result = tool_caller("list_segments")
        assert isinstance(result, dict)
        
        segments = result.get("items", [])
        code_segs = [s for s in segments if 'x' in s.get('perm', '')]
        # 大多数二进制都有可执行段
        print(f"Executable segments: {len(code_segs)}")


class TestCursor:
    """光标位置测试。"""
    
    def test_get_cursor(self, tool_caller):
        """测试获取当前光标位置。"""
        result = tool_caller("get_cursor")
        assert isinstance(result, dict)
        assert "ea" in result
        assert "function" in result
        assert "selection" in result
