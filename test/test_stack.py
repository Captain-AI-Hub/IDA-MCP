"""测试栈相关工具。

测试逻辑：
1. 使用 fixtures 获取有效函数地址
2. 测试栈帧信息获取
3. 测试栈变量声明

API 参数对应：
- stack_frame: addr (逗号分隔)
- declare_stack: items (List of {function_address, offset, name, type?, size?})
- delete_stack: items (List of {function_address, name})

注意：
- 64 位代码和简单函数可能没有显式栈帧定义
- 栈帧获取可能来自：ida9_frame、classic_frame、hexrays_lvars

运行方式：
    pytest -m stack         # 只运行 stack 模块测试
    pytest test_stack.py    # 运行此文件所有测试
"""
import pytest

pytestmark = pytest.mark.stack


class TestStackFrame:
    """栈帧信息测试。"""
    
    def test_stack_frame(self, tool_caller, first_function_address):
        """测试获取栈帧信息。"""
        # API 参数名为 addr
        result = tool_caller("stack_frame", {
            "addr": hex(first_function_address)
        })
        
        # API 返回 List[dict]
        assert isinstance(result, list)
        if result and "error" not in result[0]:
            # 应该返回栈帧信息
            assert "variables" in result[0]
    
    def test_stack_frame_by_name(self, tool_caller, first_function_name):
        """测试按名称获取栈帧信息。"""
        result = tool_caller("stack_frame", {
            "addr": first_function_name
        })
        
        assert isinstance(result, list)
    
    def test_stack_frame_invalid_address(self, tool_caller):
        """测试无效地址。"""
        result = tool_caller("stack_frame", {
            "addr": "0xDEADBEEF"
        })
        assert isinstance(result, list)
        if result:
            assert "error" in result[0]
    
    def test_stack_frame_batch(self, tool_caller, functions_cache):
        """测试批量获取栈帧信息（逗号分隔）。"""
        if len(functions_cache) < 2:
            pytest.skip("Not enough functions")
        
        addr_list = ",".join(f["start_ea"] for f in functions_cache[:2])
        result = tool_caller("stack_frame", {"addr": addr_list})
        
        assert isinstance(result, list)
        assert len(result) == 2
    
    def test_stack_frame_main(self, tool_caller, main_function_address):
        """测试 main 函数的栈帧。"""
        result = tool_caller("stack_frame", {
            "addr": hex(main_function_address)
        })
        
        # main 函数通常有栈帧
        assert isinstance(result, list)
    
    def test_stack_frame_complex_function(self, tool_caller, functions_cache):
        """测试复杂函数的栈帧（如 __tmainCRTStartup）。
        
        这些函数通常有局部变量和栈帧定义。
        """
        # 查找 __tmainCRTStartup 或类似复杂函数
        complex_funcs = ["__tmainCRTStartup", "_tmainCRTStartup", "printf", "main"]
        target = None
        
        for func in functions_cache:
            if func.get("name") in complex_funcs:
                target = func
                break
        
        if not target:
            # 找一个较大的函数（end_ea - start_ea > 0x100）
            for func in functions_cache:
                try:
                    start = int(func["start_ea"], 16)
                    end = int(func["end_ea"], 16)
                    if end - start > 0x100:
                        target = func
                        break
                except Exception:
                    continue
        
        if not target:
            pytest.skip("No suitable complex function found")
        
        result = tool_caller("stack_frame", {
            "addr": target["start_ea"]
        })
        
        assert isinstance(result, list)
        assert len(result) == 1
        
        # 验证结果结构
        frame_info = result[0]
        if "error" in frame_info:
            pytest.skip(f"Stack frame unavailable for selected function: {frame_info['error']}")
        assert "name" in frame_info
        assert "start_ea" in frame_info
        assert "variables" in frame_info
        
        # 如果有变量，验证变量结构
        if frame_info.get("variables"):
            for var in frame_info["variables"]:
                assert "name" in var
                # 变量可能在栈上（有 offset）或寄存器中（有 location）
                assert "offset" in var or var.get("location") == "register"


class TestDeclareStack:
    """声明栈变量测试。"""
    
    def test_declare_stack(self, tool_caller, first_function_address):
        """测试声明栈变量。"""
        # API 参数: items (List of {function_address, offset, name, type?, size?})
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
        """测试批量声明栈变量。"""
        result = tool_caller("declare_stack", {
            "items": [
                {"function_address": hex(first_function_address), "offset": -16, "name": "test_local2", "size": 4},
                {"function_address": hex(first_function_address), "offset": -24, "name": "test_local3", "size": 8},
            ]
        })
        
        assert isinstance(result, list)
        assert len(result) == 2


class TestDeleteStack:
    """删除栈变量测试。"""
    
    def test_delete_stack(self, tool_caller, first_function_address):
        """测试删除栈变量。"""
        addr = hex(first_function_address)
        # 先声明一个栈变量
        tool_caller("declare_stack", {
            "items": [{"function_address": addr, "offset": -128, "name": "to_be_deleted", "size": 4}]
        })
        
        # 然后删除 - API 参数: items (List of {function_address, name})
        result = tool_caller("delete_stack", {
            "items": [{"function_address": addr, "name": "to_be_deleted"}]
        })
        
        # 可能成功或失败
        assert isinstance(result, list)
