"""栈帧 API - 栈帧操作。

提供工具:
    - stack_frame          获取栈帧变量
    - declare_stack        创建栈变量
    - delete_stack         删除栈变量
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread, idawrite, wait_for_auto_analysis
from .utils import parse_address, normalize_list_input, hex_addr

# IDA 模块导入
try:
    import idaapi  # type: ignore
    import ida_funcs  # type: ignore
    import ida_frame  # type: ignore
    import ida_typeinf  # type: ignore
    import ida_hexrays  # type: ignore
except ImportError:
    idaapi = None
    ida_funcs = None
    ida_frame = None
    ida_typeinf = None
    ida_hexrays = None

from . import compat  # IDA 8.x/9.x 兼容层

# 检测 IDA 版本
IDA_VERSION = getattr(idaapi, 'IDA_SDK_VERSION', 0)
IDA9_OR_LATER = IDA_VERSION >= 900


# ============================================================================
# 栈帧信息
# ============================================================================

@tool
@idaread
def stack_frame(
    addr: Annotated[Union[int, str], "Function address(es) - single or comma-separated"],
) -> List[dict]:
    """Get stack frame variables for function(s)."""
    wait_for_auto_analysis()
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        result = _stack_frame_single(query)
        results.append(result)
    
    return results


def _stack_frame_single(query: str) -> dict:
    """获取单个函数的栈帧信息。"""
    parsed = parse_address(query)
    if not parsed["ok"]:
        # 尝试作为函数名
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, query)
            if ea == idaapi.BADADDR:
                return {"error": "not found", "query": query}
        except Exception:
            return {"error": "invalid address", "query": query}
    else:
        ea = parsed["value"]
    
    if ea is None:
        return {"error": "invalid address", "query": query}
    
    try:
        f = ida_funcs.get_func(ea)
    except Exception:
        f = None
    if not f:
        return {"error": "function not found", "query": query}
    
    try:
        fname = idaapi.get_func_name(f.start_ea)
    except Exception:
        fname = "?"
    
    frame_variables: List[dict] = []
    local_variables: List[dict] = []
    hexrays_error = None
    
    # 获取 IDA 栈帧结构
    # 方法 1: IDA 9.x - 使用 func.frame + tinfo_t
    if IDA9_OR_LATER:
        try:
            tif = ida_typeinf.tinfo_t()
            if hasattr(f, 'frame') and f.frame and tif.get_type_by_tid(f.frame):
                if tif.is_udt():
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        for udm in udt:
                            try:
                                if hasattr(udm, 'is_gap') and udm.is_gap():
                                    continue
                                frame_variables.append({
                                    "name": udm.name,
                                    "offset": udm.offset // 8,
                                    "size": udm.size // 8,
                                    "type": str(udm.type) if udm.type else None,
                                })
                            except Exception:
                                continue
        except Exception:
            pass
    
    # 方法 2: 传统栈帧 (ida_frame.get_frame) - 作为回退
    if not frame_variables:
        frame = None
        try:
            frame = ida_frame.get_frame(f)  # type: ignore
        except Exception:
            frame = None
        
        if frame:
            try:
                frame_size = compat.get_struc_size(frame)
                offset = 0
                while offset < frame_size:
                    member = compat.get_member(frame, offset)
                    if member:
                        try:
                            member_name = compat.get_member_name(member.id)
                            member_size = compat.get_member_size(member)
                            member_offset = member.soff
                            
                            member_type = None
                            try:
                                tif = ida_typeinf.tinfo_t()
                                if compat.get_member_tinfo(tif, member):
                                    member_type = str(tif)
                            except Exception:
                                pass
                            
                            frame_variables.append({
                                "name": member_name,
                                "offset": member_offset,
                                "size": member_size,
                                "type": member_type,
                            })
                            
                            offset = member.soff + member_size
                        except Exception:
                            offset += 1
                    else:
                        offset += 1
            except Exception:
                pass
    
    # 获取 Hex-Rays 局部变量（始终尝试，获取所有局部变量）
    try:
        if ida_hexrays.init_hexrays_plugin():  # type: ignore
            cfunc = ida_hexrays.decompile(f.start_ea)  # type: ignore
            if cfunc and cfunc.lvars:  # type: ignore
                for lv in cfunc.lvars:  # type: ignore
                    try:
                        lv_type = None
                        try:
                            t = lv.type()
                            if t:
                                lv_type = str(t)
                        except Exception:
                            pass
                        
                        # 判断变量位置
                        is_stk = hasattr(lv, 'is_stk_var') and lv.is_stk_var()
                        is_reg = hasattr(lv, 'is_reg_var') and lv.is_reg_var()
                        
                        var_info: dict = {
                            "name": lv.name,
                            "type": lv_type,
                            "size": lv.width if hasattr(lv, 'width') else None,
                        }
                        
                        if is_stk:
                            var_info["location"] = "stack"
                            var_info["offset"] = getattr(lv, 'stkoff', None)
                        elif is_reg:
                            var_info["location"] = "register"
                        else:
                            var_info["location"] = "other"
                        
                        local_variables.append(var_info)
                    except Exception:
                        continue
        else:
            hexrays_error = "failed to init hex-rays"
    except Exception:
        hexrays_error = "hex-rays decompile failed"
    
    # 如果两者都为空
    if not frame_variables and not local_variables:
        if hexrays_error:
            return {
                "query": query,
                "name": fname,
                "start_ea": hex_addr(f.start_ea),
                "variables": [],
                "error": hexrays_error,
            }
        return {
            "query": query,
            "name": fname,
            "start_ea": hex_addr(f.start_ea),
            "variables": [],
            "note": "no stack frame or local variables",
            "error": None,
        }
    
    # 返回结构：优先使用 local_variables（更完整），frame_variables 作为补充
    result: dict = {
        "query": query,
        "name": fname,
        "start_ea": hex_addr(f.start_ea),
        "error": None,
    }
    
    # 主要返回 Hex-Rays 局部变量（如果有）
    if local_variables:
        result["variables"] = local_variables
        result["method"] = "hexrays"
        # 如果也有栈帧结构，作为补充信息
        if frame_variables:
            result["frame_structure"] = frame_variables
    else:
        # 只有栈帧结构
        result["variables"] = frame_variables
        result["method"] = "ida_frame"
    
    return result


# ============================================================================
# 栈变量创建/删除
# ============================================================================

@tool
@idawrite
def declare_stack(
    items: Annotated[List[Dict[str, Any]], "List of {function_address, offset, name, type?, size?}"],
) -> List[dict]:
    """Create stack variable(s) at specified offset(s)."""
    results = []
    
    for item in items:
        func_addr = item.get("function_address")
        offset = item.get("offset")
        name = item.get("name")
        var_type = item.get("type")
        size = item.get("size", 4)
        
        if func_addr is None or offset is None or not name:
            results.append({"error": "missing required fields", "item": item})
            continue
        
        # 解析函数地址
        parsed = parse_address(func_addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid function_address", "item": item})
            continue
        
        try:
            f = ida_funcs.get_func(parsed["value"])
        except Exception:
            f = None
        if not f:
            results.append({"error": "function not found", "item": item})
            continue
        
        # 获取栈帧
        frame = None
        try:
            frame = ida_frame.get_frame(f)  # type: ignore
        except Exception:
            frame = None
        
        if not frame:
            results.append({"error": "no stack frame", "item": item})
            continue
        
        # 创建栈变量
        try:
            # 添加成员到栈帧
            ok = compat.add_struc_member(
                frame,
                name,
                offset,
                idaapi.FF_DWORD if size == 4 else (idaapi.FF_QWORD if size == 8 else idaapi.FF_BYTE),
                None,
                size
            )
            results.append({
                "function_address": parsed["value"],
                "offset": offset,
                "name": name,
                "created": ok == 0,
                "error": None if ok == 0 else f"add_struc_member returned {ok}",
            })
        except Exception as e:
            results.append({"error": str(e), "item": item})
    
    return results


@tool
@idawrite
def delete_stack(
    items: Annotated[List[Dict[str, Any]], "List of {function_address, name}"],
) -> List[dict]:
    """Delete stack variable(s) by name."""
    results = []
    
    for item in items:
        func_addr = item.get("function_address")
        name = item.get("name")
        
        if func_addr is None or not name:
            results.append({"error": "missing required fields", "item": item})
            continue
        
        parsed = parse_address(func_addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid function_address", "item": item})
            continue
        
        try:
            f = ida_funcs.get_func(parsed["value"])
        except Exception:
            f = None
        if not f:
            results.append({"error": "function not found", "item": item})
            continue
        
        frame = None
        try:
            frame = ida_frame.get_frame(f)  # type: ignore
        except Exception:
            frame = None
        
        if not frame:
            results.append({"error": "no stack frame", "item": item})
            continue
        
        # 查找并删除成员
        try:
            member = compat.get_member_by_name(frame, name)
            if member:
                ok = compat.del_struc_member(frame, member.soff)
                results.append({
                    "function_address": parsed["value"],
                    "name": name,
                    "deleted": bool(ok),
                    "error": None,
                })
            else:
                results.append({"error": "member not found", "item": item})
        except Exception as e:
            results.append({"error": str(e), "item": item})
    
    return results
