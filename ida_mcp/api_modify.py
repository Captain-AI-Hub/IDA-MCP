"""修改 API - 注释、重命名、补丁等。

提供工具:
    - set_comment          设置注释 (批量)
    - rename_function      重命名函数
    - rename_local_variable 重命名局部变量
    - rename_global_variable 重命名全局变量
    - patch_bytes          字节补丁
"""
from __future__ import annotations

import re
from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .strings_cache import invalidate_strings_cache
from .sync import idaread, idawrite, wait_for_auto_analysis
from .utils import parse_address, is_valid_c_identifier, normalize_list_input, hex_addr

# IDA 模块导入
try:
    import idaapi  # type: ignore
    import ida_bytes  # type: ignore
    import ida_funcs  # type: ignore
    import ida_name  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_kernwin  # type: ignore
    import idc  # type: ignore
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_name = None
    ida_hexrays = None
    ida_kernwin = None
    idc = None
from contextlib import contextmanager


def _invalidate_strings_cache() -> None:
    invalidate_strings_cache()

@contextmanager
def suppress_ida_warnings():
    """临时启用 batch 模式以禁用 IDA 的警告弹窗。"""
    old_batch = ida_kernwin.cvar.batch
    ida_kernwin.cvar.batch = 1
    try:
        yield
    finally:
        ida_kernwin.cvar.batch = old_batch

@tool
@idawrite
def set_comment(
    items: Annotated[List[Dict[str, Any]], "List of {address, comment} objects"],
) -> List[dict]:
    """Set comments at address(es). Each item: {address, comment}."""
    results = []
    for item in items:
        address = item.get("address")
        comment = item.get("comment", "")
        
        if address is None:
            results.append({"error": "invalid address", "address": address})
            continue
        
        parsed = parse_address(address)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "address": address})
            continue
        
        addr_int = parsed["value"]
        
        try:
            old = idaapi.get_cmt(addr_int, False)
        except Exception:
            old = None
        
        new_text = str(comment).strip() if comment else ""
        if len(new_text) > 1024:
            new_text = new_text[:1024]
        
        try:
            ok = idaapi.set_cmt(addr_int, new_text or '', False)
        except Exception as e:
            results.append({"error": f"set failed: {e}", "address": hex_addr(addr_int)})
            continue
        
        results.append({
            "address": hex_addr(addr_int),
            "old": old,
            "new": new_text if new_text else None,
            "changed": old != (new_text if new_text else None) and ok,
            "error": None,
        })
    
    return results




# ============================================================================
# 重命名
# ============================================================================

@tool
@idawrite
def rename_function(
    address: Annotated[Union[int, str], "Function name or address (hex/decimal)"],
    new_name: Annotated[str, "New function name (valid C identifier)"],
) -> dict:
    """Rename function. Accepts function name or address."""
    if address is None:
        return {"error": "invalid address"}
    if not new_name:
        return {"error": "empty new_name"}
    
    new_name_clean = new_name.strip()
    if len(new_name_clean) > 255:
        new_name_clean = new_name_clean[:255]
    
    if not is_valid_c_identifier(new_name_clean):
        return {"error": "new_name not a valid C identifier"}
    
    # 使用 batch 模式包裹整个操作以抑制所有警告消息
    with suppress_ida_warnings():
        f = None
        addr = None
        
        # 方法 1: 尝试作为函数名查找
        if isinstance(address, str):
            try:
                ea = idaapi.get_name_ea(idaapi.BADADDR, address)
                if ea != idaapi.BADADDR:
                    f = ida_funcs.get_func(ea)
                    if f:
                        addr = ea
            except Exception:
                pass
        
        # 方法 2: 尝试作为地址解析
        if not f:
            parsed = parse_address(str(address))
            if parsed["ok"] and parsed["value"] is not None:
                addr = parsed["value"]
                try:
                    f = ida_funcs.get_func(addr)
                except Exception:
                    pass
        
        if not f:
            return {
                "error": "function not found",
                "query": str(address),
                "parsed_addr": hex_addr(addr) if addr is not None else None,
            }
        
        start_ea = int(f.start_ea)
        
        try:
            old_name = idaapi.get_func_name(f.start_ea)
        except Exception:
            old_name = None
        
        # 如果新旧名称相同，跳过重命名
        if old_name == new_name_clean:
            return {
                "start_ea": hex_addr(start_ea),
                "old_name": old_name,
                "new_name": new_name_clean,
                "changed": False,
                "note": "name unchanged",
            }
        
        try:
            # SN_NOWARN | SN_NOCHECK 用于进一步确保无警告
            flags = idaapi.SN_NOWARN | idaapi.SN_NOCHECK
            ok = idaapi.set_name(start_ea, new_name_clean, flags)
        except Exception as e:
            return {"error": f"set_name failed: {e}"}
        
        return {
            "start_ea": hex_addr(start_ea),
            "old_name": old_name,
            "new_name": new_name_clean,
            "changed": bool(ok) and old_name != new_name_clean,
        }


@tool
@idawrite
def rename_local_variable(
    function_address: Annotated[Union[int, str], "Function start or internal address (hex or decimal)"],
    old_name: Annotated[str, "Old local variable name (exact match)"],
    new_name: Annotated[str, "New variable name (valid C identifier)"],
) -> dict:
    """Rename local variable (Hex-Rays)."""
    wait_for_auto_analysis()
    if function_address is None:
        return {"error": "invalid function_address"}
    if not old_name:
        return {"error": "empty old_name"}
    if not new_name:
        return {"error": "empty new_name"}
    
    parsed = parse_address(str(function_address))
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid function_address"}
    
    addr = parsed["value"]
    
    new_name_clean = new_name.strip()
    if len(new_name_clean) > 255:
        new_name_clean = new_name_clean[:255]
    
    if not is_valid_c_identifier(new_name_clean):
        return {"error": "new_name not a valid C identifier"}
    
    # 初始化 Hex-Rays
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"error": "failed to init hex-rays"}
    except Exception:
        return {"error": "failed to init hex-rays"}
    
    try:
        f = ida_funcs.get_func(addr)
    except Exception:
        f = None
    if not f:
        return {"error": "function not found"}
    
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"error": f"decompile failed: {e}"}
    if not cfunc:
        return {"error": "decompile returned None"}
    
    # 查找变量
    target = None
    try:
        for lv in cfunc.lvars:  # type: ignore
            try:
                if lv.name == old_name:
                    target = lv
                    break
            except Exception:
                continue
    except Exception:
        return {"error": "iterate lvars failed"}
    
    if not target:
        return {"error": "local variable not found"}
    
    # 重命名
    try:
        if hasattr(cfunc, "set_user_lvar_name"):
            ok = cfunc.set_user_lvar_name(target, new_name_clean)  # type: ignore[attr-defined]
        elif hasattr(cfunc, "set_lvar_name"):
            ok = cfunc.set_lvar_name(target, new_name_clean, 0)  # type: ignore[attr-defined]
        else:
            target.name = new_name_clean
            ok = True
    except Exception as e:
        return {"error": f"set_lvar_name failed: {e}"}
    
    try:
        fname = idaapi.get_func_name(f.start_ea)
    except Exception:
        fname = "?"
    
    return {
        "function": fname,
        "start_ea": hex_addr(f.start_ea),
        "old_name": old_name,
        "new_name": new_name_clean,
        "changed": bool(ok),
    }


@tool
@idawrite
def rename_global_variable(
    old_name: Annotated[str, "Existing global symbol name (exact match)"],
    new_name: Annotated[str, "New name (valid C identifier)"],
) -> dict:
    """Rename global variable."""
    if not old_name:
        return {"error": "empty old_name"}
    if not new_name:
        return {"error": "empty new_name"}
    
    new_name_clean = new_name.strip()
    if len(new_name_clean) > 255:
        new_name_clean = new_name_clean[:255]
    
    if not is_valid_c_identifier(new_name_clean):
        return {"error": "new_name not a valid C identifier"}
    
    try:
        ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    except Exception:
        ea = idaapi.BADADDR
    
    if ea == idaapi.BADADDR:
        return {"error": "global not found"}
    
    # 若是函数起始地址则拒绝
    try:
        f = ida_funcs.get_func(ea)
        if f and int(f.start_ea) == int(ea):
            return {"error": "target is a function start (use function rename)"}
    except Exception:
        pass
    
    # 如果新旧名称相同，跳过重命名
    if old_name == new_name_clean:
        return {
            "ea": hex_addr(ea),
            "old_name": old_name,
            "new_name": new_name_clean,
            "changed": False,
            "note": "name unchanged",
        }
    
    try:
        # 使用 batch 模式完全禁用弹窗
        with suppress_ida_warnings():
            flags = idaapi.SN_NOWARN | idaapi.SN_NOCHECK
            ok = idaapi.set_name(ea, new_name_clean, flags)
    except Exception as e:
        return {"error": f"set_name failed: {e}"}
    
    return {
        "ea": hex_addr(ea),
        "old_name": old_name,
        "new_name": new_name_clean,
        "changed": bool(ok),
    }


# ============================================================================
# 字节补丁
# ============================================================================

@tool
@idawrite
def patch_bytes(
    items: Annotated[List[Dict[str, Any]], "List of {address, bytes: [int,...] or hex_string}"],
) -> List[dict]:
    """Patch bytes at address(es). Each item: {address, bytes}.
    
    bytes can be:
    - List of integers: [0x90, 0x90, 0x90]
    - Hex string: "90 90 90" or "909090"
    """
    results = []
    cache_invalidated = False
    
    for item in items:
        address = item.get("address")
        data = item.get("bytes")
        
        if address is None:
            results.append({"error": "invalid address", "item": item})
            continue
        
        parsed = parse_address(address)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "address": address})
            continue
        
        addr_int = parsed["value"]
        
        # 解析字节数据
        byte_list: List[int] = []
        
        if isinstance(data, list):
            # 直接是整数列表
            try:
                byte_list = [int(b) & 0xFF for b in data]
            except (ValueError, TypeError) as e:
                results.append({"error": f"invalid bytes: {e}", "address": hex_addr(addr_int)})
                continue
        elif isinstance(data, str):
            # 十六进制字符串
            hex_str = data.strip().replace(' ', '')
            if len(hex_str) % 2 != 0:
                results.append({"error": "hex string length must be even", "address": hex_addr(addr_int)})
                continue
            try:
                byte_list = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
            except ValueError as e:
                results.append({"error": f"invalid hex string: {e}", "address": hex_addr(addr_int)})
                continue
        else:
            results.append({"error": "bytes must be list or hex string", "address": hex_addr(addr_int)})
            continue
        
        if not byte_list:
            results.append({"error": "empty bytes", "address": hex_addr(addr_int)})
            continue
        
        if len(byte_list) > 1024:
            results.append({"error": "bytes too long (max 1024)", "address": hex_addr(addr_int)})
            continue
        
        # 读取原始字节
        old_bytes = None
        try:
            old_data = ida_bytes.get_bytes(addr_int, len(byte_list))
            if old_data:
                old_bytes = ' '.join(f'{b:02X}' for b in old_data)
        except Exception:
            pass
        
        # 写入补丁
        patched_count = 0
        errors: List[str] = []
        
        for i, b in enumerate(byte_list):
            try:
                ida_bytes.patch_byte(addr_int + i, b)
                patched_count += 1
            except Exception as e:
                errors.append(f"offset {i}: {e}")
                break
        
        # 读取验证
        new_bytes = None
        try:
            new_data = ida_bytes.get_bytes(addr_int, len(byte_list))
            if new_data:
                new_bytes = ' '.join(f'{b:02X}' for b in new_data)
        except Exception:
            pass
        
        result: dict = {
            "address": hex_addr(addr_int),
            "size": len(byte_list),
            "patched": patched_count,
            "old_bytes": old_bytes,
            "new_bytes": new_bytes,
            "error": errors[0] if errors else None,
        }
        
        results.append(result)
        if patched_count > 0 and not cache_invalidated:
            _invalidate_strings_cache()
            cache_invalidated = True
    
    return results
