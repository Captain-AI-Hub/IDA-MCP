"""MCP Resources API - REST-like URI 模式访问 IDB 状态。

提供 MCP Resources:
    - ida://idb/metadata          IDB 元数据
    - ida://functions/{pattern}   函数列表 (可过滤)
    - ida://function/{addr}       单个函数详情
    - ida://strings/{pattern}     字符串列表 (可过滤)
    - ida://globals/{pattern}     全局变量列表 (可过滤)
    - ida://types/{pattern}       类型列表 (可过滤)
    - ida://segments              段列表
    - ida://imports               导入列表
    - ida://exports               导出列表
    - ida://xrefs/to/{addr}       交叉引用 (到)
    - ida://xrefs/from/{addr}     交叉引用 (从)
    - ida://memory/{addr}?size=N  内存读取
"""
from __future__ import annotations

from typing import Optional, List, Dict, Any
import re

from .rpc import resource
from .sync import idaread
from .utils import hex_addr

# IDA 模块导入
import idaapi  # type: ignore
import idautils  # type: ignore
import ida_funcs  # type: ignore
import ida_segment  # type: ignore
import ida_bytes  # type: ignore
import ida_typeinf  # type: ignore
import ida_nalt  # type: ignore
import ida_entry  # type: ignore


# ============================================================================
# IDB 元数据
# ============================================================================

@resource(uri="ida://idb/metadata")
@idaread
def idb_metadata_resource() -> dict:
    """IDB file info via ida://idb/metadata URI."""
    from .api_core import get_metadata
    return get_metadata.__wrapped__()


# ============================================================================
# 函数
# ============================================================================

@resource(uri="ida://functions")
@idaread
def functions_resource() -> list:
    """All functions via ida://functions URI."""
    return _list_functions_internal(None)


@resource(uri="ida://functions/{pattern}")
@idaread
def functions_pattern_resource(pattern: str = "*") -> list:
    """Functions matching pattern via ida://functions/{pattern} URI."""
    return _list_functions_internal(pattern)


def _list_functions_internal(pattern: Optional[str]) -> list:
    """内部: 列出函数。"""
    from .utils import pattern_filter
    
    functions: List[dict] = []
    try:
        for ea in idautils.Functions():
            f = ida_funcs.get_func(ea)
            if not f:
                continue
            name = idaapi.get_func_name(ea)
            functions.append({
                "name": name,
                "start_ea": hex_addr(f.start_ea),
                "end_ea": hex_addr(f.end_ea),
                "size": hex_addr(int(f.end_ea) - int(f.start_ea)),
            })
    except Exception:
        pass
    
    functions.sort(key=lambda x: int(x['start_ea'], 16))
    
    if pattern and pattern != "*":
        functions = pattern_filter(functions, 'name', pattern)
    
    return functions


@resource(uri="ida://function/{addr}")
@idaread
def function_detail_resource(addr: str) -> dict:
    """Function details via ida://function/{addr} URI."""
    from .utils import parse_address
    
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address"}
    
    try:
        f = ida_funcs.get_func(parsed["value"])
    except Exception:
        f = None
    
    if not f:
        return {"error": "function not found"}
    
    name = idaapi.get_func_name(f.start_ea)
    
    return {
        "name": name,
        "start_ea": hex_addr(f.start_ea),
        "end_ea": hex_addr(f.end_ea),
        "size": hex_addr(int(f.end_ea) - int(f.start_ea)),
    }


# ============================================================================
# 字符串
# ============================================================================

@resource(uri="ida://strings")
@idaread
def strings_resource() -> list:
    """All strings via ida://strings URI."""
    return _list_strings_internal(None)


@resource(uri="ida://strings/{pattern}")
@idaread
def strings_pattern_resource(pattern: str = "*") -> list:
    """Strings matching pattern via ida://strings/{pattern} URI."""
    return _list_strings_internal(pattern)


def _list_strings_internal(pattern: Optional[str]) -> list:
    """内部: 列出字符串 (使用缓存)。"""
    from .api_core import _get_strings_cache
    
    substr = (pattern or '').lower() if pattern and pattern != "*" else ''
    cached = _get_strings_cache()
    
    if substr:
        items = [
            {'ea': ea, 'length': length, 'text': text}
            for ea, length, _stype, text in cached
            if substr in text.lower()
        ]
    else:
        items = [
            {'ea': ea, 'length': length, 'text': text}
            for ea, length, _stype, text in cached
        ]
    
    return items


# ============================================================================
# 全局变量
# ============================================================================

@resource(uri="ida://globals")
@idaread
def globals_resource() -> list:
    """All global symbols via ida://globals URI."""
    return _list_globals_internal(None)


@resource(uri="ida://globals/{pattern}")
@idaread
def globals_pattern_resource(pattern: str = "*") -> list:
    """Global symbols matching pattern via ida://globals/{pattern} URI."""
    return _list_globals_internal(pattern)


def _list_globals_internal(pattern: Optional[str]) -> list:
    """内部: 列出全局变量。"""
    from .utils import pattern_filter
    
    entries: List[dict] = []
    try:
        for ea, name in idautils.Names():
            try:
                f = ida_funcs.get_func(ea)
                if f and int(f.start_ea) == int(ea):
                    continue
            except Exception:
                pass
            
            item_size = None
            try:
                item_size = ida_bytes.get_item_size(ea)
            except Exception:
                item_size = None
            
            entries.append({
                "name": name,
                "ea": hex_addr(ea),
                "size": item_size,
            })
    except Exception:
        pass
    
    entries.sort(key=lambda x: int(x['ea'], 16))
    
    if pattern and pattern != "*":
        entries = pattern_filter(entries, 'name', pattern)
    
    return entries


# ============================================================================
# 类型
# ============================================================================

@resource(uri="ida://types")
@idaread
def types_resource() -> list:
    """All local types via ida://types URI."""
    return _list_types_internal(None)


@resource(uri="ida://types/{pattern}")
@idaread
def types_pattern_resource(pattern: str = "*") -> list:
    """Local types matching pattern via ida://types/{pattern} URI."""
    return _list_types_internal(pattern)


def _list_types_internal(pattern: Optional[str]) -> list:
    """内部: 列出本地类型。"""
    from .utils import pattern_filter
    
    items: List[dict] = []
    try:
        qty = ida_typeinf.get_ordinal_qty()  # type: ignore
    except Exception:
        qty = 0
    
    for ordinal in range(1, qty + 1):
        try:
            name = ida_typeinf.get_numbered_type_name(idaapi.cvar.idati, ordinal)  # type: ignore
        except Exception:
            name = None
        if not name:
            continue
        
        decl = None
        try:
            tif = ida_typeinf.tinfo_t()
            ida_typeinf.get_numbered_type(idaapi.cvar.idati, ordinal, tif)  # type: ignore
            try:
                decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, '')  # type: ignore
            except Exception:
                decl = None
        except Exception:
            decl = None
        
        if decl is None:
            decl = name
        if len(decl) > 256:
            decl = decl[:256] + '...'
        
        items.append({
            'ordinal': ordinal,
            'name': name,
            'decl': decl,
        })
    
    if pattern and pattern != "*":
        items = pattern_filter(items, 'name', pattern)
    
    return items


# ============================================================================
# 段
# ============================================================================

@resource(uri="ida://segments")
@idaread
def segments_resource() -> list:
    """All segments via ida://segments URI."""
    segments: List[dict] = []
    
    try:
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if not seg:
                continue
            
            name = None
            try:
                name = ida_segment.get_segm_name(seg)
            except Exception:
                name = None
            
            segments.append({
                "index": i,
                "name": name,
                "start_ea": hex_addr(seg.start_ea),
                "end_ea": hex_addr(seg.end_ea),
                "size": hex_addr(int(seg.end_ea) - int(seg.start_ea)),
                "type": seg.type,
                "perm": seg.perm,
            })
    except Exception:
        pass
    
    return segments


# ============================================================================
# 导入
# ============================================================================

@resource(uri="ida://imports")
@idaread
def imports_resource() -> list:
    """All imports via ida://imports URI."""
    imports: List[dict] = []
    
    try:
        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            name = idaapi.get_import_module_name(i)
            
            def imp_cb(ea, name, ordinal):
                imports.append({
                    "module_index": i,
                    "module_name": idaapi.get_import_module_name(i),
                    "ea": hex_addr(ea),
                    "name": name,
                    "ordinal": ordinal,
                })
                return True
            
            idaapi.enum_import_names(i, imp_cb)
    except Exception:
        pass
    
    return imports


# ============================================================================
# 导出
# ============================================================================

@resource(uri="ida://exports")
@idaread
def exports_resource() -> list:
    """All exports via ida://exports URI."""
    exports: List[dict] = []
    
    try:
        qty = 0
        try:
            qty = idaapi.get_entry_qty()
        except Exception:
            qty = 0
        
        for i in range(qty):
            try:
                ordv = idaapi.get_entry_ordinal(i)
                ea = idaapi.get_entry(ordv)
                name = None
                try:
                    name = idaapi.get_entry_name(ordv)
                except Exception:
                    name = None
                if not name:
                    try:
                        name = idaapi.get_name(ea)
                    except Exception:
                        name = None
                
                exports.append({
                    'ordinal': int(ordv),
                    'ea': hex_addr(ea),
                    'name': name,
                })
            except Exception:
                continue
    except Exception:
        pass
    
    return exports


# ============================================================================
# 交叉引用
# ============================================================================

@resource(uri="ida://xrefs/to/{addr}")
@idaread
def xrefs_to_resource(addr: str) -> dict:
    """Cross-references TO address via ida://xrefs/to/{addr} URI."""
    from .utils import parse_address
    
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address"}
    
    address = parsed["value"]
    xrefs: List[dict] = []
    
    try:
        for xr in idautils.XrefsTo(address, 0):
            try:
                frm = int(getattr(xr, 'frm', 0))
                t = int(getattr(xr, 'type', 0))
                iscode = False
                try:
                    if hasattr(xr, 'iscode'):
                        iscode = bool(getattr(xr, 'iscode', lambda: 0)())  # type: ignore
                except Exception:
                    iscode = False
                xrefs.append({'frm': hex_addr(frm), 'type': t, 'iscode': iscode})
            except Exception:
                continue
    except Exception:
        pass
    
    return {
        "address": hex_addr(address),
        "total": len(xrefs),
        "xrefs": xrefs,
    }


@resource(uri="ida://xrefs/from/{addr}")
@idaread
def xrefs_from_resource(addr: str) -> dict:
    """Cross-references FROM address via ida://xrefs/from/{addr} URI."""
    from .utils import parse_address
    
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address"}
    
    address = parsed["value"]
    xrefs: List[dict] = []
    
    try:
        for xr in idautils.XrefsFrom(address, 0):
            try:
                to = int(getattr(xr, 'to', 0))
                t = int(getattr(xr, 'type', 0))
                iscode = False
                try:
                    if hasattr(xr, 'iscode'):
                        iscode = bool(getattr(xr, 'iscode', lambda: 0)())  # type: ignore
                except Exception:
                    iscode = False
                xrefs.append({'to': hex_addr(to), 'type': t, 'iscode': iscode})
            except Exception:
                continue
    except Exception:
        pass
    
    return {
        "address": hex_addr(address),
        "total": len(xrefs),
        "xrefs": xrefs,
    }


# ============================================================================
# 内存
# ============================================================================

@resource(uri="ida://memory/{addr}")
@idaread
def memory_resource(addr: str, size: int = 16) -> dict:
    """Read memory via ida://memory/{addr}?size=N URI."""
    from .utils import parse_address
    
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address"}
    
    address = parsed["value"]
    
    if size <= 0:
        size = 16
    if size > 4096:
        size = 4096
    
    try:
        data = idaapi.get_bytes(address, size)
        if data is None:
            return {"error": "failed to read", "address": hex_addr(address)}
        
        byte_list = list(data)
        hex_str = ' '.join(f'{b:02X}' for b in byte_list)
        
        return {
            "address": hex_addr(address),
            "size": len(byte_list),
            "bytes": byte_list,
            "hex": hex_str,
        }
    except Exception as e:
        return {"error": str(e), "address": hex_addr(address)}
