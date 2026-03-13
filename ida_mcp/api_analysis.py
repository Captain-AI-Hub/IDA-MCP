"""分析 API - 反编译、反汇编、交叉引用等。

提供工具:
    - decompile           反编译函数 (Hex-Rays)
    - disasm              反汇编函数
    - linear_disassemble  线性反汇编
    - xrefs_to            交叉引用 (到)
    - xrefs_from          交叉引用 (从)
    - xrefs_to_field      结构体字段引用
    - find_bytes          字节模式搜索
    - get_basic_blocks    获取基本块
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread, wait_for_auto_analysis
from .utils import parse_address, hex_addr

# IDA 模块导入
try:
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import ida_funcs  # type: ignore
    import ida_bytes  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_search  # type: ignore
    import ida_gdl  # type: ignore
except ImportError:
    idaapi = None
    idautils = None
    ida_funcs = None
    ida_bytes = None
    ida_hexrays = None
    ida_search = None
    ida_gdl = None

from . import compat  # IDA 8.x/9.x 兼容层


# ============================================================================
# 反编译
# ============================================================================

@tool
@idaread
def decompile(
    addr: Annotated[Union[int, str], "Function address or name (single or comma-separated)"],
) -> List[dict]:
    """Decompile function(s) at given address(es). Requires Hex-Rays."""
    wait_for_auto_analysis()
    # 解析地址列表
    from .utils import normalize_list_input
    queries = normalize_list_input(addr)
    
    results = []
    for query in queries:
        result = _decompile_single(query)
        results.append(result)
    
    return results


def _decompile_single(query: str) -> dict:
    """反编译单个函数。"""
    # 解析地址
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
    
    # 初始化 Hex-Rays
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"error": "failed to init hex-rays", "query": query}
    except Exception:
        return {"error": "failed to init hex-rays", "query": query}
    
    # 获取函数
    try:
        f = ida_funcs.get_func(ea)
    except Exception:
        f = None
    if not f:
        return {"error": "function not found", "query": query}
    
    # 反编译
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"error": f"decompile failed: {e}", "query": query}
    if not cfunc:
        return {"error": "decompile returned None", "query": query}
    
    try:
        name = idaapi.get_func_name(f.start_ea)
    except Exception:
        name = "?"
    
    try:
        text = str(cfunc)
    except Exception:
        text = "<print failed>"
    
    return {
        "query": query,
        "name": name,
        "start_ea": hex_addr(f.start_ea),
        "end_ea": hex_addr(f.end_ea),
        "decompiled": text,
        "error": None,
    }




# ============================================================================
# 反汇编
# ============================================================================

@tool
@idaread
def disasm(
    addr: Annotated[Union[int, str], "Function address(es) - single or comma-separated"],
) -> List[dict]:
    """Disassemble function(s) with full details."""
    wait_for_auto_analysis()
    from .utils import normalize_list_input
    queries = normalize_list_input(addr)
    
    results = []
    for query in queries:
        result = _disasm_single(query)
        results.append(result)
    
    return results


def _disasm_single(query: str) -> dict:
    """反汇编单个函数。"""
    parsed = parse_address(query)
    if not parsed["ok"]:
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
    
    start = int(f.start_ea)
    end = int(f.end_ea)
    
    try:
        name = idaapi.get_func_name(f.start_ea)
    except Exception:
        name = "?"
    
    instructions: List[dict] = []
    for head_ea in idautils.Heads(start, end):
        try:
            flags = idaapi.get_full_flags(head_ea)
            if not idaapi.is_code(flags):
                continue
            
            insn_len = 0
            try:
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, head_ea):
                    insn_len = insn.size
            except Exception:
                insn_len = 0
            
            # 指令文本
            text = None
            try:
                text = idaapi.generate_disasm_line(head_ea, 0)
            except Exception:
                text = None
            if text is None:
                text = "?"
            
            # 指令 bytes
            b_hex = None
            if insn_len:
                try:
                    raw = ida_bytes.get_bytes(head_ea, insn_len)
                    if raw:
                        b_hex = raw.hex().upper()
                        if len(b_hex) > 32:
                            b_hex = b_hex[:32] + '...'
                except Exception:
                    b_hex = None
            
            # 注释
            cmt_parts: List[str] = []
            try:
                c1 = idaapi.get_cmt(head_ea, False)
                if c1:
                    cmt_parts.append(c1)
            except Exception:
                pass
            try:
                c2 = idaapi.get_cmt(head_ea, True)
                if c2:
                    cmt_parts.append(c2)
            except Exception:
                pass
            comment = ' // '.join(cmt_parts) if cmt_parts else None
            
            instructions.append({
                'ea': int(head_ea),
                'bytes': b_hex,
                'text': text,
                'comment': comment,
            })
        except Exception:
            continue
    
    return {
        'query': query,
        'name': name,
        'start_ea': start,
        'end_ea': end,
        'instructions': instructions,
        'error': None,
    }


# ============================================================================
# 线性反汇编
# ============================================================================

@tool
@idaread
def linear_disassemble(
    start_address: Annotated[Union[int, str], "Starting address"],
    count: Annotated[int, "Max number of instructions (1..64)"] = 16,
) -> dict:
    """Linear disassemble from arbitrary address (not limited to functions)."""
    if start_address is None:
        return {"error": "invalid start_address"}
    if count < 1 or count > 64:
        return {"error": "count out of range (1..64)"}
    
    parsed = parse_address(start_address)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": parsed["error"] or "invalid start_address"}
    
    addr_int = parsed["value"]
    if addr_int < 0:
        return {"error": "invalid start_address"}
    
    ea = int(addr_int)
    
    # 确认段存在
    try:
        if hasattr(idaapi, 'getseg') and not idaapi.getseg(ea):
            return {'error': 'no_segment'}
    except Exception:
        pass
    
    collected: List[dict] = []
    for _ in range(count):
        try:
            insn = idaapi.insn_t()
            size = 0
            try:
                if idaapi.decode_insn(insn, ea):
                    size = insn.size
            except Exception:
                size = 0
            
            if size <= 0:
                if not collected:
                    return {'error': 'decode_failed'}
                break
            
            # 读取 flags 判定 is_code
            is_code = False
            try:
                flags = idaapi.get_full_flags(ea)
                is_code = bool(idaapi.is_code(flags))
            except Exception:
                pass
            
            # 指令文本
            text = None
            try:
                text = idaapi.generate_disasm_line(ea, 0)
            except Exception:
                text = None
            if text is None:
                text = '?'
            
            # bytes
            b_hex = None
            try:
                raw = ida_bytes.get_bytes(ea, size)
                if raw:
                    b_hex = raw.hex().upper()
                    if len(b_hex) > 32:
                        b_hex = b_hex[:32] + '...'
            except Exception:
                b_hex = None
            
            collected.append({
                'ea': int(ea),
                'bytes': b_hex,
                'text': text,
                'is_code': is_code,
                'len': size,
            })
            ea += size
        except Exception:
            if not collected:
                return {'error': 'decode_failed'}
            break
    
    if not collected:
        return {'error': 'no_instructions'}
    
    result: dict = {
        'start_address': int(addr_int),
        'count': count,
        'instructions': collected,
    }
    if len(collected) >= count:
        result['truncated'] = True
    
    return result


# ============================================================================
# 交叉引用
# ============================================================================

@tool
@idaread
def xrefs_to(
    addr: Annotated[Union[int, str], "Target address(es) - single or comma-separated"],
) -> List[dict]:
    """Get all cross-references to address(es)."""
    from .utils import normalize_list_input
    queries = normalize_list_input(addr)
    
    results = []
    for query in queries:
        result = _xrefs_to_single(query)
        results.append(result)
    
    return results


def _xrefs_to_single(query: str) -> dict:
    """获取单个地址的交叉引用。"""
    parsed = parse_address(query)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address", "query": query}
    
    address = parsed["value"]
    xrefs: List[dict] = []
    
    try:
        for xr in idautils.XrefsTo(address, 0):
            try:
                frm = int(getattr(xr, 'frm', 0))
                t = int(getattr(xr, 'type', 0))
                iscode = bool(getattr(xr, 'iscode', 0))
                xrefs.append({'frm': hex_addr(frm), 'type': t, 'iscode': iscode})
            except Exception:
                continue
    except Exception as e:
        return {"error": f"xrefs failed: {e}", "query": query}
    
    return {
        "query": query,
        "address": hex_addr(address),
        "total": len(xrefs),
        "xrefs": xrefs,
        "error": None,
    }


@tool
@idaread
def xrefs_from(
    addr: Annotated[Union[int, str], "Source address(es) - single or comma-separated"],
) -> List[dict]:
    """Get all cross-references from address(es)."""
    from .utils import normalize_list_input
    queries = normalize_list_input(addr)
    
    results = []
    for query in queries:
        result = _xrefs_from_single(query)
        results.append(result)
    
    return results


def _xrefs_from_single(query: str) -> dict:
    """获取单个地址的出向交叉引用。"""
    parsed = parse_address(query)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address", "query": query}
    
    address = parsed["value"]
    xrefs: List[dict] = []
    
    try:
        for xr in idautils.XrefsFrom(address, 0):
            try:
                to = int(getattr(xr, 'to', 0))
                t = int(getattr(xr, 'type', 0))
                iscode = bool(getattr(xr, 'iscode', 0))
                xrefs.append({'to': hex_addr(to), 'type': t, 'iscode': iscode})
            except Exception:
                continue
    except Exception as e:
        return {"error": f"xrefs failed: {e}", "query": query}
    
    return {
        "query": query,
        "address": hex_addr(address),
        "total": len(xrefs),
        "xrefs": xrefs,
        "error": None,
    }


# ============================================================================
# 结构体字段引用
# ============================================================================

@tool
@idaread
def xrefs_to_field(
    struct_name: Annotated[str, "Struct name"],
    field_name: Annotated[str, "Field name"],
) -> dict:
    """Heuristic search for struct field references."""
    if not struct_name or not field_name:
        return {"error": "empty struct_name or field_name"}
    
    sid = compat.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        return {"error": "struct not found"}
    
    s = compat.get_struc(sid)
    if not s:
        return {"error": "struct not found"}
    
    # 查找成员偏移
    target_off = None
    m = compat.get_first_member(s)
    while m is not None and m != idaapi.BADADDR:
        try:
            name = compat.get_member_name(compat.get_member_id(m))
        except Exception:
            name = None
        if name == field_name:
            try:
                target_off = compat.get_member_offset(m)
            except Exception:
                target_off = None
            break
        try:
            m = compat.get_next_member(s, compat.get_member_offset(m))
        except Exception:
            break
    
    if target_off is None:
        return {"error": "field not found"}
    
    # 启发式扫描
    fname_lower = field_name.lower()
    matches: List[dict] = []
    truncated = False
    MAX_MATCH = 500
    
    try:
        for fea in idautils.Functions():
            f = ida_funcs.get_func(fea)
            if not f:
                continue
            for ea in idautils.Heads(int(f.start_ea), int(f.end_ea)):
                try:
                    flags = idaapi.get_full_flags(ea)
                    if not idaapi.is_code(flags):
                        continue
                    
                    line = None
                    try:
                        line = idaapi.generate_disasm_line(ea, 0)
                    except Exception:
                        line = None
                    
                    if not line:
                        continue
                    
                    lcline = line.lower()
                    hit = fname_lower in lcline
                    
                    if not hit:
                        pat_hex = f"0x{target_off:X}".lower()
                        if pat_hex in lcline or f"{target_off}" in lcline:
                            hit = True
                    
                    if hit:
                        matches.append({'ea': int(ea), 'line': line})
                        if len(matches) >= MAX_MATCH:
                            truncated = True
                            break
                except Exception:
                    continue
            if truncated:
                break
    except Exception:
        pass
    
    result: dict = {
        'struct': struct_name,
        'field': field_name,
        'offset': int(target_off) if target_off is not None else None,
        'matches': matches,
    }
    if truncated:
        result['truncated'] = True
    if not matches:
        result['note'] = 'no heuristic matches (may be optimized code or indirect access)'
    
    return result


# ============================================================================
# 字节模式搜索
# ============================================================================

@tool
@idaread
def find_bytes(
    pattern: Annotated[str, "Byte pattern with wildcards (e.g. '48 8B ?? ?? 48 89')"],
    start: Annotated[Optional[str], "Start address (default: min_ea)"] = None,
    end: Annotated[Optional[str], "End address (default: max_ea)"] = None,
    limit: Annotated[int, "Max results (1..1000)"] = 100,
) -> dict:
    """Search for byte pattern with wildcards (?? for any byte)."""
    wait_for_auto_analysis()
    if not pattern or not pattern.strip():
        return {"error": "empty pattern"}
    if limit < 1 or limit > 1000:
        return {"error": "limit out of range (1..1000)"}
    
    # 解析起止地址
    start_ea = None
    end_ea = None
    
    if start:
        parsed = parse_address(start)
        if parsed["ok"] and parsed["value"] is not None:
            start_ea = parsed["value"]
    
    if end:
        parsed = parse_address(end)
        if parsed["ok"] and parsed["value"] is not None:
            end_ea = parsed["value"]
    
    # 默认搜索整个数据库
    if start_ea is None:
        try:
            start_ea = idaapi.cvar.inf.min_ea  # type: ignore
        except Exception:
            try:
                start_ea = idaapi.get_inf_structure().min_ea  # type: ignore
            except Exception:
                start_ea = 0
    
    if end_ea is None:
        try:
            end_ea = idaapi.cvar.inf.max_ea  # type: ignore
        except Exception:
            try:
                end_ea = idaapi.get_inf_structure().max_ea  # type: ignore
            except Exception:
                end_ea = 0xFFFFFFFFFFFFFFFF
    
    # 解析模式字符串
    pattern_text = pattern.strip()
    
    # 转换为 IDA 搜索格式
    # IDA 使用空格分隔的十六进制字节，? 表示通配符
    # 输入: "48 8B ?? ?? 48 89" 或 "48 8B ? ? 48 89"
    # IDA 格式: "48 8B ? ? 48 89"
    parts = pattern_text.split()
    ida_pattern_parts = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p in ('??', '?'):
            ida_pattern_parts.append('?')
        else:
            # 验证是否为有效的十六进制
            try:
                int(p, 16)
                ida_pattern_parts.append(p.upper())
            except ValueError:
                return {"error": f"invalid hex byte: {p}"}
    
    if not ida_pattern_parts:
        return {"error": "empty pattern after parsing"}
    
    ida_pattern = ' '.join(ida_pattern_parts)
    
    # 搜索
    matches: List[dict] = []
    truncated = False
    
    try:
        ea = start_ea
        while ea < end_ea and len(matches) < limit:
            # 使用 ida_search.find_binary
            try:
                found = ida_search.find_binary(  # type: ignore
                    ea, end_ea, ida_pattern,
                    16,  # radix
                    ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
                )
            except Exception:
                break
            
            if found == idaapi.BADADDR:
                break
            
            # 读取匹配的字节
            match_len = len([p for p in ida_pattern_parts if p != '?'])
            # 实际匹配长度是所有部分
            actual_len = len(ida_pattern_parts)
            
            bytes_hex = None
            try:
                raw = ida_bytes.get_bytes(found, actual_len)
                if raw:
                    bytes_hex = ' '.join(f'{b:02X}' for b in raw)
            except Exception:
                pass
            
            # 获取函数信息
            func_name = None
            try:
                f = ida_funcs.get_func(found)
                if f:
                    func_name = idaapi.get_func_name(f.start_ea)
            except Exception:
                pass
            
            matches.append({
                "ea": hex_addr(found),
                "bytes": bytes_hex,
                "function": func_name,
            })
            
            ea = found + 1
        
        if len(matches) >= limit:
            truncated = True
    except Exception as e:
        return {"error": f"search failed: {e}"}
    
    result: dict = {
        "pattern": pattern_text,
        "ida_pattern": ida_pattern,
        "total": len(matches),
        "matches": matches,
    }
    if truncated:
        result["truncated"] = True
    
    return result


# ============================================================================
# 基本块
# ============================================================================

@tool
@idaread
def get_basic_blocks(
    addr: Annotated[Union[int, str], "Function address or name"],
) -> dict:
    """Get basic blocks with control flow information."""
    wait_for_auto_analysis()
    # 解析地址
    parsed = parse_address(addr)
    if not parsed["ok"]:
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, str(addr))
            if ea == idaapi.BADADDR:
                return {"error": "not found", "query": addr}
        except Exception:
            return {"error": "invalid address", "query": addr}
    else:
        ea = parsed["value"]
    
    if ea is None:
        return {"error": "invalid address", "query": addr}
    
    # 获取函数
    try:
        f = ida_funcs.get_func(ea)
    except Exception:
        f = None
    if not f:
        return {"error": "function not found", "query": addr}
    
    try:
        name = idaapi.get_func_name(f.start_ea)
    except Exception:
        name = "?"
    
    blocks: List[dict] = []
    
    try:
        # 使用 FlowChart 获取基本块
        fc = ida_gdl.FlowChart(f)
        
        for block in fc:
            block_info: dict = {
                "start_ea": hex_addr(block.start_ea),
                "end_ea": hex_addr(block.end_ea),
                "size": block.end_ea - block.start_ea,
            }
            
            # 获取前驱
            preds: List[str] = []
            try:
                for i in range(block.npred):  # type: ignore
                    pred = fc[block.pred(i)]  # type: ignore
                    preds.append(hex_addr(pred.start_ea))
            except Exception:
                pass
            block_info["predecessors"] = preds
            
            # 获取后继
            succs: List[str] = []
            try:
                for i in range(block.nsucc):  # type: ignore
                    succ = fc[block.succ(i)]  # type: ignore
                    succs.append(hex_addr(succ.start_ea))
            except Exception:
                pass
            block_info["successors"] = succs
            
            # 块类型
            try:
                block_info["type"] = block.type
            except Exception:
                pass
            
            blocks.append(block_info)
    except Exception as e:
        return {"error": f"failed to get basic blocks: {e}", "query": addr}
    
    # 按起始地址排序
    blocks.sort(key=lambda x: int(x['start_ea'], 16))
    
    return {
        "query": addr,
        "function": name,
        "start_ea": hex_addr(f.start_ea),
        "end_ea": hex_addr(f.end_ea),
        "total": len(blocks),
        "blocks": blocks,
    }
