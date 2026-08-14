"""Analysis API - decompilation, disassembly, cross-references, etc.

Provides tools:
    - decompile           decompile function (Hex-Rays)
    - disasm              disassemble function
    - linear_disasm       linear disassembly
    - get_callers         get caller summary
    - get_callees         get callee summary
    - get_function_signature get function signature
    - xrefs_to            cross-references (to)
    - xrefs_from          cross-references (from)
    - xrefs_to_field      struct field references
    - find_bytes          byte pattern search
    - get_basic_blocks    get basic blocks
    - find_regex          regex search over symbol names
    - search_text         search disassembly text and comments
    - find_instructions   find instructions by mnemonic and/or pattern
    - callgraph           build a call graph from root functions
    - trace_data_flow     trace data references to/from an address
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread, wait_for_auto_analysis
from .utils import parse_address, hex_addr
from .analysis_utils import decompile_with_error as _decompile_with_error
from . import ida_shims

# IDA module imports
try:
    import idaapi  # type: ignore
    import ida_ida  # type: ignore
    import idautils  # type: ignore
    import ida_funcs  # type: ignore
    import ida_bytes  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_search  # type: ignore
    import ida_gdl  # type: ignore
    import ida_segment  # type: ignore
    import ida_typeinf  # type: ignore
except ImportError:
    idaapi = None
    ida_ida = None
    idautils = None
    ida_funcs = None
    ida_bytes = None
    ida_hexrays = None
    ida_search = None
    ida_gdl = None
    ida_segment = None
    ida_typeinf = None


# ============================================================================
# Internal helpers
# ============================================================================

def _resolve_function(query: Union[int, str]) -> dict:
    """Resolve a function by address or symbol name."""
    parsed = parse_address(query)
    if parsed["ok"] and parsed["value"] is not None:
        ea = parsed["value"]
    else:
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, str(query))
            if ea == idaapi.BADADDR:
                return {"error": "not found", "query": query}
        except Exception:
            return {"error": "invalid address", "query": query}

    if ea is None:
        return {"error": "invalid address", "query": query}

    try:
        bounds = ida_shims.func_bounds(ea)
    except Exception:
        bounds = None
    if not bounds:
        return {"error": "function not found", "query": query}

    try:
        name = idaapi.get_func_name(bounds[0])
    except Exception:
        name = "?"

    return {
        "query": query,
        "ea": int(ea),
        "name": name,
        "start_ea": int(bounds[0]),
        "end_ea": int(bounds[1]),
    }


def _init_hexrays() -> Optional[str]:
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return "failed to init hex-rays"
    except Exception:
        return "failed to init hex-rays"
    return None


def _decompile_cfunc(info: dict) -> tuple[Any, Optional[str]]:
    hexrays_error = _init_hexrays()
    if hexrays_error:
        return None, hexrays_error

    return _decompile_with_error(info["start_ea"])


def _decompile_text(info: dict) -> tuple[Optional[str], Optional[str]]:
    cfunc, error = _decompile_cfunc(info)
    if error:
        return None, error

    try:
        return str(cfunc), None
    except Exception:
        return "<print failed>", None


def _decode_insn_size(ea: int) -> int:
    try:
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, ea):
            return int(insn.size)
    except Exception:
        pass
    return 0


def _is_call_insn(ea: int) -> bool:
    try:
        checker = getattr(idaapi, "is_call_insn", None)
        if callable(checker):
            return bool(checker(ea))
    except Exception:
        pass

    try:
        mnem = idaapi.print_insn_mnem(ea)
        if mnem:
            return str(mnem).lower().startswith("call")
    except Exception:
        pass

    try:
        line = idaapi.generate_disasm_line(ea, 0)
        if line:
            return str(line).lstrip().lower().startswith("call")
    except Exception:
        pass

    return False


def _symbol_name(ea: int) -> Optional[str]:
    for fn_name in ("get_name", "get_ea_name", "get_func_name"):
        try:
            fn = getattr(idaapi, fn_name, None)
            if callable(fn):
                value = fn(ea)
                if value:
                    return str(value)
        except Exception:
            continue
    return None


def _group_call_site(
    groups: Dict[str, dict],
    owner_ea: int,
    owner_name: Optional[str],
    site_ea: int,
) -> None:
    key = hex_addr(owner_ea)
    bucket = groups.setdefault(
        key,
        {
            "address": key,
            "name": owner_name,
            "call_count": 0,
            "call_sites": [],
        },
    )
    call_site = hex_addr(site_ea)
    if call_site not in bucket["call_sites"]:
        bucket["call_sites"].append(call_site)
        bucket["call_count"] += 1


def _sorted_group_items(groups: Dict[str, dict]) -> List[dict]:
    items = list(groups.values())
    for item in items:
        item["call_sites"].sort(key=lambda value: int(value, 16))
    items.sort(key=lambda item: int(item["address"], 16))
    return items


def _signature_from_typeinfo(info: dict) -> Optional[str]:
    if idaapi is None:
        return None

    try:
        import ida_typeinf  # type: ignore
    except ImportError:
        ida_typeinf = None  # type: ignore

    if ida_typeinf is None:
        return None

    try:
        tif = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(tif, info["start_ea"]):
            try:
                return ida_typeinf.print_tinfo(
                    "",
                    0,
                    0,
                    ida_typeinf.PRTYPE_1LINE,
                    tif,
                    info["name"],
                    "",
                )  # type: ignore[attr-defined]
            except Exception:
                return ida_typeinf.print_tinfo(  # type: ignore[attr-defined]
                    "",
                    0,
                    0,
                    ida_typeinf.PRTYPE_1LINE,
                    tif,
                    "",
                    "",
                )
    except Exception:
        return None

    return None


def _signature_from_pseudocode(info: dict) -> Optional[str]:
    text, error = _decompile_text(info)
    if error or not text:
        return None

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.endswith("{"):
            stripped = stripped[:-1].rstrip()
        if stripped:
            return stripped
    return None


# ============================================================================
# Decompilation
# ============================================================================

@tool
@idaread
def decompile(
    addr: Annotated[Union[int, str], "Function address or name (single or comma-separated)"],
) -> List[dict]:
    """Decompile function(s) at given address(es). Requires Hex-Rays."""
    wait_for_auto_analysis()
    # parse address list
    from .utils import normalize_list_input
    queries = normalize_list_input(addr)
    
    results = []
    for query in queries:
        result = _decompile_single(query)
        results.append(result)
    
    return results


def _decompile_single(query: str) -> dict:
    """Decompile a single function."""
    info = _resolve_function(query)
    if info.get("error"):
        return info

    text, error = _decompile_text(info)
    if error:
        return {"error": error, "query": query}

    return {
        "query": query,
        "name": info["name"],
        "start_ea": hex_addr(info["start_ea"]),
        "end_ea": hex_addr(info["end_ea"]),
        "decompiled": text,
    }


def decompile_function(query: Union[int, str]) -> dict:
    """Service helper for a single decompile request."""
    return _decompile_single(str(query))




# ============================================================================
# Disassembly
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
    """Disassemble a single function."""
    info = _resolve_function(query)
    if info.get("error"):
        return info

    start = info["start_ea"]
    end = info["end_ea"]
    
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
            
            # instruction text
            text = None
            try:
                text = idaapi.generate_disasm_line(head_ea, 0)
            except Exception:
                text = None
            if text is None:
                text = "?"
            
            # instruction bytes
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
            
            # comments
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
        'name': info["name"],
        'start_ea': hex_addr(start),
        'end_ea': hex_addr(end),
        'instructions': instructions,
    }


def disassemble_function(query: Union[int, str]) -> dict:
    """Service helper for a single function disassembly request."""
    return _disasm_single(str(query))


# ============================================================================
# Linear disassembly
# ============================================================================

@tool
@idaread
def linear_disasm(
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
    
    # verify segment exists
    try:
        if ida_segment is not None and not ida_shims.segment_exists(ea):
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
            
            # read flags to determine is_code
            is_code = False
            try:
                flags = idaapi.get_full_flags(ea)
                is_code = bool(idaapi.is_code(flags))
            except Exception:
                pass
            
            # instruction text
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
# Call relationships and structured pseudocode
# ============================================================================

@tool
@idaread
def get_callers(
    addr: Annotated[Union[int, str], "Function address or name"],
) -> dict:
    """Get callers grouped by calling function and call sites."""
    wait_for_auto_analysis()
    info = _resolve_function(addr)
    if info.get("error"):
        return info

    groups: Dict[str, dict] = {}

    try:
        for xr in idautils.XrefsTo(info["start_ea"], 0):
            try:
                site_ea = int(getattr(xr, "frm", 0))
                if not bool(getattr(xr, "iscode", 0)):
                    continue
                if not _is_call_insn(site_ea):
                    continue

                owner_start = ida_shims.func_start(site_ea)
                if owner_start is not None:
                    owner_ea = int(owner_start)
                    owner_name = idaapi.get_func_name(owner_start)
                else:
                    owner_ea = site_ea
                    owner_name = _symbol_name(site_ea)

                _group_call_site(groups, owner_ea, owner_name, site_ea)
            except Exception:
                continue
    except Exception as exc:
        return {"error": f"get_callers failed: {exc}", "query": addr}

    items = _sorted_group_items(groups)
    return {
        "query": addr,
        "function": info["name"],
        "start_ea": hex_addr(info["start_ea"]),
        "end_ea": hex_addr(info["end_ea"]),
        "total": len(items),
        "items": items,
    }


@tool
@idaread
def get_callees(
    addr: Annotated[Union[int, str], "Function address or name"],
) -> dict:
    """Get callees grouped by target function and call sites."""
    wait_for_auto_analysis()
    info = _resolve_function(addr)
    if info.get("error"):
        return info

    groups: Dict[str, dict] = {}

    try:
        for head_ea in idautils.Heads(info["start_ea"], info["end_ea"]):
            try:
                flags = idaapi.get_full_flags(head_ea)
                if not idaapi.is_code(flags) or not _is_call_insn(head_ea):
                    continue

                insn_size = _decode_insn_size(head_ea)
                for xr in idautils.XrefsFrom(head_ea, 0):
                    target_ea = int(getattr(xr, "to", 0))
                    if not bool(getattr(xr, "iscode", 0)):
                        continue
                    if insn_size > 0 and target_ea == head_ea + insn_size:
                        continue

                    callee_start = ida_shims.func_start(target_ea)
                    if callee_start is not None:
                        callee_ea = int(callee_start)
                        callee_name = idaapi.get_func_name(callee_start)
                    else:
                        callee_ea = target_ea
                        callee_name = _symbol_name(target_ea)

                    _group_call_site(groups, callee_ea, callee_name, int(head_ea))
            except Exception:
                continue
    except Exception as exc:
        return {"error": f"get_callees failed: {exc}", "query": addr}

    items = _sorted_group_items(groups)
    return {
        "query": addr,
        "function": info["name"],
        "start_ea": hex_addr(info["start_ea"]),
        "end_ea": hex_addr(info["end_ea"]),
        "total": len(items),
        "items": items,
    }


@tool
@idaread
def get_function_signature(
    addr: Annotated[Union[int, str], "Function address or name"],
) -> dict:
    """Get the best available function signature string."""
    wait_for_auto_analysis()
    info = _resolve_function(addr)
    if info.get("error"):
        return info

    signature = _signature_from_typeinfo(info)
    source = "typeinfo"
    inferred = False

    if not signature:
        signature = _signature_from_pseudocode(info)
        source = "pseudocode"
        inferred = True

    if not signature:
        signature = f"void {info['name']}(void)"
        source = "fallback_name"
        inferred = True

    return {
        "query": addr,
        "function": info["name"],
        "start_ea": hex_addr(info["start_ea"]),
        "end_ea": hex_addr(info["end_ea"]),
        "signature": signature,
        "source": source,
        "inferred": inferred,
    }


# ============================================================================
# Cross-references
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
    """Get cross-references to a single address."""
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
    }


def xrefs_to_address(query: Union[int, str]) -> dict:
    """Service helper for xrefs-to on a single address."""
    return _xrefs_to_single(str(query))


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
    """Get outgoing cross-references from a single address."""
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
    }


def xrefs_from_address(query: Union[int, str]) -> dict:
    """Service helper for xrefs-from on a single address."""
    return _xrefs_from_single(str(query))


# ============================================================================
# Struct field references
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
    
    if ida_typeinf is None:
        return {"error": "type APIs unavailable"}

    tif = ida_typeinf.tinfo_t()
    try:
        if not tif.get_named_type(ida_typeinf.get_idati(), struct_name):
            return {"error": "struct not found"}
    except Exception:
        return {"error": "struct not found"}

    try:
        if not (tif.is_struct() or tif.is_union()):
            return {"error": "not a struct/union"}
    except Exception:
        return {"error": "struct not found"}

    # find member offset
    target_off = None
    try:
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            for member in udt:
                if member.name == field_name:
                    target_off = int(member.offset // 8)
                    break
    except Exception:
        target_off = None
    
    if target_off is None:
        return {"error": "field not found"}
    
    # heuristic scan
    fname_lower = field_name.lower()
    matches: List[dict] = []
    truncated = False
    MAX_MATCH = 500
    
    try:
        for fea in ida_shims.iter_function_starts():
            bounds = ida_shims.func_bounds(fea)
            if not bounds:
                continue
            for ea in idautils.Heads(int(bounds[0]), int(bounds[1])):
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
# Byte pattern search
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
    
    # parse start/end addresses
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
    
    # default to searching the whole database
    if start_ea is None:
        try:
            start_ea = int(ida_ida.inf_get_min_ea())  # type: ignore[union-attr]
        except Exception:
            start_ea = 0
    
    if end_ea is None:
        try:
            end_ea = int(ida_ida.inf_get_max_ea())  # type: ignore[union-attr]
        except Exception:
            end_ea = 0xFFFFFFFFFFFFFFFF
    
    # parse pattern string
    pattern_text = pattern.strip()
    
    # convert to IDA search format
    # IDA uses space-separated hex bytes, ? as wildcard
    # input: "48 8B ?? ?? 48 89" or "48 8B ? ? 48 89"
    # IDA format: "48 8B ? ? 48 89"
    parts = pattern_text.split()
    ida_pattern_parts = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p in ('??', '?'):
            ida_pattern_parts.append('?')
        else:
            # validate hex byte
            try:
                int(p, 16)
                ida_pattern_parts.append(p.upper())
            except ValueError:
                return {"error": f"invalid hex byte: {p}"}
    
    if not ida_pattern_parts:
        return {"error": "empty pattern after parsing"}
    
    ida_pattern = ' '.join(ida_pattern_parts)
    
    # search
    matches: List[dict] = []
    truncated = False
    
    try:
        ea = start_ea
        while ea < end_ea and len(matches) < limit:
            # use ida_search.find_binary
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
            
            # read matched bytes
            match_len = len([p for p in ida_pattern_parts if p != '?'])
            # actual match length is the total number of parts
            actual_len = len(ida_pattern_parts)
            
            bytes_hex = None
            try:
                raw = ida_bytes.get_bytes(found, actual_len)
                if raw:
                    bytes_hex = ' '.join(f'{b:02X}' for b in raw)
            except Exception:
                pass
            
            # get function info
            func_name = None
            try:
                fstart = ida_shims.func_start(found)
                if fstart is not None:
                    func_name = idaapi.get_func_name(fstart)
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
# Basic blocks
# ============================================================================

@tool
@idaread
def get_basic_blocks(
    addr: Annotated[Union[int, str], "Function address or name"],
) -> dict:
    """Get basic blocks with control flow information."""
    wait_for_auto_analysis()
    return _basic_blocks_single(addr)


def _basic_blocks_single(addr: Union[int, str]) -> dict:
    """Get basic blocks with control flow information for one function."""
    info = _resolve_function(addr)
    if info.get("error"):
        return info

    blocks: List[dict] = []

    try:
        # use FlowChart to get basic blocks
        fc = ida_gdl.FlowChart(bounds=(info["start_ea"], info["end_ea"]))
        
        for block in fc:
            block_info: dict = {
                "start_ea": hex_addr(block.start_ea),
                "end_ea": hex_addr(block.end_ea),
                "size": block.end_ea - block.start_ea,
            }
            
            # get predecessors
            preds: List[str] = []
            try:
                for pred in block.preds():  # type: ignore[attr-defined]
                    preds.append(hex_addr(pred.start_ea))
            except Exception:
                pass
            block_info["predecessors"] = preds
            
            # get successors
            succs: List[str] = []
            try:
                for succ in block.succs():  # type: ignore[attr-defined]
                    succs.append(hex_addr(succ.start_ea))
            except Exception:
                pass
            block_info["successors"] = succs
            
            # block type
            try:
                block_info["type"] = block.type
            except Exception:
                pass
            
            blocks.append(block_info)
    except Exception as e:
        return {"error": f"failed to get basic blocks: {e}", "query": addr}
    
    # sort by start address
    blocks.sort(key=lambda x: int(x['start_ea'], 16))
    
    return {
        "query": addr,
        "function": info["name"],
        "start_ea": hex_addr(info["start_ea"]),
        "end_ea": hex_addr(info["end_ea"]),
        "total": len(blocks),
        "blocks": blocks,
    }


def basic_blocks_for_function(query: Union[int, str]) -> dict:
    """Service helper for one function's basic blocks."""
    return _basic_blocks_single(query)


# ============================================================================
# Search: symbol names, listing text, instructions
# ============================================================================

import re
from collections import deque

from .utils import normalize_list_input

try:
    import ida_lines  # type: ignore
    import ida_xref  # type: ignore
except ImportError:
    ida_lines = None
    ida_xref = None


def _listing_text(ea: int) -> str:
    """Plain disassembly line text (tags removed) for an address."""
    if ida_lines is None:
        return ""
    try:
        line = ida_lines.generate_disasm_line(ea, 0) or ""
        return str(ida_lines.tag_remove(line)).strip()
    except Exception:
        return ""


def _iter_all_heads():
    """Yield every instruction/data head in the database."""
    try:
        start = int(ida_ida.inf_get_min_ea())
        end = int(ida_ida.inf_get_max_ea())
    except Exception:
        return
    if start >= end:
        return
    for head in idautils.Heads(start, end):
        yield int(head)


def _function_name_at(ea: int) -> Optional[str]:
    try:
        fstart = ida_shims.func_start(ea)
        if fstart is not None:
            return idaapi.get_func_name(fstart)
    except Exception:
        pass
    return None


@tool
@idaread
def find_regex(
    pattern: Annotated[str, "Regular expression matched against symbol names"],
    limit: Annotated[int, "Maximum matches to return"] = 30,
    offset: Annotated[int, "Number of matches to skip"] = 0,
) -> dict:
    """Search symbol names (functions, globals, labels) with a regular expression."""
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return {"error": f"invalid regex: {e}", "pattern": pattern}

    matches: List[dict] = []
    skipped = 0
    truncated = False
    for ea, name in idautils.Names():
        if not name or not rx.search(str(name)):
            continue
        if skipped < max(0, offset):
            skipped += 1
            continue
        matches.append({"ea": hex_addr(int(ea)), "name": str(name)})
        if len(matches) >= max(1, limit):
            truncated = True
            break

    result: Dict[str, Any] = {
        "pattern": pattern,
        "count": len(matches),
        "items": matches,
    }
    if truncated:
        result["truncated"] = True
    return result


@tool
@idaread
def search_text(
    query: Annotated[str, "Substring (default) or regular expression matched against disassembly lines and comments"],
    regex: Annotated[bool, "Treat query as a regular expression"] = False,
    limit: Annotated[int, "Maximum matches to return"] = 30,
) -> dict:
    """Search disassembly listing text (instructions, comments) across the database."""
    if regex:
        try:
            rx = re.compile(query, re.IGNORECASE)
        except re.error as e:
            return {"error": f"invalid regex: {e}", "query": query}

        def matcher(text: str) -> bool:
            return bool(rx.search(text))
    else:
        needle = query.lower()

        def matcher(text: str) -> bool:
            return needle in text.lower()

    matches: List[dict] = []
    truncated = False
    for head in _iter_all_heads():
        text = _listing_text(head)
        try:
            cmt = ida_bytes.get_cmt(head, False) or ""
        except Exception:
            cmt = ""
        haystack = f"{text} ; {cmt}" if cmt else text
        if not haystack or not matcher(haystack):
            continue
        matches.append({
            "ea": hex_addr(head),
            "text": text,
            "comment": cmt or None,
            "function": _function_name_at(head),
        })
        if len(matches) >= max(1, limit):
            truncated = True
            break

    result: Dict[str, Any] = {
        "query": query,
        "regex": bool(regex),
        "count": len(matches),
        "items": matches,
    }
    if truncated:
        result["truncated"] = True
    return result


@tool
@idaread
def find_instructions(
    mnemonic: Annotated[str, "Mnemonic filter (case-insensitive substring, e.g. 'call'); empty matches all"] = "",
    pattern: Annotated[str, "Optional regex matched against the full instruction text"] = "",
    limit: Annotated[int, "Maximum matches to return"] = 100,
) -> dict:
    """Find instructions by mnemonic and/or a regex over the instruction text."""
    rx = None
    if pattern:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return {"error": f"invalid regex: {e}", "pattern": pattern}

    needle = mnemonic.strip().lower()
    if not needle and rx is None:
        return {"error": "provide mnemonic and/or pattern"}

    matches: List[dict] = []
    truncated = False
    for head in _iter_all_heads():
        text = _listing_text(head)
        if not text:
            continue
        parts = text.split(None, 1)
        mnem = parts[0] if parts else ""
        if needle and needle not in mnem.lower():
            continue
        if rx is not None and not rx.search(text):
            continue
        matches.append({
            "ea": hex_addr(head),
            "mnemonic": mnem,
            "text": text,
            "function": _function_name_at(head),
        })
        if len(matches) >= max(1, limit):
            truncated = True
            break

    result: Dict[str, Any] = {
        "mnemonic": mnemonic,
        "pattern": pattern,
        "count": len(matches),
        "items": matches,
    }
    if truncated:
        result["truncated"] = True
    return result


# ============================================================================
# Call graph and data-flow tracing
# ============================================================================


@tool
@idaread
def callgraph(
    roots: Annotated[Union[int, str, List[str]], "Root function name(s) or address(es) (comma-separated ok)"],
    max_depth: Annotated[int, "Maximum call depth from the roots"] = 5,
    max_nodes: Annotated[int, "Maximum functions to include"] = 1000,
) -> dict:
    """Build a call graph by walking call references from the root function(s)."""
    nodes: Dict[int, dict] = {}
    edges: List[dict] = []
    seen_edges = set()
    errors: List[dict] = []
    queue: deque = deque()
    root_names: List[str] = []

    for query in normalize_list_input(roots):
        info = _resolve_function(query)
        if "error" in info:
            errors.append(info)
            continue
        root_names.append(info["name"])
        queue.append((info["start_ea"], 0))

    truncated = False
    while queue:
        start_ea, depth = queue.popleft()
        if start_ea in nodes:
            continue
        if len(nodes) >= max(1, max_nodes):
            truncated = True
            break
        nodes[start_ea] = {
            "ea": hex_addr(start_ea),
            "name": _function_name_at(start_ea),
            "depth": depth,
        }
        if depth >= max_depth:
            continue
        try:
            bounds = ida_shims.func_bounds(start_ea)
            heads = ida_shims.iter_func_items(*bounds) if bounds else iter(())
        except Exception:
            continue
        for head in heads:
            for x in idautils.XrefsFrom(head, 0):
                if not x.iscode:
                    continue
                try:
                    callee_start = ida_shims.func_start(x.to)
                except Exception:
                    callee_start = None
                if callee_start is None or int(callee_start) == start_ea:
                    continue
                callee = int(callee_start)
                key = (start_ea, callee)
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({
                        "caller": hex_addr(start_ea),
                        "callee": hex_addr(callee),
                    })
                if callee not in nodes:
                    queue.append((callee, depth + 1))

    result: Dict[str, Any] = {
        "roots": root_names,
        "max_depth": max_depth,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": sorted(nodes.values(), key=lambda item: (item["depth"], item["ea"])),
        "edges": edges,
    }
    if truncated:
        result["truncated"] = True
    if errors:
        result["errors"] = errors
    return result


@tool
@idaread
def trace_data_flow(
    address: Annotated[Union[int, str], "Start address or symbol name"],
    direction: Annotated[str, "to | from | both"] = "both",
    max_depth: Annotated[int, "Maximum xref hops"] = 3,
    max_nodes: Annotated[int, "Maximum nodes to include"] = 200,
) -> dict:
    """Trace data references (reads/writes/offsets) to and from an address."""
    parsed = parse_address(address)
    if parsed["ok"] and parsed["value"] is not None:
        start = parsed["value"]
    else:
        try:
            start = int(idaapi.get_name_ea(idaapi.BADADDR, str(address)))
        except Exception:
            start = idaapi.BADADDR
        if start == idaapi.BADADDR:
            return {"error": "not found", "query": address}

    direction_norm = str(direction or "both").lower()
    if direction_norm not in {"to", "from", "both"}:
        return {"error": f"invalid direction: {direction}", "expected": "to|from|both"}

    nodes: Dict[int, dict] = {}
    edges: List[dict] = []
    seen_edges = set()
    queue: deque = deque([(int(start), 0)])
    truncated = False

    while queue:
        ea, depth = queue.popleft()
        if ea in nodes:
            continue
        if len(nodes) >= max(1, max_nodes):
            truncated = True
            break
        nodes[ea] = {"ea": hex_addr(ea), "name": _symbol_name(ea), "depth": depth}
        if depth >= max(0, max_depth):
            continue

        neighbors = []
        if direction_norm in {"to", "both"}:
            try:
                for x in idautils.XrefsTo(ea, 0):
                    if not x.iscode:
                        neighbors.append((int(x.frm), ea, int(x.type)))
            except Exception:
                pass
        if direction_norm in {"from", "both"}:
            try:
                for x in idautils.XrefsFrom(ea, 0):
                    if not x.iscode:
                        neighbors.append((ea, int(x.to), int(x.type)))
            except Exception:
                pass

        for frm, to, xtype in neighbors:
            key = (frm, to)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"frm": hex_addr(frm), "to": hex_addr(to), "type": xtype})
            other = frm if to == ea else to
            if other not in nodes:
                queue.append((other, depth + 1))

    result: Dict[str, Any] = {
        "query": address,
        "start": hex_addr(int(start)),
        "direction": direction_norm,
        "max_depth": max_depth,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": sorted(nodes.values(), key=lambda item: (item["depth"], item["ea"])),
        "edges": edges,
    }
    if truncated:
        result["truncated"] = True
    return result
