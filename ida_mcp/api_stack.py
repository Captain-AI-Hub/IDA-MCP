"""Stack frame API - stack frame operations.

Provides tools:
    - stack_frame          get stack frame variables
    - declare_stack        create stack variables
    - delete_stack         delete stack variables
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread, idawrite, wait_for_auto_analysis
from .utils import parse_address, normalize_list_input, hex_addr, is_valid_c_identifier
from . import ida_shims

# IDA module imports
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

PT_SIL = getattr(ida_typeinf, 'PT_SIL', 1) if ida_typeinf is not None else 1
_MAX_BATCH_ITEMS = 100


def _error(message: str, **extra: Any) -> dict:
    result = {"error": message}
    result.update(extra)
    return result


def _parse_stack_tinfo(type_text: str) -> tuple[Any, Optional[str]]:
    if ida_typeinf is None or idaapi is None:
        return None, "type APIs unavailable"

    normalized = type_text.strip()
    if "[" in normalized and normalized.endswith("]"):
        bracket = normalized.index("[")
        base = normalized[:bracket].strip()
        suffix = normalized[bracket:]
        candidate_decl = f"{base} __ida_mcp_stackvar{suffix};"
    else:
        candidate_decl = f"{normalized} __ida_mcp_stackvar;"
    tif = ida_typeinf.tinfo_t()
    errors: list[str] = []

    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tif, idaapi.cvar.idati, candidate_decl, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tif, idaapi.cvar.idati, candidate_decl, PT_SIL)),  # type: ignore
    ]

    for label, fn in variants:
        try:
            _ = fn()
            if tif and not tif.empty():
                return tif, None
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    details = "; ".join(errors[:2]) if errors else "parse failed"
    return None, details


def _default_stack_type(size: int) -> str:
    if size == 1:
        return "char"
    if size == 2:
        return "short"
    if size == 4:
        return "int"
    if size == 8:
        return "__int64"
    return f"char[{size}]"


def _get_frame_tinfo(func_ea: int) -> Any:
    """Load a function frame as IDA 9 tinfo_t."""
    if ida_typeinf is None or ida_frame is None:
        return None

    tif = ida_typeinf.tinfo_t()
    try:
        if ida_shims.get_func_frame(tif, func_ea):
            return tif
    except Exception:
        pass

    try:
        frame_id = ida_shims.get_frame_id(func_ea)
        if frame_id and tif.get_type_by_tid(frame_id):
            return tif
    except Exception:
        pass
    return None


def _frame_variables_from_func(func_ea: int) -> List[dict]:
    """Return IDA 9 frame members from a function frame type."""
    tif = _get_frame_tinfo(func_ea)
    if tif is None:
        return []

    variables: List[dict] = []
    try:
        if not tif.is_udt():
            return []
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return []
        for udm in udt:
            try:
                if getattr(udm, "is_gap", lambda: False)():
                    continue
                variables.append({
                    "name": udm.name,
                    "offset": udm.offset // 8,
                    "size": udm.size // 8,
                    "type": str(udm.type) if udm.type else None,
                })
            except Exception:
                continue
    except Exception:
        return []
    return variables


def _frame_member_by_name(func_ea: int, name: str) -> Optional[dict]:
    for member in _frame_variables_from_func(func_ea):
        if member.get("name") == name:
            return member
    return None


def _define_stack_member(func_ea: int, offset: int, name: str, tif: Any) -> tuple[bool, Optional[str]]:
    errors: list[str] = []

    if ida_frame is None:
        return False, "ida_frame unavailable"

    try:
        if ida_shims.define_stkvar(func_ea, name, offset, tif):
            return True, None
    except Exception as exc:
        errors.append(f"define_stkvar failed: {exc}")
    else:
        errors.append("define_stkvar returned False")

    try:
        if ida_shims.add_frame_member(func_ea, name, offset, tif):
            return True, None
    except Exception as exc:
        errors.append(f"add_frame_member failed: {exc}")
    else:
        errors.append("add_frame_member returned False")

    return False, "; ".join(errors)


# ============================================================================
# Stack frame info
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
    """Get stack frame info for a single function."""
    parsed = parse_address(query)
    if not parsed["ok"]:
        # try as function name
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
        bounds = ida_shims.func_bounds(ea)
    except Exception:
        bounds = None
    if not bounds:
        return {"error": "function not found", "query": query}

    func_start = bounds[0]

    try:
        fname = idaapi.get_func_name(func_start)
    except Exception:
        fname = "?"
    
    frame_variables: List[dict] = []
    local_variables: List[dict] = []
    hexrays_error = None
    
    frame_variables = _frame_variables_from_func(func_start)

    # get Hex-Rays local variables (always attempt to retrieve all locals)
    try:
        if ida_hexrays.init_hexrays_plugin():  # type: ignore
            from .analysis_utils import decompile_silent as _decompile_silent
            cfunc = _decompile_silent(func_start)  # type: ignore
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
                        
                        # determine variable location
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
    
    # if both are empty
    if not frame_variables and not local_variables:
        if hexrays_error:
            return {
                "query": query,
                "name": fname,
                "start_ea": hex_addr(func_start),
                "variables": [],
                "error": hexrays_error,
            }
        return {
            "query": query,
            "name": fname,
            "start_ea": hex_addr(func_start),
            "variables": [],
            "note": "no stack frame or local variables",
        }
    
    # Frame members are the stable source for stack offsets. Hex-Rays locals
    # can rename/split variables after decompilation and are kept as supplement.
    result: dict = {
        "query": query,
        "name": fname,
        "start_ea": hex_addr(func_start),
    }
    
    if frame_variables:
        result["variables"] = frame_variables
        result["frame_variables"] = frame_variables
        result["method"] = "ida_frame"
        if local_variables:
            result["local_variables"] = local_variables
    else:
        result["variables"] = local_variables
        result["local_variables"] = local_variables
        result["method"] = "hexrays"
    
    return result


def stack_frame_for_function(query: Union[int, str]) -> dict:
    """Service helper for a single stack-frame request."""
    return _stack_frame_single(str(query))


# ============================================================================
# Stack variable creation/deletion
# ============================================================================

@tool
@idawrite
def declare_stack(
    items: Annotated[List[Dict[str, Any]], "List of {function_address, offset, name, type?, size?}"],
) -> List[dict]:
    """Create stack variable(s) at specified offset(s)."""
    wait_for_auto_analysis()
    if not isinstance(items, list):
        return [{"error": "items must be a list"}]
    if len(items) > _MAX_BATCH_ITEMS:
        return [{"error": f"too many items (max {_MAX_BATCH_ITEMS})"}]

    results = []
    
    for item in items:
        if not isinstance(item, dict):
            results.append({"error": "item must be an object", "item": item})
            continue
        func_addr = item.get("function_address")
        offset = item.get("offset")
        name = item.get("name")
        var_type = item.get("type")
        size = item.get("size", 4)
        
        if func_addr is None or offset is None or not name:
            results.append({"error": "missing required fields", "item": item})
            continue

        if not isinstance(offset, int):
            results.append(_error("offset must be an integer", item=item))
            continue

        if not isinstance(size, int) or size <= 0:
            results.append(_error("size must be a positive integer", item=item))
            continue

        name = str(name).strip()
        if not is_valid_c_identifier(name):
            results.append(_error("name is not a valid C identifier", item=item))
            continue
        
        # parse function address
        parsed = parse_address(func_addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid function_address", "item": item})
            continue
        
        try:
            bounds = ida_shims.func_bounds(parsed["value"])
        except Exception:
            bounds = None
        if not bounds:
            results.append({"error": "function not found", "item": item})
            continue

        func_start = bounds[0]

        existing = _frame_member_by_name(func_start, name)
        if existing:
            results.append({
                "function_address": hex_addr(int(func_start)),
                "offset": offset,
                "name": name,
                "changed": False,
                "note": "stack variable already exists",
            })
            continue

        declared_type = str(var_type).strip() if var_type else _default_stack_type(size)
        tif, parse_error = _parse_stack_tinfo(declared_type)
        if parse_error:
            results.append(_error(
                "parse type failed",
                function_address=hex_addr(int(func_start)),
                offset=offset,
                name=name,
                declared_type=declared_type,
                details=parse_error,
            ))
            continue

        ok, error = _define_stack_member(func_start, offset, name, tif)
        result = {
            "function_address": hex_addr(int(func_start)),
            "offset": offset,
            "name": name,
            "declared_type": declared_type,
            "size": size,
            "changed": bool(ok),
        }
        if error is not None:
            result["error"] = error
        results.append(result)
    
    return results


@tool
@idawrite
def delete_stack(
    items: Annotated[List[Dict[str, Any]], "List of {function_address, name}"],
) -> List[dict]:
    """Delete stack variable(s) by name."""
    if not isinstance(items, list):
        return [{"error": "items must be a list"}]
    if len(items) > _MAX_BATCH_ITEMS:
        return [{"error": f"too many items (max {_MAX_BATCH_ITEMS})"}]

    results = []
    
    for item in items:
        if not isinstance(item, dict):
            results.append({"error": "item must be an object", "item": item})
            continue
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
            bounds = ida_shims.func_bounds(parsed["value"])
        except Exception:
            bounds = None
        if not bounds:
            results.append({"error": "function not found", "item": item})
            continue

        func_start = bounds[0]

        if ida_frame is None:
            results.append({"error": "ida_frame unavailable", "item": item})
            continue

        member = _frame_member_by_name(func_start, str(name))
        if not member:
            results.append({
                "function_address": hex_addr(int(func_start)),
                "name": name,
                "changed": False,
                "deleted": False,
                "error": "member not found",
            })
            continue

        offset = int(member["offset"])
        size = int(member.get("size") or 1)
        if size <= 0:
            size = 1

        try:
            ok = ida_shims.delete_frame_members(func_start, offset, offset + size)
            results.append({
                "function_address": hex_addr(int(func_start)),
                "name": name,
                "changed": bool(ok),
                "deleted": bool(ok),
            })
        except Exception as e:
            results.append({"error": str(e), "item": item})
    
    return results
