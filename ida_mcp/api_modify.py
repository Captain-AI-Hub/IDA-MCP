"""Modification API - comments, renaming, patching, etc.

Provides tools:
    - set_comment          set comments (batch)
    - rename_function      rename function
    - rename_local_variable rename local variable
    - rename_global_variable rename global variable
    - patch_bytes          byte patching
"""
from __future__ import annotations

import re
from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool, unsafe
from .strings_cache import invalidate_strings_cache
from .sync import idaread, idawrite, wait_for_auto_analysis
from .utils import parse_address, is_valid_c_identifier, normalize_list_input, hex_addr

# IDA module imports
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
    """Temporarily enable batch mode to suppress IDA warning dialogs."""
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
        })
    
    return results




# ============================================================================
# Renaming
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
    
    # wrap the entire operation in batch mode to suppress all warning messages
    with suppress_ida_warnings():
        f = None
        addr = None
        
        # method 1: try to look up as function name
        if isinstance(address, str):
            try:
                ea = idaapi.get_name_ea(idaapi.BADADDR, address)
                if ea != idaapi.BADADDR:
                    f = ida_funcs.get_func(ea)
                    if f:
                        addr = ea
            except Exception:
                pass
        
        # method 2: try to parse as address
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
        
        # skip rename if old and new names are identical
        if old_name == new_name_clean:
            return {
                "start_ea": hex_addr(start_ea),
                "old_name": old_name,
                "new_name": new_name_clean,
                "changed": False,
                "note": "name unchanged",
            }
        
        try:
            # SN_NOWARN | SN_NOCHECK to further ensure no warnings
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
    
    # initialize Hex-Rays
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
    
    from .analysis_utils import decompile_silent as _decompile_silent
    cfunc = _decompile_silent(f.start_ea)
    if not cfunc:
        return {"error": "decompile returned None"}
    
    # find variable
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
    
    # rename
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
    
    # reject if target is a function start
    try:
        f = ida_funcs.get_func(ea)
        if f and int(f.start_ea) == int(ea):
            return {"error": "target is a function start (use function rename)"}
    except Exception:
        pass
    
    # skip rename if old and new names are identical
    if old_name == new_name_clean:
        return {
            "ea": hex_addr(ea),
            "old_name": old_name,
            "new_name": new_name_clean,
            "changed": False,
            "note": "name unchanged",
        }
    
    try:
        # use batch mode to completely disable dialogs
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
# Byte patching
# ============================================================================

@unsafe
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
        
        # parse byte data
        byte_list: List[int] = []
        
        if isinstance(data, list):
            # direct integer list
            try:
                byte_list = [int(b) & 0xFF for b in data]
            except (ValueError, TypeError) as e:
                results.append({"error": f"invalid bytes: {e}", "address": hex_addr(addr_int)})
                continue
        elif isinstance(data, str):
            # hex string
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
        
        # read original bytes
        old_bytes = None
        try:
            old_data = ida_bytes.get_bytes(addr_int, len(byte_list))
            if old_data:
                old_bytes = ' '.join(f'{b:02X}' for b in old_data)
        except Exception:
            pass
        
        # write patch
        patched_count = 0
        errors: List[str] = []
        
        for i, b in enumerate(byte_list):
            try:
                ida_bytes.patch_byte(addr_int + i, b)
                patched_count += 1
            except Exception as e:
                errors.append(f"offset {i}: {e}")
                break
        
        # read back for verification
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
        }
        if errors:
            result["error"] = errors[0]
        
        results.append(result)
        if patched_count > 0 and not cache_invalidated:
            _invalidate_strings_cache()
            cache_invalidated = True
    
    return results
