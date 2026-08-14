"""Debugger API - debugger controls (unsafe).

Provides tools:
    - dbg_regs  get registers
    - dbg_callstack  get call stack
    - dbg_list_bps  list breakpoints
    - dbg_start  start debugger
    - dbg_exit  exit debugger
    - dbg_continue  continue execution
    - dbg_run_to  run to address
    - dbg_add_bp  add breakpoint
    - dbg_delete_bp  delete breakpoint
    - dbg_enable_bp  enable/disable breakpoint
    - dbg_step_into  step into
    - dbg_step_over  step over
    - dbg_read_mem  read debug memory
    - dbg_write_mem  write debug memory
    - dbg_status  get debugger status
    - dbg_thread_regs  read per-thread registers
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool, unsafe
from .sync import idaread, idawrite
from .utils import parse_address, normalize_list_input, hex_addr
from . import ida_shims

# IDA module imports
try:
    import idaapi  # type: ignore
    import ida_funcs  # type: ignore
    import ida_dbg  # type: ignore
except ImportError:
    idaapi = None
    ida_funcs = None
    ida_dbg = None

_MAX_DEBUG_REGIONS = 64
_MAX_DEBUG_MEMORY_BYTES = 4096
_MAX_DEBUG_TOTAL_BYTES = 1024 * 1024


def _breakpoint_exists(address: int) -> bool:
    try:
        if hasattr(ida_dbg, 'get_bpt_flags'):
            return ida_dbg.get_bpt_flags(address) != -1  # type: ignore
    except Exception:
        pass
    return False


def _delete_breakpoint(address: int) -> bool:
    try:
        if hasattr(ida_dbg, 'del_bpt'):
            return bool(ida_dbg.del_bpt(address))
    except Exception:
        pass
    return False

def _wait_for_debugger_event(timeout_ms: int = 1000) -> bool:
    """Wait for debugger events and handle them. Returns whether the debugger is suspended."""
    import time
    
    start = time.time()
    timeout_sec = timeout_ms / 1000.0
    
    while (time.time() - start) < timeout_sec:
        try:
            # try waiting for a debugger event
            if hasattr(ida_dbg, 'wait_for_next_event'):
                # briefly wait for event (10ms)
                event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10)
                if event:
                    return True
            
            # check debugger state
            if ida_dbg.is_debugger_on():
                # try reading a register to verify the debugger is actually usable
                try:
                    rip = ida_dbg.get_reg_val("RIP")
                    if rip is not None:
                        return True
                    rip = ida_dbg.get_reg_val("EIP")
                    if rip is not None:
                        return True
                except Exception:
                    pass
            
            time.sleep(0.05)
        except Exception:
            time.sleep(0.05)
    
    return False


# ============================================================================
# Registers
# ============================================================================

@unsafe
@tool
@idaread
def dbg_regs() -> dict:
    """Get all debugger registers (requires active debugger)."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"error": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    regs: List[dict] = []
    names: List[str] = []
    
    # try to get register names
    try:
        if hasattr(ida_dbg, 'get_dbg_reg_names'):
            names = list(ida_dbg.get_dbg_reg_names())  # type: ignore
    except Exception:
        pass
    
    # if no names available, fall back to common x64 registers
    if not names:
        names = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", 
                 "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                 "RIP", "RFLAGS", "CS", "SS", "DS", "ES", "FS", "GS"]
    
    for n in names:
        try:
            v = ida_dbg.get_reg_val(n)
            if v is None:
                continue
            if isinstance(v, int):
                bits = 8
                if v > 0xFFFFFFFF:
                    bits = 64
                elif v > 0xFFFF:
                    bits = 32
                elif v > 0xFF:
                    bits = 16
                width = bits // 4
                regs.append({"name": n, "value": f"0x{v:0{width}X}"})
            else:
                regs.append({"name": n, "value": repr(v)})
        except Exception:
            continue
    
    result: dict = {"registers": regs}
    if not regs:
        result["note"] = "no registers retrieved (process may be running)"
    
    return result


# ============================================================================
# Call stack
# ============================================================================

@unsafe
@tool
@idaread
def dbg_callstack() -> dict:
    """Get current call stack (requires active debugger)."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"frames": [], "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    frames: List[dict] = []
    collected = False
    
    # prefer official API
    try:
        if hasattr(ida_dbg, 'get_call_stack'):
            stk = ida_dbg.get_call_stack()  # type: ignore
            for idx, item in enumerate(stk or []):
                try:
                    ea = int(getattr(item, 'ea', 0))
                    func_name = None
                    try:
                        fstart = ida_shims.func_start(ea)
                        if fstart is not None:
                            func_name = idaapi.get_func_name(fstart)
                    except Exception:
                        func_name = None
                    frames.append({
                        'index': idx,
                        'ea': hex_addr(ea),
                        'func': func_name,
                    })
                except Exception:
                    continue
            if frames:
                collected = True
    except Exception:
        pass
    
    # fallback: walk_stack
    if not collected:
        try:
            if hasattr(ida_dbg, 'walk_stack'):
                def _cb(entry):
                    try:
                        ea = int(getattr(entry, 'ea', 0))
                        func_name = None
                        try:
                            fstart = ida_shims.func_start(ea)
                            if fstart is not None:
                                func_name = idaapi.get_func_name(fstart)
                        except Exception:
                            func_name = None
                        frames.append({
                            'index': len(frames),
                            'ea': hex_addr(ea),
                            'func': func_name,
                        })
                    except Exception:
                        return False
                    return True
                ida_dbg.walk_stack(_cb)  # type: ignore
                if frames:
                    collected = True
        except Exception:
            pass
    
    if not collected:
        return {"frames": [], "note": "call stack API unavailable or empty"}
    
    return {"frames": frames}


# ============================================================================
# Breakpoints
# ============================================================================

@unsafe
@tool
@idaread
def dbg_list_bps() -> dict:
    """List all breakpoints (works without active debugger)."""
    # note: breakpoints can exist while the debugger is not running, so skip is_debugger_on() check
    bps: List[dict] = []
    qty = 0
    
    try:
        qty = ida_dbg.get_bpt_qty()
    except Exception:
        qty = 0
    
    for i in range(qty):
        try:
            ea = ida_dbg.get_bpt_ea(i)  # type: ignore
        except Exception:
            continue
        if ea in (None, idaapi.BADADDR):
            continue
        
        info: dict = {'ea': hex_addr(ea)}
        
        # flags / enabled
        flags = None
        try:
            if hasattr(ida_dbg, 'get_bpt_attr'):
                flags = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_FLAGS)  # type: ignore
            elif hasattr(ida_dbg, 'get_bpt_flags'):
                flags = ida_dbg.get_bpt_flags(ea)  # type: ignore
        except Exception:
            flags = None
        
        enabled = None
        try:
            if flags is not None and hasattr(ida_dbg, 'BPT_ENABLED'):
                enabled = bool(flags & ida_dbg.BPT_ENABLED)  # type: ignore
        except Exception:
            enabled = None
        if enabled is not None:
            info['enabled'] = enabled
        
        # size
        try:
            if hasattr(ida_dbg, 'get_bpt_attr'):
                sz = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_SIZE)  # type: ignore
                if isinstance(sz, int) and sz > 0:
                    info['size'] = int(sz)
        except Exception:
            pass
        
        # type
        try:
            if hasattr(ida_dbg, 'get_bpt_attr'):
                tp = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_TYPE)  # type: ignore
                if isinstance(tp, int):
                    info['type'] = int(tp)
        except Exception:
            pass
        
        bps.append(info)
    
    return {"total": len(bps), "breakpoints": bps}


# ============================================================================
# Debug control
# ============================================================================

@unsafe
@tool
@idawrite
def dbg_start() -> dict:
    """Start debugger process (debugger type should be configured manually in IDA)."""
    try:
        if ida_dbg.is_debugger_on():
            return {"started": False, "note": "debugger already running"}
    except Exception:
        pass
    
    try:
        path = idaapi.get_input_file_path()
    except Exception:
        path = None
    if not path:
        return {"error": "cannot determine input file path"}
    
    # start process
    try:
        started = ida_dbg.start_process(path, '', '')  # type: ignore
    except Exception as e:
        return {"error": f"start_process failed: {e}"}
    
    ok = bool(started)
    pid = None
    suspended = False
    
    if ok:
        try:
            state = ida_dbg.get_process_state()
            if state:
                pid = getattr(state, 'pid', None)
        except Exception:
            pid = None
        
        # wait for debugger to suspend
        suspended = _wait_for_debugger_event(2000)
        
        if not suspended:
            try:
                if ida_dbg.is_debugger_on():
                    suspended = True
            except Exception:
                pass
    
    return {"started": ok, "pid": pid, "suspended": suspended}


@unsafe
@tool
@idawrite
def dbg_exit() -> dict:
    """Exit debugger."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"exited": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    try:
        ida_dbg.exit_process()
    except Exception as e:
        return {"error": f"exit_process failed: {e}"}
    
    return {"exited": True}


@unsafe
@tool
@idawrite
def dbg_continue() -> dict:
    """Continue execution."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"continued": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    cont_ok = False
    errors: List[str] = []
    tried = False
    
    try:
        if hasattr(ida_dbg, 'continue_process'):
            tried = True
            cont_ok = bool(ida_dbg.continue_process())
    except Exception as e:
        errors.append(f"continue_process: {e}")
    
    if not cont_ok:
        try:
            if hasattr(ida_dbg, 'continue_execution'):
                tried = True
                cont_ok = bool(ida_dbg.continue_execution())  # type: ignore
        except Exception as e:
            errors.append(f"continue_execution: {e}")
    
    if not tried:
        return {"error": "no continue API available"}
    if not cont_ok and errors:
        return {"continued": False, "note": "; ".join(errors)[:200]}
    
    return {"continued": bool(cont_ok)}


@unsafe
@tool
@idawrite
def dbg_run_to(
    addr: Annotated[Union[int, str], "Target address to run to"],
) -> dict:
    """Run debugger to specific address."""
    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address"}
    
    address = parsed["value"]
    
    try:
        if not ida_dbg.is_debugger_on():
            return {"error": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR"}
    
    requested = False
    used_temp_bpt = False
    notes: List[str] = []
    
    # try request_run_to
    try:
        if hasattr(ida_dbg, 'request_run_to'):
            requested = bool(ida_dbg.request_run_to(address))
            if not requested:
                notes.append('request_run_to returned False')
        else:
            notes.append('request_run_to unavailable')
    except Exception as e:
        notes.append(f'request_run_to error: {e}')
    
    # fallback: set temporary breakpoint
    if not requested:
        try:
            has_bp = _breakpoint_exists(address)
            
            if not has_bp and hasattr(ida_dbg, 'add_bpt'):
                try:
                    added = False
                    if hasattr(ida_dbg, 'BPT_DEFAULT'):
                        added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                    if not added:
                        added = bool(ida_dbg.add_bpt(address, 0))
                    if not added:
                        added = bool(ida_dbg.add_bpt(address))
                    used_temp_bpt = bool(added)
                except Exception as e:
                    notes.append(f'add_bpt error: {e}')
        except Exception:
            notes.append('temp breakpoint fallback failed')
    
    # continue execution
    continued = False
    suspended = False
    cleaned_temp_bpt = None
    try:
        if hasattr(ida_dbg, 'continue_process'):
            continued = bool(ida_dbg.continue_process())
        elif hasattr(ida_dbg, 'continue_execution'):
            continued = bool(ida_dbg.continue_execution())  # type: ignore
        else:
            notes.append('no continue API')
    except Exception as e:
        notes.append(f'continue error: {e}')

    if used_temp_bpt:
        if continued:
            suspended = _wait_for_debugger_event(2000)
            if not suspended:
                notes.append('timed out waiting for temporary breakpoint to trigger')
        else:
            notes.append('continue failed after creating temporary breakpoint')
        cleaned_temp_bpt = _delete_breakpoint(address)
        if not cleaned_temp_bpt and _breakpoint_exists(address):
            notes.append('failed to clean temporary breakpoint')
    
    result: dict = {
        'requested': requested,
        'continued': continued,
        'suspended': suspended if used_temp_bpt else None,
        'used_temp_bpt': used_temp_bpt,
        'cleaned_temp_bpt': cleaned_temp_bpt,
    }
    if not (requested or used_temp_bpt):
        result['error'] = 'run_to failed'
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


# ============================================================================
# Breakpoint operations
# ============================================================================

@unsafe
@tool
@idawrite
def dbg_add_bp(
    addr: Annotated[Union[int, str], "Address(es) for breakpoint - single or comma-separated"],
) -> List[dict]:
    """Add breakpoint(s) at address(es)."""
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        result = _set_breakpoint_single(query)
        results.append(result)
    
    return results


def _set_breakpoint_single(query: str) -> dict:
    """Set a single breakpoint."""
    parsed = parse_address(query)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address", "query": query}
    
    address = parsed["value"]
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR", "query": query}
    
    notes: List[str] = []
    existed = False
    
    try:
        existed = _breakpoint_exists(address)
    except Exception:
        existed = False
    
    added = False
    if not existed:
        try:
            if hasattr(ida_dbg, 'add_bpt'):
                if hasattr(ida_dbg, 'BPT_DEFAULT'):
                    added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                if not added:
                    try:
                        added = bool(ida_dbg.add_bpt(address, 0))
                    except Exception:
                        pass
                if not added:
                    try:
                        added = bool(ida_dbg.add_bpt(address))
                    except Exception:
                        pass
            if not added and hasattr(ida_dbg, 'set_bpt'):
                try:
                    added = bool(ida_dbg.set_bpt(address))  # type: ignore
                except Exception as e:
                    notes.append(f'set_bpt error: {e}')
        except Exception as e:
            notes.append(f'add_bpt error: {e}')
    
    ok = existed or added
    result: dict = {
        'ea': hex_addr(address),
        'existed': bool(existed and not added),
        'added': bool(added),
    }
    if not ok:
        result['error'] = 'failed to add breakpoint'
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


@unsafe
@tool
@idawrite
def dbg_delete_bp(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
) -> List[dict]:
    """Delete breakpoint(s) at address(es)."""
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        result = _delete_breakpoint_single(query)
        results.append(result)
    
    return results


def _delete_breakpoint_single(query: str) -> dict:
    """Delete a single breakpoint."""
    parsed = parse_address(query)
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid address", "query": query}
    
    address = parsed["value"]
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR", "query": query}
    
    notes: List[str] = []
    existed = False
    
    try:
        existed = _breakpoint_exists(address)
    except Exception:
        existed = False
    
    deleted = False
    if existed:
        try:
            if hasattr(ida_dbg, 'del_bpt'):
                deleted = _delete_breakpoint(address)
            else:
                notes.append('no del_bpt API')
        except Exception as e:
            notes.append(f'del_bpt error: {e}')
    
    ok = not existed or deleted
    result: dict = {
        'ea': hex_addr(address),
        'existed': bool(existed),
        'deleted': bool(deleted),
    }
    if not ok:
        result['error'] = 'failed to delete breakpoint'
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


@unsafe
@tool
@idawrite
def dbg_enable_bp(
    items: Annotated[List[Dict[str, Any]], "List of {address, enable: bool}"],
) -> List[dict]:
    """Enable or disable breakpoint(s)."""
    results = []
    
    for item in items:
        addr = item.get("address")
        enable = item.get("enable", True)
        
        if addr is None:
            results.append({"error": "invalid address"})
            continue
        
        parsed = parse_address(addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address"})
            continue
        
        address = parsed["value"]
        result = _enable_breakpoint_single(address, enable)
        results.append(result)
    
    return results


def _enable_breakpoint_single(address: int, enable: bool) -> dict:
    """Enable or disable a single breakpoint."""
    if int(address) == idaapi.BADADDR:
        return {"error": "BADADDR"}
    
    notes: List[str] = []
    existed = False
    flags = None
    
    try:
        if hasattr(ida_dbg, 'get_bpt_flags'):
            flags = ida_dbg.get_bpt_flags(address)  # type: ignore
            existed = flags != -1
    except Exception:
        existed = False
    
    changed = False
    
    # if enabling and breakpoint does not exist -> create it
    if enable and not existed:
        try:
            added = False
            if hasattr(ida_dbg, 'add_bpt'):
                if hasattr(ida_dbg, 'BPT_DEFAULT'):
                    added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                if not added:
                    added = bool(ida_dbg.add_bpt(address, 0))
            if added:
                existed = True
                changed = True
        except Exception as e:
            notes.append(f'add_bpt error: {e}')
    
    # toggle enabled state
    if existed:
        try:
            if hasattr(ida_dbg, 'enable_bpt'):
                ok = ida_dbg.enable_bpt(address, enable)
                if ok:
                    changed = True
        except Exception as e:
            notes.append(f'enable_bpt error: {e}')
    
    # read final state
    enabled_now = enable if existed else False
    try:
        if hasattr(ida_dbg, 'get_bpt_flags'):
            flags2 = ida_dbg.get_bpt_flags(address)  # type: ignore
            if flags2 is not None and flags2 != -1 and hasattr(ida_dbg, 'BPT_ENABLED'):
                enabled_now = bool(flags2 & ida_dbg.BPT_ENABLED)  # type: ignore
    except Exception:
        pass
    
    result: dict = {
        'ea': hex_addr(address),
        'existed': bool(existed),
        'enabled': bool(enabled_now),
        'changed': bool(changed),
    }
    if not existed:
        result['error'] = 'breakpoint not found'
    if notes:
        result['note'] = '; '.join(notes)[:300]
    
    return result


# ============================================================================
# Single stepping
# ============================================================================

@unsafe
@tool
@idawrite
def dbg_step_into() -> dict:
    """Step into instruction."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"stepped": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    step_ok = False
    errors: List[str] = []
    tried = False
    
    try:
        if hasattr(ida_dbg, 'step_into'):
            tried = True
            step_ok = bool(ida_dbg.step_into())
    except Exception as e:
        errors.append(f"step_into: {e}")
    
    if not step_ok and not tried:
        try:
            if hasattr(ida_dbg, 'request_step_into'):
                tried = True
                step_ok = bool(ida_dbg.request_step_into())
        except Exception as e:
            errors.append(f"request_step_into: {e}")
    
    if not tried:
        return {"error": "no step_into API available"}
    if not step_ok and errors:
        return {"stepped": False, "note": "; ".join(errors)[:200]}
    
    return {"stepped": bool(step_ok)}


@unsafe
@tool
@idawrite
def dbg_step_over() -> dict:
    """Step over instruction."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"stepped": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}
    
    step_ok = False
    errors: List[str] = []
    tried = False
    
    try:
        if hasattr(ida_dbg, 'step_over'):
            tried = True
            step_ok = bool(ida_dbg.step_over())
    except Exception as e:
        errors.append(f"step_over: {e}")
    
    if not step_ok and not tried:
        try:
            if hasattr(ida_dbg, 'request_step_over'):
                tried = True
                step_ok = bool(ida_dbg.request_step_over())
        except Exception as e:
            errors.append(f"request_step_over: {e}")
    
    if not tried:
        return {"error": "no step_over API available"}
    if not step_ok and errors:
        return {"stepped": False, "note": "; ".join(errors)[:200]}
    
    return {"stepped": bool(step_ok)}


# ============================================================================
# Debug memory operations
# ============================================================================

@unsafe
@tool
@idaread
def dbg_read_mem(
    regions: Annotated[List[Dict[str, Any]], "List of {address, size}"],
) -> List[dict]:
    """Read memory from debugged process."""
    try:
        if not ida_dbg.is_debugger_on():
            return [{"error": "debugger not active"}]
    except Exception:
        return [{"error": "cannot determine debugger state"}]
    
    if not isinstance(regions, list):
        return [{"error": "regions must be a list"}]
    if len(regions) > _MAX_DEBUG_REGIONS:
        return [{"error": f"too many regions (max {_MAX_DEBUG_REGIONS})"}]

    results = []
    total_requested = 0
    
    for region in regions:
        if not isinstance(region, dict):
            results.append({"error": "region must be an object", "region": region})
            continue
        addr = region.get("address")
        size = region.get("size", 16)
        
        if addr is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        parsed = parse_address(addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        address = parsed["value"]
        if not isinstance(size, int):
            results.append({"error": "size must be an integer", "address": hex_addr(address)})
            continue
        if size <= 0:
            results.append({"error": "size must be > 0", "address": hex_addr(address)})
            continue
        if size > _MAX_DEBUG_MEMORY_BYTES:
            results.append({"error": f"size too large (max {_MAX_DEBUG_MEMORY_BYTES})", "address": hex_addr(address)})
            continue
        total_requested += size
        if total_requested > _MAX_DEBUG_TOTAL_BYTES:
            results.append({"error": f"total read too large (max {_MAX_DEBUG_TOTAL_BYTES})", "address": hex_addr(address)})
            continue
        
        try:
            data = ida_dbg.read_dbg_memory(address, size)  # type: ignore
            if data is None:
                results.append({"error": "failed to read", "address": hex_addr(address)})
                continue
            
            byte_list = list(data)
            hex_str = ' '.join(f'{b:02X}' for b in byte_list)
            
            results.append({
                "address": hex_addr(address),
                "size": len(byte_list),
                "hex": hex_str,
            })
        except Exception as e:
            results.append({"error": str(e), "address": hex_addr(address)})
    
    return results


@unsafe
@tool
@idawrite
def dbg_write_mem(
    regions: Annotated[List[Dict[str, Any]], "List of {address, bytes: [int,...]}"],
) -> List[dict]:
    """Write memory to debugged process."""
    try:
        if not ida_dbg.is_debugger_on():
            return [{"error": "debugger not active"}]
    except Exception:
        return [{"error": "cannot determine debugger state"}]
    
    if not isinstance(regions, list):
        return [{"error": "regions must be a list"}]
    if len(regions) > _MAX_DEBUG_REGIONS:
        return [{"error": f"too many regions (max {_MAX_DEBUG_REGIONS})"}]

    results = []
    total_requested = 0
    
    for region in regions:
        if not isinstance(region, dict):
            results.append({"error": "region must be an object", "region": region})
            continue
        addr = region.get("address")
        data = region.get("bytes", [])
        
        if addr is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        parsed = parse_address(addr)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "region": region})
            continue
        
        address = parsed["value"]
        if not isinstance(data, list):
            results.append({"error": "bytes must be a list", "address": hex_addr(address)})
            continue
        if len(data) > _MAX_DEBUG_MEMORY_BYTES:
            results.append({"error": f"bytes too long (max {_MAX_DEBUG_MEMORY_BYTES})", "address": hex_addr(address)})
            continue
        total_requested += len(data)
        if total_requested > _MAX_DEBUG_TOTAL_BYTES:
            results.append({"error": f"total write too large (max {_MAX_DEBUG_TOTAL_BYTES})", "address": hex_addr(address)})
            continue
        
        try:
            byte_data = bytes(data)
            written = ida_dbg.write_dbg_memory(address, byte_data)

            results.append({
                "address": hex_addr(address),
                "size": len(byte_data),
                "written": written,
            })
        except Exception as e:
            results.append({"error": str(e), "address": hex_addr(address)})

    return results


# ============================================================================
# Status and per-thread registers
# ============================================================================


@unsafe
@tool
@idaread
def dbg_status() -> dict:
    """Get debugger status: state, pid, threads, current instruction pointer."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"debugger_on": False, "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}

    result: Dict[str, Any] = {"debugger_on": True}

    try:
        state_code = ida_dbg.get_process_state()
        state_names = {
            getattr(ida_dbg, "DSTATE_SUSP", -1): "suspended",
            getattr(ida_dbg, "DSTATE_RUN", -2): "running",
            getattr(ida_dbg, "DSTATE_NOTASK", -3): "no_process",
        }
        result["state"] = state_names.get(state_code, f"unknown({state_code})")
    except Exception as e:
        result["state"] = None
        result.setdefault("notes", []).append(f"get_process_state: {e}")

    try:
        result["pid"] = int(ida_dbg.get_pid())
    except Exception:
        result["pid"] = None

    try:
        threads = []
        for i in range(ida_dbg.get_thread_qty()):
            threads.append(int(ida_dbg.getn_thread(i)))
        result["threads"] = threads
        result["current_thread"] = int(ida_dbg.get_current_thread())
    except Exception as e:
        result["threads"] = []
        result.setdefault("notes", []).append(f"thread list: {e}")

    try:
        ip = ida_dbg.get_ip_val()
        result["ip"] = hex_addr(int(ip)) if ip is not None else None
    except Exception:
        result["ip"] = None

    try:
        sp = ida_dbg.get_sp_val()
        result["sp"] = hex_addr(int(sp)) if sp is not None else None
    except Exception:
        result["sp"] = None

    return result


@unsafe
@tool
@idawrite
def dbg_thread_regs(
    thread_ids: Annotated[Optional[Union[int, str, List[int]]], "Thread ID(s) in decimal (comma-separated ok); omit for all threads"] = None,
    names: Annotated[Optional[str], "Comma-separated register names to read; omit for all registers"] = None,
) -> dict:
    """Read registers of one or more debug threads (temporarily selects each thread, then restores)."""
    try:
        if not ida_dbg.is_debugger_on():
            return {"threads": [], "note": "debugger not active"}
    except Exception:
        return {"error": "cannot determine debugger state"}

    susp = getattr(ida_dbg, "DSTATE_SUSP", None)
    try:
        if susp is not None and ida_dbg.get_process_state() != susp:
            return {"threads": [], "note": "process is not suspended"}
    except Exception:
        pass

    # resolve target threads
    tids: List[int] = []
    if thread_ids is None:
        try:
            for i in range(ida_dbg.get_thread_qty()):
                tids.append(int(ida_dbg.getn_thread(i)))
        except Exception as e:
            return {"error": f"cannot enumerate threads: {e}"}
    else:
        for raw in normalize_list_input(thread_ids):
            try:
                tids.append(int(str(raw), 0))
            except ValueError:
                return {"error": f"invalid thread id: {raw}"}

    # register name filter
    wanted: Optional[List[str]] = None
    if names:
        wanted = [n.strip() for n in str(names).split(",") if n.strip()]

    def _read_current_thread_regs() -> List[dict]:
        reg_names = wanted
        if reg_names is None:
            try:
                if hasattr(ida_dbg, "get_dbg_reg_names"):
                    reg_names = list(ida_dbg.get_dbg_reg_names())  # type: ignore
            except Exception:
                reg_names = None
        if not reg_names:
            reg_names = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                         "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                         "RIP", "RFLAGS"]

        regs: List[dict] = []
        for reg_name in reg_names:
            try:
                v = ida_dbg.get_reg_val(reg_name)
            except Exception:
                continue
            if v is None:
                continue
            if isinstance(v, int):
                width = 16 if v > 0xFFFFFFFF else 8
                regs.append({"name": reg_name, "value": f"0x{v:0{width}X}"})
            else:
                regs.append({"name": reg_name, "value": repr(v)})
        return regs

    try:
        current = int(ida_dbg.get_current_thread())
    except Exception:
        current = None

    threads: List[dict] = []
    try:
        for tid in tids:
            try:
                if current is not None and tid != current:
                    if not ida_dbg.select_thread(tid):
                        threads.append({"tid": tid, "error": "select_thread failed"})
                        continue
                threads.append({"tid": tid, "registers": _read_current_thread_regs()})
            except Exception as e:
                threads.append({"tid": tid, "error": str(e)})
    finally:
        if current is not None:
            try:
                ida_dbg.select_thread(current)
            except Exception:
                pass

    return {"threads": threads}
