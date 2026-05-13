"""Core API - IDB metadata, function/string/global lists, etc.

Provides tools:
    - check_connection     check gateway/registry connection status
    - list_instances       list all registered instances in the gateway
    - get_metadata         get IDB metadata
    - list_functions       list functions
    - list_globals         list global variables
    - list_strings         list strings
    - list_local_types     list local types
    - get_entry_points     list entry points
    - convert_number       number conversion
    - list_imports         list imports
    - list_exports         list exports
    - list_segments        list memory segments
    - get_cursor           get current cursor position
"""
from __future__ import annotations

import os
import hashlib
import stat
from typing import Annotated, Optional, List

from .rpc import tool
from .sync import idaread
from .utils import paginate, pattern_filter, normalize_arch, hex_addr
from .strings_cache import (
    get_strings_cache as _shared_get_strings_cache,
    init_strings_cache as _shared_init_strings_cache,
    invalidate_strings_cache as _shared_invalidate_strings_cache,
)

# IDA module imports
try:
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import ida_funcs  # type: ignore
    import ida_bytes  # type: ignore
    import ida_typeinf  # type: ignore
    import ida_segment  # type: ignore
    import ida_nalt  # type: ignore
    import ida_entry  # type: ignore
    import ida_name  # type: ignore
    import ida_kernwin  # type: ignore
    import ida_loader  # type: ignore
    import ida_pro  # type: ignore
except ImportError:
    # allow import outside IDA (e.g. for tests), but related features will be unavailable
    idaapi = None
    idautils = None
    ida_funcs = None
    ida_bytes = None
    ida_typeinf = None
    ida_segment = None
    ida_nalt = None
    ida_entry = None
    ida_name = None
    ida_kernwin = None
    ida_loader = None
    ida_pro = None

from . import registry


# ============================================================================
# String cache (avoid rebuilding strlist on every call)
# ============================================================================

def _get_strings_cache() -> list:
    """Get the cached string list, building it on first access."""
    return _shared_get_strings_cache()


def invalidate_strings_cache():
    """Clear the string cache (call after IDB changes)."""
    _shared_invalidate_strings_cache()


def init_caches():
    """Pre-build caches when the plugin starts."""
    import time
    t0 = time.perf_counter()
    strings_count = _shared_init_strings_cache()
    t1 = time.perf_counter()
    print(f"[IDA-MCP] Cached {strings_count} strings in {(t1 - t0) * 1000:.0f}ms")


# ============================================================================
# Instance management
# ============================================================================

@tool
def check_connection() -> dict:
    """Check gateway/registry health. Returns { ok: bool, count: int }."""
    if registry is None:
        return {"ok": False, "count": 0}
    try:
        return registry.check_connection()
    except Exception:
        return {"ok": False, "count": 0}


@tool
def list_instances() -> List[dict]:
    """List all IDA instances registered in the shared gateway."""
    if registry is None:
        return []
    try:
        return registry.get_instances()
    except Exception as e:
        return [{"error": str(e)}]

@tool
@idaread
def get_metadata() -> dict:
    """Get IDB metadata (input_file, arch, bits, endian, hash)."""

    # get input file
    try:
        input_file = idaapi.get_input_file_path()
    except Exception:
        input_file = None
    
    # get architecture/bit width
    arch: Optional[str] = None
    bits = 0
    try:
        inf = idaapi.get_inf_structure()  # type: ignore
        arch = getattr(inf, 'procname', None) or getattr(inf, 'procName', None)
        if isinstance(arch, bytes):
            arch = arch.decode(errors='ignore')
        
        is_64 = False
        try:
            is_64 = inf.is_64bit()
        except Exception:
            try:
                is_64 = bool(getattr(inf, 'is_64bit', lambda: False)())
            except Exception:
                is_64 = False
        bits = 64 if is_64 else 32
    except Exception:
        pass
    
    # fallback architecture retrieval
    if not arch:
        for fn_name in ('ph_get_idp_name', 'get_idp_name', 'ph_get_id', 'ph_get_idp_desc'):
            try:
                fn = getattr(idaapi, fn_name, None)
                if callable(fn):
                    cand = fn()
                    if isinstance(cand, bytes):
                        cand = cand.decode(errors='ignore')
                    if cand:
                        arch = cand
                        break
            except Exception:
                continue
    
    # fallback bit-width retrieval
    if not bits:
        try:
            if getattr(idaapi, '__EA64__', False):
                bits = 64
            else:
                bits = 32
        except Exception:
            bits = 0
    
    # compute file hash
    file_hash: Optional[str] = None
    if input_file and os.path.isfile(input_file):
        try:
            input_stat = os.stat(input_file)
            if stat.S_ISREG(input_stat.st_mode) and input_stat.st_size <= 32 * 1024 * 1024:
                h = hashlib.sha256()
                with open(input_file, 'rb') as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(chunk)
                file_hash = h.hexdigest()
        except Exception:
            file_hash = None
    
    # normalize architecture
    arch_normalized = normalize_arch(arch, bits)
    
    # endianness
    endian = None
    try:
        inf3 = idaapi.get_inf_structure()  # type: ignore
        if hasattr(inf3, 'is_be') and inf3.is_be():
            endian = 'big'
        else:
            endian = 'little'
    except Exception:
        endian = None
    
    return {
        "input_file": input_file,
        "arch": arch_normalized or arch,
        "bits": bits,
        "endian": endian,
        "hash": file_hash,
    }


# ============================================================================
# Function list
# ============================================================================

@tool
@idaread
def list_functions(
    offset: Annotated[int, "Pagination offset (>=0)"] = 0,
    count: Annotated[int, "Number of items (1..1000)"] = 100,
    pattern: Annotated[Optional[str], "Optional name filter pattern"] = None,
) -> dict:
    """List functions with pagination and optional filtering."""
    if offset < 0:
        return {"error": "offset < 0"}
    if count <= 0:
        return {"error": "count must be > 0"}
    if count > 1000:
        return {"error": "count too large (max 1000)"}
    
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
                "end_ea": hex_addr(f.end_ea)
            })
    except Exception:
        pass
    
    functions.sort(key=lambda x: int(x['start_ea'], 16))
    
    if pattern:
        functions = pattern_filter(functions, 'name', pattern)
    
    return paginate(functions, offset, count)  # type: ignore


# ============================================================================
# Global variables
# ============================================================================

@tool
@idaread
def list_globals(
    offset: Annotated[int, "Pagination offset (>=0)"] = 0,
    count: Annotated[int, "Number of items (1..1000)"] = 100,
    pattern: Annotated[Optional[str], "Optional name filter"] = None,
) -> dict:
    """List global (non-function) symbols with pagination."""
    if offset < 0:
        return {"error": "offset < 0"}
    if count <= 0:
        return {"error": "count must be > 0"}
    if count > 1000:
        return {"error": "count too large (max 1000)"}
    
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
    
    if pattern:
        entries = pattern_filter(entries, 'name', pattern)
    
    return paginate(entries, offset, count)  # type: ignore


# ============================================================================
# Strings
# ============================================================================

@tool
@idaread
def list_strings(
    offset: Annotated[int, "Pagination offset (>=0)"] = 0,
    count: Annotated[int, "Number of items (1..1000)"] = 100,
    pattern: Annotated[Optional[str], "Optional content filter"] = None,
) -> dict:
    """List extracted strings with pagination."""
    if offset < 0:
        return {"error": "offset < 0"}
    if count <= 0:
        return {"error": "count must be > 0"}
    if count > 1000:
        return {"error": "count too large (max 1000)"}
    
    substr = (pattern or '').lower()
    cached = _get_strings_cache()
    
    if substr:
        items = [
            {'ea': ea, 'length': length, 'type': stype, 'text': text}
            for ea, length, stype, text in cached
            if substr in text.lower()
        ]
    else:
        items = [
            {'ea': ea, 'length': length, 'type': stype, 'text': text}
            for ea, length, stype, text in cached
        ]
    
    return paginate(items, offset, count)  # type: ignore


# ============================================================================
# Local types
# ============================================================================

@tool
@idaread
def list_local_types() -> dict:
    """List all local types defined in the database."""
    items: List[dict] = []
    try:
        qty = ida_typeinf.get_ordinal_qty()  # type: ignore
    except Exception:
        qty = 0
    
    max_len = 512
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
        if len(decl) > max_len:
            decl = decl[:max_len] + '...'
        
        items.append({
            'ordinal': ordinal,
            'name': name,
            'decl': decl,
        })
    
    return {"total": len(items), "items": items}


# ============================================================================
# Entry points
# ============================================================================

@tool
@idaread
def get_entry_points() -> dict:
    """Get all program entry points."""
    out: List[dict] = []
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
                    f = ida_funcs.get_func(ea)
                    if f and int(f.start_ea) == int(ea):
                        name = idaapi.get_func_name(f.start_ea)
                except Exception:
                    name = None
            out.append({
                'ordinal': int(ordv),
                'ea': int(ea),
                'name': name,
            })
        except Exception:
            continue
    
    return {"total": len(out), "items": out}


# ============================================================================
# Number conversion
# ============================================================================

@tool
def convert_number(
    text: Annotated[str, "Numeric text (decimal, 0x, 0b, trailing h)"],
    size: Annotated[int, "Bit width: 8, 16, 32, or 64"] = 64,
) -> dict:
    """Convert number to different formats (hex, dec, bin, bytes)."""
    allowed = {8, 16, 32, 64}
    if size not in allowed:
        return {"error": f"invalid size (must be one of {sorted(allowed)})"}
    if not isinstance(text, str) or not text.strip():
        return {"error": "empty text"}
    
    original = text
    s = text.strip().replace('_', '')
    
    try:
        if s.lower().endswith('h') and len(s) > 1:
            core = s[:-1]
            sign = ''
            if core.startswith(('+', '-')):
                sign = core[0]
                core = core[1:]
            if core and all(c in '0123456789abcdefABCDEF' for c in core):
                parsed_raw = int(sign + '0x' + core, 0)
            else:
                raise ValueError("invalid trailing h hex")
        else:
            parsed_raw = int(s, 0)
    except Exception:
        return {"error": "parse failed"}
    
    mask = (1 << size) - 1
    value = parsed_raw & mask
    unsigned_val = value
    
    if value & (1 << (size - 1)):
        signed_val = value - (1 << size)
    else:
        signed_val = value
    
    hex_width = size // 4
    hex_repr = f"0x{value:0{hex_width}X}"
    bin_repr = f"0b{value:0{size}b}"
    num_bytes = size // 8
    bytes_le = [f"{(value >> (8 * i)) & 0xFF:02X}" for i in range(num_bytes)]
    bytes_be = list(reversed(bytes_le))
    
    return {
        "input": original,
        "size": size,
        "value": value,
        "hex": hex_repr,
        "dec": str(unsigned_val),
        "unsigned": unsigned_val,
        "signed": signed_val,
        "bin": bin_repr,
        "bytes_le": bytes_le,
        "bytes_be": bytes_be,
    }


# ============================================================================
# Imports
# ============================================================================

@tool
@idaread
def list_imports(
    offset: Annotated[int, "Pagination offset (>=0)"] = 0,
    count: Annotated[int, "Number of items (1..1000)"] = 100,
    pattern: Annotated[Optional[str], "Optional name filter"] = None,
) -> dict:
    """List imported functions with module names."""
    if offset < 0:
        return {"error": "offset < 0"}
    if count <= 0:
        return {"error": "count must be > 0"}
    if count > 1000:
        return {"error": "count too large (max 1000)"}
    
    items: List[dict] = []
    
    def import_callback(ea: int, name: str, ordinal: int) -> bool:
        """Callback to collect each import item."""
        if name:
            items.append({
                "ea": hex_addr(ea),
                "name": name,
                "ordinal": ordinal if ordinal else None,
                "module": current_module,
            })
        return True  # continue enumeration
    
    try:
        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            current_module = idaapi.get_import_module_name(i)
            if current_module is None:
                current_module = f"module_{i}"
            idaapi.enum_import_names(i, import_callback)
    except Exception:
        pass
    
    items.sort(key=lambda x: (x.get('module', ''), x.get('name', '')))
    
    if pattern:
        # support searching by function name or module name
        substr = pattern.lower()
        items = [
            it for it in items 
            if substr in it.get('name', '').lower() or substr in it.get('module', '').lower()
        ]
    
    return paginate(items, offset, count)  # type: ignore


# ============================================================================
# Exports
# ============================================================================

@tool
@idaread
def list_exports(
    offset: Annotated[int, "Pagination offset (>=0)"] = 0,
    count: Annotated[int, "Number of items (1..1000)"] = 100,
    pattern: Annotated[Optional[str], "Optional name filter"] = None,
) -> dict:
    """List exported functions/symbols."""
    if offset < 0:
        return {"error": "offset < 0"}
    if count <= 0:
        return {"error": "count must be > 0"}
    if count > 1000:
        return {"error": "count too large (max 1000)"}
    
    items: List[dict] = []
    
    try:
        for entry_idx, ordinal, ea, name in idautils.Entries():
            if name:
                items.append({
                    "ea": hex_addr(ea),
                    "name": name,
                    "ordinal": ordinal if ordinal else None,
                })
    except Exception:
        pass
    
    items.sort(key=lambda x: int(x['ea'], 16))
    
    if pattern:
        items = pattern_filter(items, 'name', pattern)
    
    return paginate(items, offset, count)  # type: ignore


# ============================================================================
# Memory segments
# ============================================================================

@tool
@idaread
def list_segments() -> dict:
    """List memory segments with permissions."""
    items: List[dict] = []
    
    try:
        for seg in idautils.Segments():
            s = ida_segment.getseg(seg)
            if not s:
                continue
            
            name = ida_segment.get_segm_name(s)
            seg_class = ida_segment.get_segm_class(s)
            
            # parse permissions
            perm = s.perm
            readable = bool(perm & ida_segment.SEGPERM_READ)
            writable = bool(perm & ida_segment.SEGPERM_WRITE)
            executable = bool(perm & ida_segment.SEGPERM_EXEC)
            perm_str = f"{'r' if readable else '-'}{'w' if writable else '-'}{'x' if executable else '-'}"
            
            items.append({
                "name": name,
                "start_ea": hex_addr(s.start_ea),
                "end_ea": hex_addr(s.end_ea),
                "size": s.end_ea - s.start_ea,
                "perm": perm_str,
                "class": seg_class,
                "bitness": s.bitness * 16 + 16,  # 0=16bit, 1=32bit, 2=64bit
            })
    except Exception:
        pass
    
    return {"total": len(items), "items": items}


# ============================================================================
# Cursor position
# ============================================================================

@tool
@idaread
def get_cursor() -> dict:
    """Get current cursor position and context in IDA."""
    result: dict = {}
    
    # get current cursor address
    try:
        ea = ida_kernwin.get_screen_ea()
        result["ea"] = hex_addr(ea)
        result["ea_int"] = ea
    except Exception:
        result["ea"] = None
        result["ea_int"] = None
    
    # get current function
    ea_int = result.get("ea_int")
    if ea_int is not None:
        try:
            f = ida_funcs.get_func(ea_int)
            if f:
                result["function"] = {
                    "name": idaapi.get_func_name(f.start_ea),
                    "start_ea": hex_addr(f.start_ea),
                    "end_ea": hex_addr(f.end_ea),
                }
            else:
                result["function"] = None
        except Exception:
            result["function"] = None
    
    # get selection
    try:
        selection_start, selection_end = ida_kernwin.read_range_selection(None)
        if selection_start != idaapi.BADADDR and selection_end != idaapi.BADADDR:
            result["selection"] = {
                "start": hex_addr(selection_start),
                "end": hex_addr(selection_end),
                "size": selection_end - selection_start,
            }
        else:
            result["selection"] = None
    except Exception:
        result["selection"] = None
    
    return result
