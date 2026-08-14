"""Compatibility shims for SDK functions renamed in IDA 9.4.

IDA 9.4 deprecated a number of long-standing APIs (``get_func``, ``getseg``,
``get_segm_name``, ``add_segm_ex``, ``get_func_frame``, ``define_stkvar``,
``delete_frame_members`` and the ``idautils.Functions``/``FuncItems``
iterators built on them). These helpers prefer the modern entry points and
fall back to the legacy ones on older IDA builds, so plugin code never calls
a deprecated alias directly.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional, Tuple

try:
    import ida_frame  # type: ignore
    import ida_funcs  # type: ignore
    import ida_segment  # type: ignore
    import idautils  # type: ignore
except ImportError:
    ida_frame = None
    ida_funcs = None
    ida_segment = None
    idautils = None

_HAS_FUNC_ENTRY_INFO = bool(ida_funcs) and hasattr(ida_funcs, "get_func_entry_info")
_HAS_FUNC_EA_BY_NUM = bool(ida_funcs) and hasattr(ida_funcs, "get_func_ea_by_num")
_HAS_SEGMENT_INFO = bool(ida_segment) and hasattr(ida_segment, "get_segment_info")
_HAS_ADD_SEGMENT_EX = bool(ida_segment) and hasattr(ida_segment, "add_segment_ex")
_HAS_FRAME_EA = bool(ida_frame) and hasattr(ida_frame, "get_func_frame_ea")


# ============================================================================
# Functions
# ============================================================================


def func_bounds(ea: int) -> Optional[Tuple[int, int]]:
    """Return (start_ea, end_ea) of the function containing ea, or None."""
    if ida_funcs is None:
        return None
    if _HAS_FUNC_ENTRY_INFO:
        try:
            info = ida_funcs.func_entry_info_t()
            if ida_funcs.get_func_entry_info(info, ea):
                return int(info.start_ea), int(info.end_ea)
        except Exception:
            pass
        return None
    try:
        f = ida_funcs.get_func(ea)
    except Exception:
        f = None
    if not f:
        return None
    return int(f.start_ea), int(f.end_ea)


def func_start(ea: int) -> Optional[int]:
    """Return the start address of the function containing ea, or None."""
    bounds = func_bounds(ea)
    return bounds[0] if bounds else None


def iter_function_starts(
    start: Optional[int] = None, end: Optional[int] = None
) -> Iterator[int]:
    """Yield function entry addresses, optionally within [start, end)."""
    if ida_funcs is None:
        return
    if _HAS_FUNC_EA_BY_NUM:
        for n in range(ida_funcs.get_func_qty()):
            ea = int(ida_funcs.get_func_ea_by_num(n))
            if start is not None and ea < start:
                continue
            if end is not None and ea >= end:
                continue
            yield ea
        return
    yield from idautils.Functions(start, end)


def iter_func_items(start_ea: int, end_ea: int) -> Iterator[int]:
    """Yield instruction/data heads within function bounds."""
    yield from idautils.Heads(start_ea, end_ea)


# ============================================================================
# Segments
# ============================================================================


def segment_info(ea: int) -> Optional[dict]:
    """Return {start_ea, end_ea, name, sclass, perm, bitness} for ea's segment."""
    if ida_segment is None:
        return None
    if _HAS_SEGMENT_INFO:
        try:
            si = ida_segment.segment_info_t()
            flags = ida_segment.GSI_NAME | ida_segment.GSI_SCLASS
            if ida_segment.get_segment_info(si, ea, flags):
                return {
                    "start_ea": int(si.start_ea),
                    "end_ea": int(si.end_ea),
                    "name": si.get_name() or None,
                    "sclass": si.get_sclass() or None,
                    "perm": int(si.get_perm()),
                    "bitness": int(si.get_bitness()),
                }
        except Exception:
            pass
        return None
    try:
        seg = ida_segment.getseg(ea)
    except Exception:
        seg = None
    if not seg:
        return None
    try:
        name = ida_segment.get_segm_name(seg)
    except Exception:
        name = None
    try:
        sclass = ida_segment.get_segm_class(seg)
    except Exception:
        sclass = None
    return {
        "start_ea": int(seg.start_ea),
        "end_ea": int(seg.end_ea),
        "name": name,
        "sclass": sclass,
        "perm": int(seg.perm),
        "bitness": int(seg.bitness),
    }


def segment_exists(ea: int) -> bool:
    """Whether ea belongs to a segment."""
    return segment_info(ea) is not None


def add_segment(
    start: int,
    end: int,
    name: str,
    sclass: str,
    perm: int,
    bitness_code: int,
) -> bool:
    """Create a segment. bitness_code is 0/1/2 for 16/32/64-bit."""
    if ida_segment is None:
        return False
    if _HAS_ADD_SEGMENT_EX:
        try:
            si = ida_segment.segment_info_t()
            si.start_ea = start
            si.end_ea = end
            si.set_perm(perm)
            si.set_bitness(bitness_code)
            si.set_name(name)
            si.set_sclass(sclass)
            return bool(ida_segment.add_segment_ex(si, 0))
        except Exception:
            return False
    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea = end
    seg.perm = perm
    seg.bitness = bitness_code
    return bool(ida_segment.add_segm_ex(seg, name, sclass, 0))


# ============================================================================
# Stack frames
# ============================================================================


def _legacy_func_t(ea: int) -> Any:
    """func_t pointer for fallback paths on pre-9.4 IDA builds."""
    if ida_funcs is None:
        return None
    try:
        return ida_funcs.get_func(ea)
    except Exception:
        return None


def get_func_frame(tif: Any, func_ea: int) -> bool:
    """Load a function frame type into tif."""
    if ida_frame is None:
        return False
    if _HAS_FRAME_EA:
        try:
            return bool(ida_frame.get_func_frame_ea(tif, func_ea))
        except Exception:
            return False
    f = _legacy_func_t(func_ea)
    return bool(f) and bool(ida_frame.get_func_frame(tif, f))


def get_frame_id(func_ea: int) -> Optional[int]:
    """Netnode id of the function's frame structure, if available."""
    if _HAS_FUNC_ENTRY_INFO:
        try:
            info = ida_funcs.func_entry_info_t()
            if ida_funcs.get_func_entry_info(info, func_ea):
                frame_id = info.get_frame_id()
                return int(frame_id) if frame_id else None
        except Exception:
            return None
        return None
    f = _legacy_func_t(func_ea)
    if not f:
        return None
    frame_id = getattr(f, "frame", None)
    return int(frame_id) if frame_id else None


def define_stkvar(func_ea: int, name: str, offset: int, tif: Any) -> bool:
    """Define/redefine a stack variable in a function frame."""
    if ida_frame is None:
        return False
    if _HAS_FRAME_EA:
        return bool(ida_frame.define_stkvar_ea(func_ea, name, offset, tif))
    f = _legacy_func_t(func_ea)
    if not f:
        return False
    return bool(ida_frame.define_stkvar(f, name, offset, tif))


def add_frame_member(func_ea: int, name: str, offset: int, tif: Any) -> bool:
    """Add a member to a function frame type."""
    if ida_frame is None:
        return False
    if hasattr(ida_frame, "add_frame_member_ea"):
        return bool(ida_frame.add_frame_member_ea(func_ea, name, offset, tif))
    f = _legacy_func_t(func_ea)
    if not f:
        return False
    return bool(ida_frame.add_frame_member(f, name, offset, tif))


def delete_frame_members(func_ea: int, start_offset: int, end_offset: int) -> bool:
    """Delete frame members in [start_offset, end_offset)."""
    if ida_frame is None:
        return False
    if hasattr(ida_frame, "delete_frame_members_ea"):
        try:
            return bool(
                ida_frame.delete_frame_members_ea(func_ea, start_offset, end_offset)
            )
        except Exception:
            return False
    f = _legacy_func_t(func_ea)
    if not f:
        return False
    return bool(ida_frame.delete_frame_members(f, start_offset, end_offset))
