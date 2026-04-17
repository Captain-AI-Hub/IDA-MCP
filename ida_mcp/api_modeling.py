"""Modeling API - database shaping and code/data creation.

Provides tools:
    - create_function   Create a function at an address
    - delete_function   Delete an existing function
    - make_code         Convert bytes at an address into code
    - undefine_items    Undefine a range of items
    - make_data         Create typed data items
    - make_string       Create a string literal
"""
from __future__ import annotations

from typing import Annotated, Optional, Union, Dict, Any, Tuple

from .rpc import tool
from .strings_cache import invalidate_strings_cache
from .sync import idawrite, wait_for_auto_analysis
from .utils import parse_address, hex_addr

try:
    import idaapi  # type: ignore
except ImportError:
    idaapi = None

try:
    import ida_bytes  # type: ignore
except ImportError:
    ida_bytes = None

try:
    import ida_funcs  # type: ignore
except ImportError:
    ida_funcs = None

try:
    import ida_nalt  # type: ignore
except ImportError:
    ida_nalt = None

try:
    import ida_ida  # type: ignore
except ImportError:
    ida_ida = None

try:
    import ida_ua  # type: ignore
except ImportError:
    ida_ua = None


def _error(message: str, **extra: Any) -> dict:
    result = {"error": message}
    result.update(extra)
    return result


def _invalidate_strings_cache() -> None:
    invalidate_strings_cache()


def _resolve_address(value: Union[int, str], field: str) -> Tuple[Optional[int], Optional[dict]]:
    parsed = parse_address(value)
    if not parsed["ok"] or parsed["value"] is None:
        return None, _error(f"invalid {field}", **{field: value})
    return int(parsed["value"]), None


def _describe_function(ea: int) -> Optional[dict]:
    if ida_funcs is None or idaapi is None:
        return None

    try:
        func = ida_funcs.get_func(ea)
    except Exception:
        func = None

    if not func:
        return None

    try:
        name = idaapi.get_func_name(func.start_ea)
    except Exception:
        name = None

    return {
        "name": name,
        "start_ea": hex_addr(int(func.start_ea)),
        "end_ea": hex_addr(int(func.end_ea)),
    }


def _item_flags(ea: int) -> int:
    if ida_bytes is None:
        return 0
    try:
        return int(ida_bytes.get_full_flags(ea))
    except Exception:
        return 0


def _is_string_item(head: int, flags: int) -> bool:
    if ida_bytes is None:
        return False

    checker = getattr(ida_bytes, "is_strlit", None)
    if checker is None:
        return False

    for candidate in (flags, head):
        try:
            if checker(candidate):
                return True
        except Exception:
            continue
    return False


def _describe_item(ea: int) -> dict:
    if ida_bytes is None:
        return {"ea": hex_addr(ea), "head": hex_addr(ea), "size": None, "kind": "unknown"}

    try:
        head = int(ida_bytes.get_item_head(ea))
    except Exception:
        head = ea

    try:
        size = int(ida_bytes.get_item_size(head))
    except Exception:
        size = 1

    flags = _item_flags(ea)
    head_flags = _item_flags(head)

    kind = "unknown"
    try:
        if ida_bytes.is_code(flags):
            kind = "code"
        elif ida_bytes.is_unknown(flags):
            kind = "unknown"
        elif _is_string_item(head, head_flags):
            kind = "string"
        elif ida_bytes.is_tail(flags):
            kind = "tail"
        elif ida_bytes.is_data(head_flags):
            kind = "data"
    except Exception:
        kind = "unknown"

    result = {
        "ea": hex_addr(ea),
        "head": hex_addr(head),
        "size": size,
        "kind": kind,
    }

    func = _describe_function(ea)
    if func:
        result["function"] = func

    return result


def _range_is_unknown(ea: int, size: int) -> bool:
    if ida_bytes is None:
        return False

    for current in range(ea, ea + size):
        try:
            if not ida_bytes.is_unknown(ida_bytes.get_full_flags(current)):
                return False
        except Exception:
            return False
    return True


def _undefine_range(ea: int, size: int) -> bool:
    if ida_bytes is None:
        return False
    flags = getattr(ida_bytes, "DELIT_SIMPLE", 0)
    try:
        return bool(ida_bytes.del_items(ea, flags, size))
    except Exception:
        return False


def _ensure_code(ea: int) -> bool:
    if ida_bytes is None or ida_ua is None:
        return False

    try:
        if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            return True
    except Exception:
        pass

    try:
        head = int(ida_bytes.get_item_head(ea))
    except Exception:
        head = ea

    try:
        size = int(ida_bytes.get_item_size(head))
    except Exception:
        size = 1

    if size <= 0:
        size = 1

    _undefine_range(head, size)

    try:
        created = ida_ua.create_insn(ea)
        return bool(created)
    except Exception:
        return False


def _pointer_kind() -> str:
    try:
        if ida_ida is not None and ida_ida.inf_is_64bit():
            return "qword"
    except Exception:
        pass
    return "dword"


def _normalize_data_kind(kind: str) -> str:
    normalized = (kind or "").strip().lower().replace("-", "_")
    if normalized == "pointer":
        return _pointer_kind()
    return normalized


def _string_type_value(string_type: str) -> Tuple[Optional[int], Optional[str]]:
    if ida_nalt is None:
        return None, "ida_nalt unavailable"

    key = (string_type or "c").strip().lower().replace("-", "_")
    mapping = {
        "termchr": "STRTYPE_TERMCHR",
        "c": "STRTYPE_C",
        "c_16": "STRTYPE_C_16",
        "c16": "STRTYPE_C_16",
        "c_32": "STRTYPE_C_32",
        "c32": "STRTYPE_C_32",
        "pascal": "STRTYPE_PASCAL",
        "pascal_16": "STRTYPE_PASCAL_16",
        "pascal16": "STRTYPE_PASCAL_16",
        "pascal_32": "STRTYPE_PASCAL_32",
        "pascal32": "STRTYPE_PASCAL_32",
        "len2": "STRTYPE_LEN2",
        "len2_16": "STRTYPE_LEN2_16",
        "len216": "STRTYPE_LEN2_16",
        "len2_32": "STRTYPE_LEN2_32",
        "len232": "STRTYPE_LEN2_32",
        "len4": "STRTYPE_LEN4",
        "len4_16": "STRTYPE_LEN4_16",
        "len416": "STRTYPE_LEN4_16",
        "len4_32": "STRTYPE_LEN4_32",
        "len432": "STRTYPE_LEN4_32",
    }

    constant_name = mapping.get(key)
    if not constant_name:
        return None, "unsupported string_type"

    value = getattr(ida_nalt, constant_name, None)
    if value is None:
        return None, f"{constant_name} unavailable"

    return int(value), None


def _create_numeric_items(ea: int, kind: str, count: int) -> Tuple[bool, int]:
    if ida_bytes is None:
        return False, 0

    creators = {
        "byte": (getattr(ida_bytes, "create_byte", None), 1),
        "word": (getattr(ida_bytes, "create_word", None), 2),
        "dword": (getattr(ida_bytes, "create_dword", None), 4),
        "qword": (getattr(ida_bytes, "create_qword", None), 8),
    }

    if kind in creators:
        creator, elem_size = creators[kind]
        if creator is None:
            return False, 0
        try:
            return bool(creator(ea, elem_size * count, True)), elem_size
        except Exception:
            return False, elem_size

    if kind == "oword":
        creator = getattr(ida_bytes, "create_oword", None)
        elem_size = 16
        if creator is None:
            return False, elem_size
        try:
            if count == 1:
                return bool(creator(ea)), elem_size
            for index in range(count):
                if not creator(ea + index * elem_size):
                    return False, elem_size
            return True, elem_size
        except Exception:
            return False, elem_size

    if kind == "float":
        creator = getattr(ida_bytes, "create_float", None)
        elem_size = 4
        if creator is None:
            return False, elem_size
        try:
            for index in range(count):
                if not creator(ea + index * elem_size):
                    return False, elem_size
            return True, elem_size
        except Exception:
            return False, elem_size

    if kind == "double":
        creator = getattr(ida_bytes, "create_double", None)
        elem_size = 8
        if creator is None:
            return False, elem_size
        try:
            for index in range(count):
                if not creator(ea + index * elem_size):
                    return False, elem_size
            return True, elem_size
        except Exception:
            return False, elem_size

    return False, 0


def _estimated_span(kind: str, count: int) -> int:
    element_sizes = {
        "byte": 1,
        "word": 2,
        "dword": 4,
        "qword": 8,
        "oword": 16,
        "float": 4,
        "double": 8,
    }
    return element_sizes.get(kind, 0) * count


@tool
@idawrite
def create_function(
    address: Annotated[Union[int, str], "Function start address (hex or decimal)"],
    end: Annotated[Optional[Union[int, str]], "Optional function end address (exclusive)"] = None,
) -> dict:
    """Create a function at an address."""
    wait_for_auto_analysis()

    if ida_funcs is None or idaapi is None:
        return _error("IDA function APIs unavailable")

    start_ea, err = _resolve_address(address, "address")
    if err:
        return err
    assert start_ea is not None

    end_ea = None
    if end is not None:
        end_ea, err = _resolve_address(end, "end")
        if err:
            return err
        if end_ea is not None and end_ea <= start_ea:
            return _error("end must be greater than address", address=hex_addr(start_ea), end=hex_addr(end_ea))

    existing = _describe_function(start_ea)
    if existing and existing["start_ea"] == hex_addr(start_ea):
        return {
            "address": hex_addr(start_ea),
            "requested_end": hex_addr(end_ea) if end_ea is not None else None,
            "function": existing,
            "changed": False,
            "note": "function already exists",
        }

    if not _ensure_code(start_ea):
        return _error("failed to create code at function start", address=hex_addr(start_ea))

    target_end = end_ea if end_ea is not None else getattr(idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    try:
        ok = bool(ida_funcs.add_func(start_ea, target_end))
    except Exception as exc:
        return _error(f"add_func failed: {exc}", address=hex_addr(start_ea))

    wait_for_auto_analysis()

    function = _describe_function(start_ea)
    if not ok and function is None:
        return _error("failed to create function", address=hex_addr(start_ea))

    return {
        "address": hex_addr(start_ea),
        "requested_end": hex_addr(end_ea) if end_ea is not None else None,
        "function": function,
        "changed": True,
    }


@tool
@idawrite
def delete_function(
    address: Annotated[Union[int, str], "Function start or internal address (hex or decimal)"],
) -> dict:
    """Delete an existing function."""
    wait_for_auto_analysis()

    if ida_funcs is None:
        return _error("IDA function APIs unavailable")

    ea, err = _resolve_address(address, "address")
    if err:
        return err
    assert ea is not None

    previous = _describe_function(ea)
    if previous is None:
        return {
            "address": hex_addr(ea),
            "changed": False,
            "note": "function not found",
        }

    delete_ea = int(previous["start_ea"], 16)

    try:
        ok = bool(ida_funcs.del_func(delete_ea))
    except Exception as exc:
        return _error(f"del_func failed: {exc}", address=hex_addr(ea))

    wait_for_auto_analysis()

    return {
        "address": hex_addr(ea),
        "old_function": previous,
        "changed": ok,
    }


@tool
@idawrite
def make_code(
    address: Annotated[Union[int, str], "Address to convert into code"],
) -> dict:
    """Convert bytes at an address into code."""
    ea, err = _resolve_address(address, "address")
    if err:
        return err
    assert ea is not None

    before = _describe_item(ea)
    if before["kind"] == "code":
        return {
            "address": hex_addr(ea),
            "old_item": before,
            "new_item": before,
            "changed": False,
            "note": "already code",
        }

    ok = _ensure_code(ea)
    wait_for_auto_analysis()
    after = _describe_item(ea)

    if not ok or after["kind"] != "code":
        return _error("failed to create code", address=hex_addr(ea), old_item=before, new_item=after)

    _invalidate_strings_cache()

    return {
        "address": hex_addr(ea),
        "old_item": before,
        "new_item": after,
        "changed": True,
    }


@tool
@idawrite
def undefine_items(
    address: Annotated[Union[int, str], "Start address of the range to undefine"],
    size: Annotated[int, "Number of bytes to undefine"],
) -> dict:
    """Undefine items in a range."""
    if size <= 0:
        return _error("size must be greater than zero", size=size)

    ea, err = _resolve_address(address, "address")
    if err:
        return err
    assert ea is not None

    before = _describe_item(ea)
    if _range_is_unknown(ea, size):
        return {
            "address": hex_addr(ea),
            "size": size,
            "old_item": before,
            "changed": False,
            "note": "range already undefined",
        }

    ok = _undefine_range(ea, size)
    after = _describe_item(ea)

    if not ok:
        return _error("failed to undefine items", address=hex_addr(ea), size=size, old_item=before, new_item=after)

    _invalidate_strings_cache()

    return {
        "address": hex_addr(ea),
        "size": size,
        "old_item": before,
        "new_item": after,
        "changed": True,
    }


@tool
@idawrite
def make_data(
    address: Annotated[Union[int, str], "Address to convert into typed data"],
    data_type: Annotated[str, "Data type: byte, word, dword, qword, oword, float, double, pointer"],
    count: Annotated[int, "Number of items to create"] = 1,
) -> dict:
    """Create typed data items at an address."""
    if count <= 0:
        return _error("count must be greater than zero", count=count)

    ea, err = _resolve_address(address, "address")
    if err:
        return err
    assert ea is not None

    kind = _normalize_data_kind(data_type)
    before = _describe_item(ea)
    span = _estimated_span(kind, count)
    if span <= 0:
        return _error(
            "unsupported or failed data_type",
            address=hex_addr(ea),
            data_type=data_type,
            normalized_type=kind,
            count=count,
            old_item=before,
            new_item=before,
        )

    clear_start = int(before["head"], 16) if before["kind"] != "unknown" else ea
    clear_size = max(span, int(before.get("size") or 1))
    _undefine_range(clear_start, clear_size)

    ok, elem_size = _create_numeric_items(ea, kind, count)
    wait_for_auto_analysis()
    after = _describe_item(ea)

    if not ok:
        return _error(
            "unsupported or failed data_type",
            address=hex_addr(ea),
            data_type=data_type,
            normalized_type=kind,
            count=count,
            old_item=before,
            new_item=after,
        )

    _invalidate_strings_cache()

    return {
        "address": hex_addr(ea),
        "data_type": data_type,
        "normalized_type": kind,
        "count": count,
        "item_size": elem_size,
        "old_item": before,
        "new_item": after,
        "changed": True,
    }


@tool
@idawrite
def make_string(
    address: Annotated[Union[int, str], "Address to convert into a string literal"],
    string_type: Annotated[str, "String type: c, c16, c32, pascal, len2, len4, ..."] = "c",
    length: Annotated[Optional[int], "Optional length override (0 or omitted lets IDA infer)"] = None,
) -> dict:
    """Create a string literal at an address."""
    if length is not None and length < 0:
        return _error("length must be zero or greater", length=length)

    if ida_bytes is None:
        return _error("IDA byte APIs unavailable")

    ea, err = _resolve_address(address, "address")
    if err:
        return err
    assert ea is not None

    strtype_value, strtype_error = _string_type_value(string_type)
    if strtype_error:
        return _error(strtype_error, string_type=string_type)
    assert strtype_value is not None

    requested_len = int(length or 0)
    before = _describe_item(ea)
    clear_start = int(before["head"], 16) if before["kind"] != "unknown" else ea
    clear_size = max(1, int(before.get("size") or 1), requested_len)
    if before["kind"] != "unknown" or requested_len > 1:
        _undefine_range(clear_start, clear_size)

    try:
        ok = bool(ida_bytes.create_strlit(ea, requested_len, strtype_value))
    except Exception as exc:
        return _error(f"create_strlit failed: {exc}", address=hex_addr(ea), string_type=string_type)

    wait_for_auto_analysis()
    after = _describe_item(ea)

    if not ok or after["kind"] != "string":
        return _error("failed to create string", address=hex_addr(ea), string_type=string_type, old_item=before, new_item=after)

    _invalidate_strings_cache()

    return {
        "address": hex_addr(ea),
        "string_type": string_type,
        "length": requested_len if length is not None else None,
        "old_item": before,
        "new_item": after,
        "changed": True,
    }
