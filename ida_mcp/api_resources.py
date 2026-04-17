"""Read-only MCP resources for stable IDA context snapshots."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .rpc import resource
from .strings_cache import get_strings_cache
from .sync import idaread
from .utils import hex_addr

try:
    import idaapi  # type: ignore
except ImportError:  # pragma: no cover
    idaapi = None

try:
    import idautils  # type: ignore
except ImportError:  # pragma: no cover
    idautils = None

try:
    import ida_funcs  # type: ignore
except ImportError:  # pragma: no cover
    ida_funcs = None

try:
    import ida_bytes  # type: ignore
except ImportError:  # pragma: no cover
    ida_bytes = None

try:
    import ida_name  # type: ignore
except ImportError:  # pragma: no cover
    ida_name = None

try:
    import ida_typeinf  # type: ignore
except ImportError:  # pragma: no cover
    ida_typeinf = None

try:
    import ida_segment  # type: ignore
except ImportError:  # pragma: no cover
    ida_segment = None


def _json_resource(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _resource_error(code: str, message: str, **details: Any) -> str:
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details:
        payload["error"]["details"] = details
    return _json_resource(payload)


def _resource_list(kind: str, items: list[dict[str, Any]], **fields: Any) -> str:
    payload: dict[str, Any] = {
        "kind": kind,
        "count": len(items),
        "items": items,
    }
    payload.update(fields)
    return _json_resource(payload)


def _resource_detail(kind: str, **fields: Any) -> str:
    payload: dict[str, Any] = {
        "kind": kind,
    }
    payload.update(fields)
    return _json_resource(payload)


def _first_tool_result(result: Any) -> dict[str, Any]:
    if isinstance(result, list) and result:
        first = result[0]
        if isinstance(first, dict):
            return first
    return {"error": "empty result"}


def _parse_addr_or_error(addr: str) -> tuple[Optional[int], Optional[str]]:
    from .utils import parse_address

    parsed = parse_address(addr)
    if not parsed["ok"] or parsed["value"] is None:
        return None, _resource_error("invalid_address", "Invalid address.", address=addr)
    return parsed["value"], None


def _function_summary(ea: int) -> Optional[dict[str, Any]]:
    if ida_funcs is None or idaapi is None:
        return None
    try:
        fn = ida_funcs.get_func(ea)
    except Exception:
        fn = None
    if not fn:
        return None
    return {
        "address": hex_addr(fn.start_ea),
        "name": idaapi.get_func_name(fn.start_ea),
        "end_address": hex_addr(fn.end_ea),
        "size": int(fn.end_ea) - int(fn.start_ea),
    }


def _list_functions_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idautils is None:
        return items
    try:
        for ea in idautils.Functions():
            summary = _function_summary(int(ea))
            if summary:
                items.append(summary)
    except Exception:
        return items
    items.sort(key=lambda item: int(item["address"], 16))
    return items


def _list_strings_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for ea, length, stype, text in get_strings_cache():
        items.append(
            {
                "address": hex_addr(ea),
                "length": length,
                "type": stype,
                "text": text,
            }
        )
    return items


def _list_globals_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idautils is None or ida_funcs is None:
        return items
    try:
        for ea, name in idautils.Names():
            try:
                fn = ida_funcs.get_func(ea)
                if fn and int(fn.start_ea) == int(ea):
                    continue
            except Exception:
                pass

            size = None
            try:
                size = ida_bytes.get_item_size(ea) if ida_bytes is not None else None
            except Exception:
                size = None
            items.append(
                {
                    "address": hex_addr(ea),
                    "name": name,
                    "size": size,
                }
            )
    except Exception:
        return items
    items.sort(key=lambda item: int(item["address"], 16))
    return items


def _list_types_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if ida_typeinf is None or idaapi is None:
        return items
    try:
        qty = ida_typeinf.get_ordinal_qty()  # type: ignore[attr-defined]
    except Exception:
        qty = 0

    for ordinal in range(1, qty + 1):
        try:
            name = ida_typeinf.get_numbered_type_name(idaapi.cvar.idati, ordinal)  # type: ignore[attr-defined]
        except Exception:
            name = None
        if not name:
            continue

        decl = None
        try:
            tif = ida_typeinf.tinfo_t()
            ida_typeinf.get_numbered_type(idaapi.cvar.idati, ordinal, tif)  # type: ignore[attr-defined]
            try:
                decl = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, "")  # type: ignore[attr-defined]
            except Exception:
                decl = None
        except Exception:
            decl = None

        if decl is None:
            decl = name
        items.append(
            {
                "ordinal": ordinal,
                "name": name,
                "decl": decl if len(decl) <= 256 else decl[:256] + "...",
            }
        )
    return items


def _normalize_segment_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "start_address": item.get("start_ea"),
        "end_address": item.get("end_ea"),
        "size": item.get("size"),
        "perm": item.get("perm"),
        "class": item.get("class"),
        "bitness": item.get("bitness"),
    }


def _normalize_import_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "module": item.get("module"),
        "name": item.get("name"),
        "address": item.get("ea"),
        "ordinal": item.get("ordinal"),
    }


def _normalize_export_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "address": item.get("ea"),
        "ordinal": item.get("ordinal"),
    }


def _list_import_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idaapi is None:
        return items
    try:
        nimps = idaapi.get_import_module_qty()
        for index in range(nimps):
            module_name = idaapi.get_import_module_name(index)

            def _collect(ea: int, name: str, ordinal: int) -> bool:
                items.append(
                    {
                        "module": module_name,
                        "name": name,
                        "address": hex_addr(ea),
                        "ordinal": ordinal or None,
                    }
                )
                return True

            idaapi.enum_import_names(index, _collect)
    except Exception:
        return items
    items.sort(key=lambda item: (str(item.get("module") or ""), str(item.get("name") or "")))
    return items


def _list_export_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if idautils is None:
        return items
    try:
        for _, ordinal, ea, name in idautils.Entries():
            items.append(
                {
                    "name": name,
                    "address": hex_addr(ea),
                    "ordinal": ordinal or None,
                }
            )
    except Exception:
        return items
    items.sort(key=lambda item: int(item["address"], 16))
    return items


def _normalize_entry_point_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "address": hex_addr(item["ea"]),
        "ordinal": item.get("ordinal"),
    }


def _normalize_xref_item(item: dict[str, Any], direction: str) -> dict[str, Any]:
    if direction == "to":
        return {
            "address": item.get("frm"),
            "type": item.get("type"),
            "is_code": bool(item.get("iscode")),
        }
    return {
        "address": item.get("to"),
        "type": item.get("type"),
        "is_code": bool(item.get("iscode")),
    }


def _summarize_xrefs(address: str, items: list[dict[str, Any]], direction: str) -> str:
    grouped: dict[str, dict[str, Any]] = {}
    code_count = 0

    for item in items:
        ref_address = item.get("address")
        if not isinstance(ref_address, str):
            continue
        if item.get("is_code"):
            code_count += 1

        key = ref_address
        name = None
        fn_address = None
        try:
            ref_int = int(ref_address, 16)
            if ida_funcs is not None and idaapi is not None:
                fn = ida_funcs.get_func(ref_int)
                if fn:
                    fn_address = hex_addr(fn.start_ea)
                    name = idaapi.get_func_name(fn.start_ea)
                    key = fn_address
        except Exception:
            pass

        bucket = grouped.setdefault(
            key,
            {
                "address": fn_address or ref_address,
                "name": name,
                "count": 0,
            },
        )
        bucket["count"] += 1

    summary_items = sorted(grouped.values(), key=lambda item: (-item["count"], item["address"]))
    return _resource_detail(
        f"xrefs_{direction}_summary",
        address=address,
        count=len(items),
        code_count=code_count,
        data_count=len(items) - code_count,
        items=summary_items,
    )


def _segment_detail_from_name_or_addr(name_or_addr: str) -> Optional[dict[str, Any]]:
    from .api_core import list_segments

    segments = list_segments.__wrapped__().get("items", [])

    parsed_address = None
    try:
        parsed_address, _ = _parse_addr_or_error(name_or_addr)
    except Exception:
        parsed_address = None

    for item in segments:
        normalized = _normalize_segment_item(item)
        if normalized["name"] == name_or_addr:
            return normalized
        if parsed_address is not None:
            start = int(normalized["start_address"], 16)
            end = int(normalized["end_address"], 16)
            if start <= parsed_address < end:
                return normalized
    return None


@resource(uri="ida://idb/metadata")
@idaread
def idb_metadata_resource() -> str:
    from .api_core import get_metadata

    return _resource_detail("idb_metadata", **get_metadata.__wrapped__())


@resource(uri="ida://functions")
@idaread
def functions_resource() -> str:
    return _resource_list("functions", _list_functions_items())


@resource(uri="ida://function/{addr}")
@idaread
def function_resource(addr: str) -> str:
    address, error = _parse_addr_or_error(addr)
    if error:
        return error
    assert address is not None
    item = _function_summary(address)
    if not item:
        return _resource_error("function_not_found", "Function not found.", address=addr)
    return _resource_detail("function", **item)


@resource(uri="ida://function/{addr}/decompile")
@idaread
def function_decompile_resource(addr: str) -> str:
    from .api_analysis import decompile

    result = _first_tool_result(decompile.__wrapped__(addr))
    if result.get("error"):
        error = str(result["error"])
        code = "function_not_found" if "not found" in error else "decompile_failed"
        return _resource_error(code, error, address=addr)
    return _resource_detail(
        "function_decompile",
        address=result.get("start_ea"),
        name=result.get("name"),
        end_address=result.get("end_ea"),
        decompiled=result.get("decompiled"),
    )


@resource(uri="ida://function/{addr}/disasm")
@idaread
def function_disasm_resource(addr: str) -> str:
    from .api_analysis import disasm

    result = _first_tool_result(disasm.__wrapped__(addr))
    if result.get("error"):
        return _resource_error("disasm_failed", str(result["error"]), address=addr)
    instructions = [
        {
            "address": hex_addr(item["ea"]),
            "bytes": item.get("bytes"),
            "text": item.get("text"),
            "comment": item.get("comment"),
        }
        for item in result.get("instructions", [])
    ]
    return _resource_detail(
        "function_disasm",
        address=hex_addr(result["start_ea"]),
        name=result.get("name"),
        end_address=hex_addr(result["end_ea"]),
        count=len(instructions),
        items=instructions,
    )


@resource(uri="ida://function/{addr}/basic_blocks")
@idaread
def function_basic_blocks_resource(addr: str) -> str:
    from .api_analysis import get_basic_blocks

    result = get_basic_blocks.__wrapped__(addr)
    if result.get("error"):
        return _resource_error("basic_blocks_failed", str(result["error"]), address=addr)
    blocks = [
        {
            "start_address": block.get("start_ea"),
            "end_address": block.get("end_ea"),
            "size": block.get("size"),
            "predecessors": block.get("predecessors", []),
            "successors": block.get("successors", []),
            "type": block.get("type"),
        }
        for block in result.get("blocks", [])
    ]
    return _resource_detail(
        "function_basic_blocks",
        address=result.get("start_ea"),
        name=result.get("function"),
        end_address=result.get("end_ea"),
        count=len(blocks),
        items=blocks,
    )


@resource(uri="ida://function/{addr}/stack")
@idaread
def function_stack_resource(addr: str) -> str:
    from .api_stack import stack_frame

    result = _first_tool_result(stack_frame.__wrapped__(addr))
    if result.get("error"):
        return _resource_error("stack_frame_failed", str(result["error"]), address=addr)
    return _resource_detail(
        "function_stack",
        address=result.get("start_ea"),
        name=result.get("name"),
        method=result.get("method"),
        count=len(result.get("variables", [])),
        items=result.get("variables", []),
        frame_structure=result.get("frame_structure"),
    )


@resource(uri="ida://strings")
@idaread
def strings_resource() -> str:
    return _resource_list("strings", _list_strings_items())


@resource(uri="ida://globals")
@idaread
def globals_resource() -> str:
    return _resource_list("globals", _list_globals_items())


@resource(uri="ida://types")
@idaread
def types_resource() -> str:
    return _resource_list("types", _list_types_items())


@resource(uri="ida://segments")
@idaread
def segments_resource() -> str:
    from .api_core import list_segments

    items = [_normalize_segment_item(item) for item in list_segments.__wrapped__().get("items", [])]
    return _resource_list("segments", items)


@resource(uri="ida://segment/{name_or_addr}")
@idaread
def segment_resource(name_or_addr: str) -> str:
    item = _segment_detail_from_name_or_addr(name_or_addr)
    if not item:
        return _resource_error("segment_not_found", "Segment not found.", query=name_or_addr)
    return _resource_detail("segment", **item)


@resource(uri="ida://imports")
@idaread
def imports_resource() -> str:
    return _resource_list("imports", _list_import_items())


@resource(uri="ida://imports/{module}")
@idaread
def imports_module_resource(module: str) -> str:
    items = [
        item
        for item in _list_import_items()
        if str(item.get("module", "")).lower() == module.lower()
    ]
    return _resource_detail("imports_module", module=module, count=len(items), items=items)


@resource(uri="ida://exports")
@idaread
def exports_resource() -> str:
    return _resource_list("exports", _list_export_items())


@resource(uri="ida://entry_points")
@idaread
def entry_points_resource() -> str:
    from .api_core import get_entry_points

    result = get_entry_points.__wrapped__()
    items = [_normalize_entry_point_item(item) for item in result.get("items", [])]
    return _resource_list("entry_points", items)


@resource(uri="ida://structs")
@idaread
def structs_resource() -> str:
    from .api_types import list_structs

    result = list_structs.__wrapped__()
    return _resource_list("structs", result.get("items", []))


@resource(uri="ida://struct/{name}")
@idaread
def struct_resource(name: str) -> str:
    from .api_types import get_struct_info

    result = get_struct_info.__wrapped__(name)
    if result.get("error"):
        return _resource_error("struct_not_found", str(result["error"]), name=name)
    return _resource_detail(
        "struct",
        name=result.get("name"),
        struct_kind=result.get("kind"),
        size=result.get("size"),
        count=result.get("member_count", 0),
        items=result.get("members", []),
    )


@resource(uri="ida://xrefs/to/{addr}")
@idaread
def xrefs_to_resource(addr: str) -> str:
    from .api_analysis import xrefs_to

    result = _first_tool_result(xrefs_to.__wrapped__(addr))
    if result.get("error"):
        return _resource_error("xrefs_to_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "to") for item in result.get("xrefs", [])]
    return _resource_detail("xrefs_to", address=result.get("address"), count=len(items), items=items)


@resource(uri="ida://xrefs/to/{addr}/summary")
@idaread
def xrefs_to_summary_resource(addr: str) -> str:
    from .api_analysis import xrefs_to

    result = _first_tool_result(xrefs_to.__wrapped__(addr))
    if result.get("error"):
        return _resource_error("xrefs_to_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "to") for item in result.get("xrefs", [])]
    return _summarize_xrefs(result.get("address", addr), items, "to")


@resource(uri="ida://xrefs/from/{addr}")
@idaread
def xrefs_from_resource(addr: str) -> str:
    from .api_analysis import xrefs_from

    result = _first_tool_result(xrefs_from.__wrapped__(addr))
    if result.get("error"):
        return _resource_error("xrefs_from_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "from") for item in result.get("xrefs", [])]
    return _resource_detail("xrefs_from", address=result.get("address"), count=len(items), items=items)


@resource(uri="ida://xrefs/from/{addr}/summary")
@idaread
def xrefs_from_summary_resource(addr: str) -> str:
    from .api_analysis import xrefs_from

    result = _first_tool_result(xrefs_from.__wrapped__(addr))
    if result.get("error"):
        return _resource_error("xrefs_from_failed", str(result["error"]), address=addr)
    items = [_normalize_xref_item(item, "from") for item in result.get("xrefs", [])]
    return _summarize_xrefs(result.get("address", addr), items, "from")


@resource(uri="ida://memory/{addr}")
@idaread
def memory_resource(addr: str, size: int = 16) -> str:
    from .api_memory import get_bytes

    address, error = _parse_addr_or_error(addr)
    if error:
        return error
    assert address is not None
    result = get_bytes.__wrapped__(hex_addr(address), size=size)
    if not result:
        return _resource_error("memory_read_failed", "Failed to read memory.", address=hex_addr(address))
    first = result[0]
    if first.get("error"):
        return _resource_error("memory_read_failed", str(first["error"]), address=hex_addr(address))
    return _resource_detail(
        "memory",
        address=hex_addr(address),
        size=first.get("size"),
        bytes=first.get("bytes"),
        hex=first.get("hex"),
    )
