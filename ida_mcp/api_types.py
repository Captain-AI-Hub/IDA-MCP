"""类型 API - 类型操作。

提供工具:
    - declare_struct       声明/更新结构体
    - declare_enum         声明/更新枚举
    - declare_typedef      声明/更新 typedef
    - set_function_prototype  设置函数原型
    - set_local_variable_type 设置局部变量类型
    - set_global_variable_type 设置全局变量类型
    - list_structs         列出结构体
    - get_struct_info      获取结构体详情
"""
from __future__ import annotations

import re
from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread, idawrite, wait_for_auto_analysis
from .utils import parse_address, is_valid_c_identifier, hex_addr

# IDA 模块导入
try:
    import idaapi  # type: ignore
except ImportError:
    idaapi = None

try:
    import ida_typeinf  # type: ignore
except ImportError:
    ida_typeinf = None

try:
    import ida_funcs  # type: ignore
except ImportError:
    ida_funcs = None

try:
    import ida_nalt  # type: ignore
except ImportError:
    ida_nalt = None

try:
    import ida_struct  # type: ignore
except ImportError:
    ida_struct = None

try:
    import ida_hexrays  # type: ignore
except ImportError:
    ida_hexrays = None

try:
    import ida_kernwin  # type: ignore
except ImportError:
    ida_kernwin = None

# PT_SIL = 1: 静默解析，不显示语法错误对话框
PT_SIL = getattr(ida_typeinf, 'PT_SIL', 1)
# PT_TYP = 2: 解析类型声明 (struct/union/enum/typedef)
PT_TYP = getattr(ida_typeinf, 'PT_TYP', 2)
# PT_EMPTY = 0x4000: 允许空声明
PT_EMPTY = getattr(ida_typeinf, 'PT_EMPTY', 0x4000)


def _parse_decls_python(decls: str, hti_flags: int) -> tuple:
    """使用 IDAPython API 调用 parse_decls。
    
    返回:
        (errors: int, messages: List[str])
    """
    try:
        # ida_typeinf.parse_decls(til, input, printer, hti_flags)
        # 使用默认类型库
        errors = ida_typeinf.parse_decls(ida_typeinf.get_idati(), decls, False, hti_flags)
        return (errors, [])
    except Exception as e:
        return (-1, [str(e)])


def _build_temp_variable_decl(type_text: str, temp_name: str) -> str:
    """Convert a type fragment like `Foo[4]` into a parseable declaration."""
    normalized = type_text.strip().rstrip(";").strip()
    if not normalized:
        return ""

    match = re.match(r"^(?P<base>.+?)(?P<suffix>(?:\s*\[[^\]]*\])+)\s*$", normalized, re.DOTALL)
    if match:
        base = match.group("base").strip()
        suffix = match.group("suffix")
        return f"{base} {temp_name}{suffix};"

    return f"{normalized} {temp_name};"


def _parse_type_fragment_tinfo(type_text: str, temp_name: str) -> tuple[Any, list[str], str]:
    candidate_decl = _build_temp_variable_decl(type_text, temp_name)
    tinfo = ida_typeinf.tinfo_t()
    errors: List[str] = []

    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, idaapi.cvar.idati, candidate_decl, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, idaapi.cvar.idati, candidate_decl, PT_SIL)),  # type: ignore
    ]

    for label, fn in variants:
        try:
            _ = fn()
            if tinfo and not tinfo.empty():
                return tinfo, errors, candidate_decl
        except Exception as e:
            errors.append(f"{label}: {e}")

    return None, errors, candidate_decl


# ============================================================================
# 类型声明
# ============================================================================

def _parse_decl_tinfo(decl_text: str) -> tuple[Any, Optional[str], list[str]]:
    tinfo = ida_typeinf.tinfo_t()
    name = None
    parse_errors: List[str] = []

    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, idaapi.cvar.idati, decl_text, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, idaapi.cvar.idati, decl_text, PT_SIL)),  # type: ignore
    ]

    for label, fn in variants:
        try:
            nm = fn()
            if isinstance(nm, (list, tuple)) and nm:
                nm = nm[0]
            if isinstance(nm, str) and nm:
                name = nm
            if tinfo and not tinfo.empty():
                break
        except Exception as e:
            parse_errors.append(f"{label}: {e}")

    return tinfo, name, parse_errors


def _kind_from_tinfo(tinfo: Any) -> str:
    try:
        if tinfo.is_struct():
            return "struct"
        if tinfo.is_enum():
            return "enum"
        if tinfo.is_typedef():
            return "typedef"
        if tinfo.is_union():
            return "union"
    except Exception:
        pass
    return "other"


def _named_type_exists(name: str) -> bool:
    try:
        return bool(ida_typeinf.get_named_type(idaapi.cvar.idati, name, 0))  # type: ignore
    except Exception:
        return False


def _apply_named_type(name: str, tinfo: Any, existed: bool) -> tuple[bool, List[str]]:
    ok = False
    set_errors: List[str] = []

    try:
        flags = getattr(ida_typeinf, 'NTF_REPLACE', 0) if existed else 0
        ok = bool(ida_typeinf.set_named_type(idaapi.cvar.idati, name, flags, tinfo, 0))  # type: ignore
    except AttributeError as e:
        set_errors.append(f"set_named_type: {e}")
    except Exception as e:
        set_errors.append(f"set_named_type: {e}")
    
    # 方法 2: tinfo_t.set_named_type (IDA 9.x)
    if not ok:
        try:
            ok = bool(tinfo.set_named_type(None, name, ida_typeinf.NTF_REPLACE if existed else 0))  # type: ignore
        except AttributeError:
            pass
        except Exception as e:
            set_errors.append(f"tinfo.set_named_type: {e}")

    return bool(ok), set_errors


def _load_named_type(name: str) -> Any:
    try:
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(ida_typeinf.get_idati(), name):
            return tif
    except Exception:
        pass
    return None


def _extract_decl_name(decl_text: str, expected_kind: str, parsed_name: Optional[str]) -> Optional[str]:
    patterns = {
        "struct": r"^\s*struct\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        "enum": r"^\s*enum\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        "typedef": r"^\s*typedef\b[\s\S]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?\s*;\s*$",
    }
    pattern = patterns.get(expected_kind)
    if pattern:
        match = re.match(pattern, decl_text.strip(), re.DOTALL)
        if match:
            return match.group(1)

    if parsed_name and is_valid_c_identifier(parsed_name):
        return parsed_name
    return None


def _declare_named_decl(decl_text: str, expected_kind: str) -> dict:
    if not decl_text or not decl_text.strip():
        return {"error": "empty declaration"}

    normalized_decl = decl_text.strip()
    if expected_kind == "struct" and not re.match(r"^\s*struct\b", normalized_decl):
        return {"error": "declaration is not a struct"}
    if expected_kind == "enum" and not re.match(r"^\s*enum\b", normalized_decl):
        return {"error": "declaration is not an enum"}
    if expected_kind == "typedef" and not normalized_decl.lstrip().startswith("typedef"):
        return {"error": "declaration is not a typedef"}

    name = _extract_decl_name(normalized_decl, expected_kind, None)
    if not name:
        return {"error": f"missing {expected_kind} name"}

    existed = _named_type_exists(name)
    hti_flags = PT_SIL | PT_TYP | PT_EMPTY
    errors, messages = _parse_decls_python(normalized_decl, hti_flags)

    if errors > 0:
        return {
            "error": f"parse failed ({errors} errors)",
            "details": messages[:5] if messages else [],
        }
    if errors < 0:
        tinfo, _parsed_name, parse_errors = _parse_decl_tinfo(normalized_decl)
        if not tinfo or tinfo.empty():
            return {"error": "parse failed", "details": parse_errors[:2]}

        parsed_kind = _kind_from_tinfo(tinfo)
        if expected_kind in ("struct", "enum") and parsed_kind != expected_kind:
            return {"error": f"declaration is not a {expected_kind}", "detected_kind": parsed_kind}
        if expected_kind == "typedef" and not normalized_decl.lstrip().startswith("typedef"):
            return {"error": "declaration is not a typedef", "detected_kind": parsed_kind}

        ok, set_errors = _apply_named_type(name, tinfo, existed)
        if not ok:
            return {"error": "set type failed", "details": set_errors[:2]}

    loaded = _load_named_type(name)
    if loaded is None:
        return {"error": "declared type not found after apply", "name": name}

    loaded_kind = _kind_from_tinfo(loaded)
    if loaded_kind != expected_kind:
        return {"error": f"declared type kind mismatch: {loaded_kind}", "name": name}

    return {
        "name": name,
        "kind": expected_kind,
        "created": not existed,
        "replaced": existed,
        "success": True,
    }


@tool
@idawrite
def declare_struct(
    decl: Annotated[str, "Struct declaration text (e.g. 'struct Name { ... };')"],
) -> dict:
    """Declare or update a struct in the local type library."""
    return _declare_named_decl(decl, "struct")


@tool
@idawrite
def declare_enum(
    decl: Annotated[str, "Enum declaration text (e.g. 'enum Name { ... };')"],
) -> dict:
    """Declare or update an enum in the local type library."""
    return _declare_named_decl(decl, "enum")


@tool
@idawrite
def declare_typedef(
    decl: Annotated[str, "Typedef declaration text (e.g. 'typedef unsigned int NAME;')"],
) -> dict:
    """Declare or update a typedef in the local type library."""
    return _declare_named_decl(decl, "typedef")


# ============================================================================
# 函数原型
# ============================================================================

@tool
@idawrite
def set_function_prototype(
    function_address: Annotated[Union[int, str], "Function start or internal address (hex or decimal)"],
    prototype: Annotated[str, "Full C function declaration"],
) -> dict:
    """Set function prototype (type signature)."""
    if function_address is None:
        return {"error": "invalid function_address"}
    if not prototype or not prototype.strip():
        return {"error": "empty prototype"}
    
    parsed = parse_address(str(function_address))
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid function_address"}
    
    proto_text = prototype.strip()
    
    try:
        f = ida_funcs.get_func(parsed["value"])
    except Exception:
        f = None
    if not f:
        return {"error": "function not found"}
    
    start_ea = int(f.start_ea)
    
    # 获取旧类型
    old_decl = None
    try:
        old_t = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(old_t, start_ea):
            try:
                old_decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, old_t, '', '')  # type: ignore
            except Exception:
                old_decl = None
    except Exception:
        pass
    
    # 解析新类型
    tinfo = ida_typeinf.tinfo_t()
    parsed_name = None
    parse_ok = False
    parse_errors: List[str] = []
    
    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, idaapi.cvar.idati, proto_text, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, idaapi.cvar.idati, proto_text, PT_SIL)),  # type: ignore
    ]
    
    for label, fn in variants:
        try:
            name = fn()
            if isinstance(name, (list, tuple)) and name:
                name = name[0]
            if isinstance(name, str) and name:
                parsed_name = name
            if tinfo and tinfo.is_func():
                parse_ok = True
                break
        except Exception as e:
            parse_errors.append(f"{label}: {e}")
    
    if not parse_ok or not tinfo or not tinfo.is_func():
        return {"error": "parse failed or not a function type", "details": parse_errors[:2]}
    
    # 应用类型
    try:
        applied = idaapi.apply_tinfo(start_ea, tinfo, idaapi.TINFO_DEFINITE)
    except Exception:
        try:
            applied = idaapi.apply_tinfo2(start_ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
        except Exception as e:
            return {"error": f"apply failed: {e}"}
    
    # 获取新类型
    new_decl = None
    try:
        nt = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(nt, start_ea):
            try:
                new_decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', '')  # type: ignore
            except Exception:
                new_decl = None
    except Exception:
        pass
    
    return {
        "start_ea": hex_addr(start_ea),
        "applied": bool(applied),
        "old_type": old_decl,
        "new_type": new_decl,
        "parsed_name": parsed_name,
    }


# ============================================================================
# 局部变量类型
# ============================================================================

@tool
@idawrite
def set_local_variable_type(
    function_address: Annotated[Union[int, str], "Function start or internal address (hex or decimal)"],
    variable_name: Annotated[str, "Local variable name (exact match)"],
    new_type: Annotated[str, "C type fragment (e.g. int, char *, MyStruct *)"],
) -> dict:
    """Set local variable type (Hex-Rays)."""
    wait_for_auto_analysis()
    if function_address is None:
        return {"error": "invalid function_address"}
    if not variable_name:
        return {"error": "empty variable_name"}
    if not new_type or not new_type.strip():
        return {"error": "empty new_type"}
    
    parsed = parse_address(str(function_address))
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid function_address"}
    
    type_text = new_type.strip()
    
    # 初始化 Hex-Rays
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"error": "failed to init hex-rays"}
    except Exception:
        return {"error": "failed to init hex-rays"}
    
    # 定位函数
    try:
        f = ida_funcs.get_func(parsed["value"])
    except Exception:
        f = None
    if not f:
        return {"error": "function not found"}
    
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"error": f"decompile failed: {e}"}
    if not cfunc:
        return {"error": "decompile returned None"}
    
    # 查找局部变量
    target = None
    try:
        for lv in cfunc.lvars:  # type: ignore
            try:
                if lv.name == variable_name:
                    target = lv
                    break
            except Exception:
                continue
    except Exception:
        return {"error": "iterate lvars failed"}
    
    if not target:
        return {"error": "local variable not found"}
    
    # 获取原类型
    old_type_str = None
    try:
        old_t = target.type()
        if old_t:
            try:
                old_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, old_t, '', '')  # type: ignore
            except Exception:
                old_type_str = None
    except Exception:
        pass
    
    # 解析新类型
    tinfo, errors, candidate_decl = _parse_type_fragment_tinfo(type_text, "__ida_mcp_lvar")
    if not tinfo:
        return {"error": "parse type failed", "details": errors[:2], "candidate_decl": candidate_decl}
    
    # 应用
    try:
        if hasattr(target, "set_lvar_type"):
            applied = target.set_lvar_type(tinfo)  # type: ignore[attr-defined]
        elif hasattr(cfunc, "set_lvar_type"):
            applied = cfunc.set_lvar_type(target, tinfo)  # type: ignore[attr-defined]
        else:
            return {"error": "set_lvar_type API not available"}
    except Exception as e:
        return {"error": f"set_lvar_type failed: {e}"}
    
    # 获取新类型
    new_type_str = None
    try:
        nt = target.type()
        if nt:
            try:
                new_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', '')  # type: ignore
            except Exception:
                new_type_str = None
    except Exception:
        pass
    
    try:
        fname = idaapi.get_func_name(f.start_ea)
    except Exception:
        fname = "?"
    
    return {
        "function": fname,
        "start_ea": hex_addr(f.start_ea),
        "variable_name": variable_name,
        "old_type": old_type_str,
        "new_type": new_type_str,
        "applied": bool(applied),
    }


# ============================================================================
# 全局变量类型
# ============================================================================

@tool
@idawrite
def set_global_variable_type(
    variable_name: Annotated[str, "Global symbol name"],
    new_type: Annotated[str, "C type fragment"],
) -> dict:
    """Set global variable type."""
    if not variable_name:
        return {"error": "empty variable_name"}
    if not new_type or not new_type.strip():
        return {"error": "empty new_type"}
    
    type_text = new_type.strip()
    
    try:
        ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    except Exception:
        ea = idaapi.BADADDR
    
    if ea == idaapi.BADADDR:
        return {"error": "global not found"}
    
    # 拒绝函数起始
    try:
        f = ida_funcs.get_func(ea)
        if f and int(f.start_ea) == int(ea):
            return {"error": "target is function start"}
    except Exception:
        pass
    
    # 获取旧类型
    old_type_str = None
    try:
        ot = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(ot, ea):
            try:
                old_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, ot, '', '')  # type: ignore
            except Exception:
                old_type_str = None
    except Exception:
        pass
    
    # 解析新类型
    tinfo, errors, candidate_decl = _parse_type_fragment_tinfo(type_text, "__ida_mcp_global")
    if not tinfo:
        return {"error": "parse type failed", "details": errors[:2], "candidate_decl": candidate_decl}
    
    # 应用
    try:
        applied = idaapi.apply_tinfo(ea, tinfo, idaapi.TINFO_DEFINITE)
    except Exception:
        try:
            applied = idaapi.apply_tinfo2(ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
        except Exception as e:
            return {"error": f"apply failed: {e}"}
    
    # 获取新类型
    new_type_str = None
    try:
        nt = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(nt, ea):
            try:
                new_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', '')  # type: ignore
            except Exception:
                new_type_str = None
    except Exception:
        pass
    
    return {
        "ea": hex_addr(ea),
        "variable_name": variable_name,
        "old_type": old_type_str,
        "new_type": new_type_str,
        "applied": bool(applied),
    }


# ============================================================================
# 结构体列表
# ============================================================================

@tool
@idaread
def list_structs(
    pattern: Annotated[Optional[str], "Optional name filter"] = None,
) -> dict:
    """List all structures/unions defined in the database."""
    items: List[dict] = []
    
    try:
        qty = ida_typeinf.get_ordinal_qty()  # type: ignore
        substr = pattern.lower() if pattern else None
        til = idaapi.cvar.idati  # type: ignore

        for ordinal in range(1, qty + 1):
            try:
                name = ida_typeinf.get_numbered_type_name(til, ordinal)  # type: ignore
            except Exception:
                name = None

            if not name:
                continue

            if substr and substr not in name.lower():
                continue

            try:
                tif = ida_typeinf.tinfo_t()
                ida_typeinf.get_numbered_type(til, ordinal, tif)  # type: ignore

                if not (tif.is_struct() or tif.is_union()):
                    continue

                udt = ida_typeinf.udt_type_data_t()
                member_count = 0
                is_union = tif.is_union()
                if tif.get_udt_details(udt):
                    member_count = udt.size()

                try:
                    size = tif.get_size()
                except Exception:
                    size = 0

                items.append({
                    "ordinal": ordinal,
                    "name": name,
                    "kind": "union" if is_union else "struct",
                    "size": size,
                    "members": member_count,
                })
            except Exception:
                continue
    except Exception:
        pass

    return {"total": len(items), "items": items}


# ============================================================================
# 结构体详情
# ============================================================================

@tool
@idaread
def get_struct_info(
    name: Annotated[str, "Structure/union name"],
) -> dict:
    """Get detailed structure/union definition with fields."""
    if not name or not name.strip():
        return {"error": "empty name"}
    
    name = name.strip()
    
    try:
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        
        # 尝试按名称获取类型
        if not tif.get_named_type(til, name):
            return {"error": "type not found", "name": name}
        
        if not (tif.is_struct() or tif.is_union()):
            return {"error": "not a struct/union", "name": name}
        
        kind = "struct" if tif.is_struct() else "union"
        size = tif.get_size()
        
        # 获取成员详情
        udt = ida_typeinf.udt_type_data_t()
        members: List[dict] = []
        
        if tif.get_udt_details(udt):
            for i in range(udt.size()):
                try:
                    member = udt[i]
                    mname = member.name if member.name else f"field_{i}"
                    mtype = member.type
                    moffset = member.offset // 8  # 位转字节
                    msize = member.size // 8 if member.size else None
                    
                    # 获取类型字符串
                    mtype_str = None
                    if mtype:
                        try:
                            mtype_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, mtype, '', '')
                        except Exception:
                            mtype_str = str(mtype)
                    
                    members.append({
                        "index": i,
                        "name": mname,
                        "type": mtype_str,
                        "offset": moffset,
                        "size": msize,
                    })
                except Exception:
                    continue
        
        return {
            "name": name,
            "kind": kind,
            "size": size if size != idaapi.BADADDR else None,
            "members": members,
            "member_count": len(members),
        }
    except Exception as e:
        return {"error": str(e), "name": name}
