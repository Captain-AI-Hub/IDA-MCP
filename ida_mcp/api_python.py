"""Python 执行 API - 在 IDA 上下文中执行任意 Python 代码。

提供工具:
    - py_eval    在 IDA 上下文中执行 Python 代码
"""
from __future__ import annotations

import ast
import io
import sys
import traceback
from typing import Annotated

from .rpc import tool, unsafe
from .sync import idaread

# IDA 模块导入
import idaapi  # type: ignore
import idc  # type: ignore
import ida_bytes  # type: ignore
import ida_funcs  # type: ignore
import ida_hexrays  # type: ignore
import ida_kernwin  # type: ignore
import ida_nalt  # type: ignore
import ida_name  # type: ignore
import ida_segment  # type: ignore
import ida_typeinf  # type: ignore
import ida_xref  # type: ignore
import ida_entry  # type: ignore
import ida_frame  # type: ignore
import ida_lines  # type: ignore
import ida_ida  # type: ignore


def _lazy_import(module_name: str):
    """延迟导入 IDA 模块，失败时返回 None。"""
    try:
        return __import__(module_name)
    except Exception:
        return None


@unsafe
@tool
@idaread
def py_eval(
    code: Annotated[str, "Python code to execute in IDA context"],
) -> dict:
    """Execute Python code in IDA context.
    Returns dict with result/stdout/stderr.
    Has access to all IDA API modules.
    Supports Jupyter-style evaluation (last expression is returned)."""
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        from .utils import parse_address, hex_addr

        exec_globals = {
            "__builtins__": __builtins__,
            "idaapi": idaapi,
            "idc": idc,
            "idautils": _lazy_import("idautils"),
            "ida_allins": _lazy_import("ida_allins"),
            "ida_auto": _lazy_import("ida_auto"),
            "ida_bytes": ida_bytes,
            "ida_dbg": _lazy_import("ida_dbg"),
            "ida_entry": ida_entry,
            "ida_expr": _lazy_import("ida_expr"),
            "ida_frame": ida_frame,
            "ida_funcs": ida_funcs,
            "ida_gdl": _lazy_import("ida_gdl"),
            "ida_graph": _lazy_import("ida_graph"),
            "ida_hexrays": ida_hexrays,
            "ida_ida": ida_ida,
            "ida_idd": _lazy_import("ida_idd"),
            "ida_idp": _lazy_import("ida_idp"),
            "ida_kernwin": ida_kernwin,
            "ida_lines": ida_lines,
            "ida_loader": _lazy_import("ida_loader"),
            "ida_nalt": ida_nalt,
            "ida_name": ida_name,
            "ida_netnode": _lazy_import("ida_netnode"),
            "ida_pro": _lazy_import("ida_pro"),
            "ida_search": _lazy_import("ida_search"),
            "ida_segment": ida_segment,
            "ida_strlist": _lazy_import("ida_strlist"),
            "ida_struct": _lazy_import("ida_struct"),
            "ida_typeinf": ida_typeinf,
            "ida_ua": _lazy_import("ida_ua"),
            "ida_xref": ida_xref,
            "ida_enum": _lazy_import("ida_enum"),
            "parse_address": parse_address,
            "hex_addr": hex_addr,
        }

        result_value = None
        exec_locals = {}

        try:
            tree = ast.parse(code)
        except SyntaxError:
            exec(code, exec_globals, exec_locals)
            exec_globals.update(exec_locals)
            if "result" in exec_locals:
                result_value = str(exec_locals["result"])
            elif exec_locals:
                last_key = list(exec_locals.keys())[-1]
                result_value = str(exec_locals[last_key])
        else:
            if not tree.body:
                pass
            elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                result_value = str(eval(code, exec_globals))
            elif isinstance(tree.body[-1], ast.Expr):
                if len(tree.body) > 1:
                    exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(
                        compile(exec_tree, "<string>", "exec"),
                        exec_globals,
                        exec_locals,
                    )
                    exec_globals.update(exec_locals)
                eval_tree = ast.Expression(body=tree.body[-1].value)
                result_value = str(
                    eval(compile(eval_tree, "<string>", "eval"), exec_globals)
                )
            else:
                exec(code, exec_globals, exec_locals)
                exec_globals.update(exec_locals)
                if "result" in exec_locals:
                    result_value = str(exec_locals["result"])
                elif exec_locals:
                    last_key = list(exec_locals.keys())[-1]
                    result_value = str(exec_locals[last_key])

        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        return {
            "result": result_value or "",
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception:
        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
