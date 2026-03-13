"""Proxy tool registration for forwarded IDA operations."""
from __future__ import annotations

from typing import Annotated, Any, Dict, List, Optional

try:
    from pydantic import Field
except ImportError:  # pragma: no cover
    Field = lambda **kwargs: None  # type: ignore

from ..config import is_unsafe_enabled
from ._state import forward
from . import api_lifecycle


def register_tools(server: Any) -> None:
    """Register all proxy-exposed forwarding tools."""
    unsafe_enabled = is_unsafe_enabled()

    @server.tool(description="List functions with pagination. Params: offset (>=0), count (1-1000), pattern (optional filter).")
    def list_functions(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        params: Dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_functions", params, port, timeout=timeout)

    @server.tool(description="Get IDB metadata (input_file, arch, bits, hash, endian).")
    def get_metadata(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_metadata", {}, port, timeout=timeout)

    @server.tool(description="List strings. Params: offset, count, pattern (optional filter).")
    def list_strings(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional content filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        params: Dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_strings", params, port, timeout=timeout)

    @server.tool(description="List global variables. Params: offset, count, pattern (optional filter).")
    def list_globals(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        params: Dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_globals", params, port, timeout=timeout)

    @server.tool(description="List local types defined in IDB.")
    def list_local_types(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("list_local_types", {}, port, timeout=timeout)

    @server.tool(description="Get entry points of the binary.")
    def get_entry_points(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_entry_points", {}, port, timeout=timeout)

    @server.tool(description="List imported functions with module names.")
    def list_imports(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name/module filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        params: Dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_imports", params, port, timeout=timeout)

    @server.tool(description="List exported functions/symbols.")
    def list_exports(
        offset: Annotated[int, Field(description="Pagination offset")] = 0,
        count: Annotated[int, Field(description="Number of items")] = 100,
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        params: Dict[str, Any] = {"offset": offset, "count": count}
        if pattern:
            params["pattern"] = pattern
        return forward("list_exports", params, port, timeout=timeout)

    @server.tool(description="List memory segments with permissions.")
    def list_segments(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("list_segments", {}, port, timeout=timeout)

    @server.tool(description="Get current cursor position and context in IDA.")
    def get_cursor(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_cursor", {}, port, timeout=timeout)

    @server.tool(description="Decompile function(s). addr can be address or name, comma-separated for batch.")
    def decompile(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("decompile", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Disassemble function(s). addr can be address or name, comma-separated for batch.")
    def disasm(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("disasm", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Linear disassembly from address. Returns raw instructions.")
    def linear_disassemble(
        start_address: Annotated[str, Field(description="Start address")],
        count: Annotated[int, Field(description="Number of instructions")] = 20,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward(
            "linear_disassemble",
            {"start_address": start_address, "count": count},
            port,
            timeout=timeout,
        )

    @server.tool(description="Get cross-references TO address(es). addr comma-separated for batch.")
    def xrefs_to(
        addr: Annotated[str, Field(description="Target address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("xrefs_to", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Get cross-references FROM address(es).")
    def xrefs_from(
        addr: Annotated[str, Field(description="Source address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("xrefs_from", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Get cross-references to struct field. struct_name: type name, field_name: member name.")
    def xrefs_to_field(
        struct_name: Annotated[str, Field(description="Structure type name")],
        field_name: Annotated[str, Field(description="Field/member name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward(
            "xrefs_to_field",
            {"struct_name": struct_name, "field_name": field_name},
            port,
            timeout=timeout,
        )

    @server.tool(description="Find function by name or address.")
    def get_function(
        query: Annotated[str, Field(description="Function name or address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_function", {"query": query}, port, timeout=timeout)

    @server.tool(description="Search for byte pattern with wildcards (e.g. '48 8B ?? ?? 48 89').")
    def find_bytes(
        pattern: Annotated[str, Field(description="Byte pattern with wildcards")],
        start: Annotated[Optional[str], Field(description="Start address")] = None,
        end: Annotated[Optional[str], Field(description="End address")] = None,
        limit: Annotated[int, Field(description="Max results")] = 100,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        params: Dict[str, Any] = {"pattern": pattern, "limit": limit}
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        return forward("find_bytes", params, port, timeout=timeout)

    @server.tool(description="Get basic blocks with control flow information.")
    def get_basic_blocks(
        addr: Annotated[str, Field(description="Function address or name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_basic_blocks", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Set comment at address(es). items: [{address, comment}].")
    def set_comment(
        items: Annotated[list, Field(description="List of {address, comment} objects")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("set_comment", {"items": items}, port, timeout=timeout)

    @server.tool(description="Rename a function.")
    def rename_function(
        address: Annotated[str, Field(description="Function address or name")],
        new_name: Annotated[str, Field(description="New function name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("rename_function", {"address": address, "new_name": new_name}, port, timeout=timeout)

    @server.tool(description="Rename a global variable.")
    def rename_global_variable(
        old_name: Annotated[str, Field(description="Current variable name")],
        new_name: Annotated[str, Field(description="New variable name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward(
            "rename_global_variable",
            {"old_name": old_name, "new_name": new_name},
            port,
            timeout=timeout,
        )

    @server.tool(description="Rename a local variable in a function.")
    def rename_local_variable(
        function_address: Annotated[str, Field(description="Function containing the variable")],
        old_name: Annotated[str, Field(description="Current variable name")],
        new_name: Annotated[str, Field(description="New variable name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward(
            "rename_local_variable",
            {
                "function_address": function_address,
                "old_name": old_name,
                "new_name": new_name,
            },
            port,
            timeout=timeout,
        )

    @server.tool(description="Patch bytes at address(es). items: [{address, bytes: [int,...] or hex_string}].")
    def patch_bytes(
        items: Annotated[list, Field(description="List of {address, bytes} objects")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("patch_bytes", {"items": items}, port, timeout=timeout)

    @server.tool(description="Read memory bytes. Returns hex dump and byte array.")
    def get_bytes(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        size: Annotated[int, Field(description="Bytes to read (1-4096)")] = 64,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_bytes", {"addr": addr, "size": size}, port, timeout=timeout)

    @server.tool(description="Read 8-bit unsigned integer from address.")
    def get_u8(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_u8", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Read 16-bit unsigned integer from address.")
    def get_u16(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_u16", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Read 32-bit unsigned integer from address.")
    def get_u32(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_u32", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Read 64-bit unsigned integer from address.")
    def get_u64(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_u64", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Read null-terminated string from address.")
    def get_string(
        addr: Annotated[str, Field(description="Memory address(es), comma-separated")],
        max_len: Annotated[int, Field(description="Maximum length")] = 256,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_string", {"addr": addr, "max_len": max_len}, port, timeout=timeout)

    @server.tool(description="Set function prototype/signature.")
    def set_function_prototype(
        function_address: Annotated[str, Field(description="Function address")],
        prototype: Annotated[str, Field(description="C-style function prototype")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward(
            "set_function_prototype",
            {"function_address": function_address, "prototype": prototype},
            port,
            timeout=timeout,
        )

    @server.tool(description="Set type of a local variable.")
    def set_local_variable_type(
        function_address: Annotated[str, Field(description="Function containing the variable")],
        variable_name: Annotated[str, Field(description="Variable name")],
        new_type: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward(
            "set_local_variable_type",
            {
                "function_address": function_address,
                "variable_name": variable_name,
                "new_type": new_type,
            },
            port,
            timeout=timeout,
        )

    @server.tool(description="Set type of a global variable.")
    def set_global_variable_type(
        variable_name: Annotated[str, Field(description="Global variable name")],
        new_type: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward(
            "set_global_variable_type",
            {"variable_name": variable_name, "new_type": new_type},
            port,
            timeout=timeout,
        )

    @server.tool(description="Declare a new C type (struct, enum, typedef).")
    def declare_type(
        decl: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("declare_type", {"decl": decl}, port, timeout=timeout)

    @server.tool(description="List all structures/unions defined in the database.")
    def list_structs(
        pattern: Annotated[Optional[str], Field(description="Optional name filter")] = None,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        params: Dict[str, Any] = {}
        if pattern:
            params["pattern"] = pattern
        return forward("list_structs", params, port, timeout=timeout)

    @server.tool(description="Get detailed structure/union definition with fields.")
    def get_struct_info(
        name: Annotated[str, Field(description="Structure/union name")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("get_struct_info", {"name": name}, port, timeout=timeout)

    if unsafe_enabled:
        @server.tool(description="Start debugger process.")
        def dbg_start(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_start", {}, port, timeout=timeout)

        @server.tool(description="Exit/terminate debugger process.")
        def dbg_exit(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_exit", {}, port, timeout=timeout)

        @server.tool(description="Continue debugger execution.")
        def dbg_continue(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_continue", {}, port, timeout=timeout)

        @server.tool(description="Step into next instruction.")
        def dbg_step_into(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_step_into", {}, port, timeout=timeout)

        @server.tool(description="Step over next instruction.")
        def dbg_step_over(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_step_over", {}, port, timeout=timeout)

        @server.tool(description="Run to address.")
        def dbg_run_to(
            addr: Annotated[str, Field(description="Target address")],
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_run_to", {"addr": addr}, port, timeout=timeout)

        @server.tool(description="Get all CPU registers.")
        def dbg_regs(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_regs", {}, port, timeout=timeout)

        @server.tool(description="Get call stack.")
        def dbg_callstack(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_callstack", {}, port, timeout=timeout)

        @server.tool(description="List all breakpoints.")
        def dbg_list_bps(
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_list_bps", {}, port, timeout=timeout)

        @server.tool(description="Add breakpoint at address.")
        def dbg_add_bp(
            addr: Annotated[str, Field(description="Breakpoint address(es), comma-separated")],
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_add_bp", {"addr": addr}, port, timeout=timeout)

        @server.tool(description="Delete breakpoint at address.")
        def dbg_delete_bp(
            addr: Annotated[str, Field(description="Breakpoint address(es), comma-separated")],
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_delete_bp", {"addr": addr}, port, timeout=timeout)

        @server.tool(description="Enable or disable breakpoint.")
        def dbg_enable_bp(
            items: Annotated[list, Field(description="List of {address, enable} objects")],
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_enable_bp", {"items": items}, port, timeout=timeout)

        @server.tool(description="Read memory in debugger.")
        def dbg_read_mem(
            regions: Annotated[List[Dict[str, Any]], Field(description="List of {address, size} objects")],
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_read_mem", {"regions": regions}, port, timeout=timeout)

        @server.tool(description="Write memory in debugger.")
        def dbg_write_mem(
            regions: Annotated[List[Dict[str, Any]], Field(description="List of {address, bytes} objects")],
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("dbg_write_mem", {"regions": regions}, port, timeout=timeout)

        @server.tool(description="Execute Python code in IDA context. Returns {result, stdout, stderr}. Has access to all IDA API modules. Supports Jupyter-style evaluation.")
        def py_eval(
            code: Annotated[str, Field(description="Python code to execute")],
            port: Annotated[Optional[int], Field(description="Instance port override")] = None,
            timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
        ) -> Any:
            return forward("py_eval", {"code": code}, port, timeout=timeout)

    @server.tool(description="Get stack frame variables for function(s). addr can be address or name, comma-separated for batch.")
    def stack_frame(
        addr: Annotated[str, Field(description="Function address(es) or name(s), comma-separated")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("stack_frame", {"addr": addr}, port, timeout=timeout)

    @server.tool(description="Declare stack variable(s). items: [{function_address, offset, name, type?, size?}].")
    def declare_stack(
        items: Annotated[List[Dict[str, Any]], Field(description="List of stack variable definitions")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("declare_stack", {"items": items}, port, timeout=timeout)

    @server.tool(description="Delete stack variable(s). items: [{function_address, name}].")
    def delete_stack(
        items: Annotated[List[Dict[str, Any]], Field(description="List of {function_address, name}")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> Any:
        return forward("delete_stack", {"items": items}, port, timeout=timeout)

    @server.tool(description="Launch IDA Pro with the specified file. Automatically attempts to load IDA-MCP plugin.")
    def open_in_ida(
        file_path: Annotated[str, Field(description="Path to the file to open (executable or IDB)")],
        extra_args: Annotated[Optional[List[str]], Field(description="Extra arguments to pass to IDA")] = None,
    ) -> dict:
        return api_lifecycle.open_in_ida(file_path, extra_args=extra_args)

    @server.tool(description="Close the target IDA instance. Warning: This terminates the process.")
    def close_ida(
        save: Annotated[bool, Field(description="Whether to save IDB file before closing")] = True,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
        timeout: Annotated[Optional[int], Field(description="Timeout in seconds")] = None,
    ) -> dict:
        return api_lifecycle.close_ida(save=save, port=port, timeout=timeout)
