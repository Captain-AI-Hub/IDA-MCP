# IDA-MCP API Reference

本文档基于当前独立 IDA-MCP 插件仓库实现整理，覆盖：

- MCP 对外 HTTP 端点
- Gateway MCP proxy 工具
- 直连 IDA instance 工具
- `ida://` 资源
- Gateway 内部 HTTP 路由

仓库根目录包含 `ida_mcp.py`、`ida_mcp/`、`ida-plugin.json`、`requirements.txt`
和 live-IDA 测试套件 `test/`。Sarma IDE 通过 Git submodule 消费本仓库。

## 1. HTTP Endpoints

| Surface | URL | Purpose |
| --- | --- | --- |
| Gateway MCP proxy | `http://127.0.0.1:11338/mcp` | 多实例统一入口，只暴露 tools，不转发 `ida://` resources |
| Direct IDA instance MCP | `http://127.0.0.1:<instance_port>/mcp/` | 单实例直连入口，暴露 tools 和 `ida://` resources |
| Gateway internal HTTP | `http://127.0.0.1:11338/internal/*` | 非 MCP 内部控制/注册/转发接口 |

说明：

- `http_host` 控制 gateway 监听地址；来自 `127.0.0.1` / `::1` 的本机请求无需 token，非本机请求必须携带匹配的 `gateway_token`，为空时拒绝远程请求
- Gateway MCP proxy 的默认 URL 由 `config.conf` 中的 `http_host/http_port/http_path` 决定
- Direct instance 端点固定为 `http://127.0.0.1:<instance_port>/mcp/`

## 2. MCP Call Conventions

### 2.1 Logical Request Shapes

工具调用逻辑上等价于：

```json
{
  "name": "list_functions",
  "arguments": {
    "offset": 0,
    "count": 10
  }
}
```

资源读取逻辑上等价于：

```json
{
  "uri": "ida://function/0x401000/decompile"
}
```

本文后续每个工具的“请求示例”都只写 `arguments` 内容；实际调用时请由 MCP client 包装为 `tools/call`。

### 2.2 Address Inputs

大多数地址参数支持：

- 十进制整数
- `0x401000`
- `401000h`
- `0x40_10_00`

部分工具支持逗号分隔批量输入，例如：

```json
{
  "addr": "0x401000,sub_402000,main"
}
```

### 2.3 Proxy Forwarded Tool Extras

除 proxy 自己实现的管理/生命周期工具外，所有“后端工具”在 Gateway MCP proxy 上调用时都额外支持：

- `port?: int`
- `timeout?: int`

示例：

```json
{
  "addr": "0x401000",
  "port": 10000,
  "timeout": 30
}
```

### 2.4 Common Response Shapes

分页工具统一返回：

```json
{
  "total": 123,
  "offset": 0,
  "count": 10,
  "items": []
}
```

实例工具常见错误格式：

```json
{
  "error": "invalid address"
}
```

gateway/control 面的包装错误常见格式：

```json
{
  "error": {
    "code": "instance_not_found",
    "message": "Port 10000 not found in registered instances.",
    "details": {
      "port": 10000
    }
  }
}
```

## 3. Gateway MCP Proxy Tools

这些工具只在 Gateway MCP proxy 暴露，直连实例没有对应工具名。

### 3.1 Management

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `check_connection` | none | `{}` | `{ok: bool, count: int}` |
| `list_instances` | none | `{}` | `[{pid, port, input_file, idb, started, python, ...}]` |
| `select_instance` | `port?: int` | `{"port": 10000}` | 设置后续未显式传 `port` 的默认实例，返回 `{selected_port}` 或包装错误 |

### 3.2 Lifecycle

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `open_in_ida` | `file_path: str`, `extra_args?: string[]` | `{"file_path":"D:\\samples\\a.exe"}` | 成功时 `{status, message, requested_port, launch_bundle, staged_file, launch_target}`；失败时 `{error}` |
| `close_ida` | `save?: bool`, `port?: int`, `timeout?: int` | `{"save":false,"port":10000}` | 直返目标实例 `close_ida` 结果，典型为 `{status:"ok", message:"IDA is closing"}` 或包装错误 |
| `shutdown_gateway` | `force?: bool`, `timeout?: int` | `{"force":true}` | `{status:"ok", message, forced, instance_count}` 或 `{error}` |

`open_in_ida` 当前行为：

- 启动 IDA 子进程时设置 `IDA_MCP_AUTO_START=1`
- 同时设置预留端口环境变量 `IDA_MCP_PORT`
- `open_in_ida` 会读取 `config.conf` 里的 `open_in_ida_autonomous` 来决定是否追加 `-A`
- 如果 `open_in_ida_bundle_dir` 已配置，则会在该目录下创建时间戳子目录
- 若目标旁边存在匹配的 `.i64/.idb`，则优先打开数据库，以避免再次弹出 loader/options 确认框
- `-A` 会把 IDA 切到 batch/autonomous 启动模式，更适合无人值守自动化；如果你需要正常交互式 GUI 流程，请把 `open_in_ida_autonomous=false`
- `wsl_path_bridge=false` 时，不做 Windows/WSL 路径转换
- `wsl_path_bridge=true` 时，`ida_path` 和 `open_in_ida_bundle_dir` 视为宿主机 Windows 路径；`open_in_ida` 会把可转换的 WSL 挂载路径转换成 Windows 路径后再启动 IDA
- `wsl_path_bridge=true` 且最终启动目标不能转换为 Windows 路径时，`open_in_ida` 会返回错误；此时应配置 `open_in_ida_bundle_dir`，先 staging 到 Windows 盘

## 4. Backend Tool Catalog

以下工具在 direct instance MCP 直接可用。

以下工具在 Gateway MCP proxy 上也可用，但会额外接受 `port?` 与 `timeout?`。

如果 `enable_unsafe=false`，则 `py_eval`、`patch_bytes`、`apply_patch`、`patch_asm`、`diff_before_after` 与全部 `dbg_*` 工具不会注册。

### 4.1 Core Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `check_connection` | none | `{}` | `{ok: bool, count: int}` |
| `list_instances` | none | `{}` | `[{pid, port, input_file, idb, started, ...}]` |
| `get_metadata` | none | `{}` | `{input_file, arch, bits, endian, hash}` |
| `list_functions` | `offset?: int`, `count?: int`, `pattern?: str` | `{"offset":0,"count":20,"pattern":"sub_*"}` | 分页结果；`items` 为 `[{name, start_ea, end_ea}]` |
| `list_globals` | `offset?: int`, `count?: int`, `pattern?: str` | `{"pattern":"g_*"}` | 分页结果；`items` 为 `[{name, ea, size}]` |
| `list_strings` | `offset?: int`, `count?: int`, `pattern?: str`, `regex?: bool` | `{"pattern":"^http","regex":true}` | 分页结果；默认对子串做大小写不敏感匹配；`regex=true` 时将 `pattern` 作为正则；`items` 为 `[{ea, length, type, text}]` |
| `list_local_types` | none | `{}` | `{total, items:[{ordinal, name, decl}]}` |
| `get_entry_points` | none | `{}` | `{total, items:[{ordinal, ea, name}]}` |
| `convert_number` | `text: str`, `size?: int` | `{"text":"401000h","size":64}` | `{input, size, value, hex, dec, unsigned, signed, bin, bytes_le, bytes_be}` |
| `list_imports` | `offset?: int`, `count?: int`, `pattern?: str` | `{"pattern":"kernel32"}` | 分页结果；`items` 为 `[{ea, name, ordinal, module}]` |
| `list_exports` | `offset?: int`, `count?: int`, `pattern?: str` | `{"count":50}` | 分页结果；`items` 为 `[{ea, name, ordinal}]` |
| `list_segments` | none | `{}` | `{total, items:[{name, start_ea, end_ea, size, perm, class, bitness}]}` |
| `get_cursor` | none | `{}` | `{ea, ea_int, function?, selection?}` |
| `survey_binary` | none | `{}` | `{metadata, counts:{functions, strings, imports, segments, entry_points}, segments, entry_points}` |

### 4.2 Analysis Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `decompile` | `addr: int | str` | `{"addr":"0x401000,main"}` | `[{query, name, start_ea, end_ea, decompiled, error}]` |
| `disasm` | `addr: int | str` | `{"addr":"0x401000"}` | `[{query, name, start_ea, end_ea, instructions, error}]`；`instructions` 为 `[{ea, bytes, text, comment}]` |
| `linear_disasm` | `start_address: int | str`, `count?: int` | `{"start_address":"0x401000","count":16}` | `{start_address, count, instructions, truncated?}`；`instructions` 为 `[{ea, bytes, text, is_code, len}]` |
| `get_callers` | `addr: int | str` | `{"addr":"main"}` | `{query, function, start_ea, end_ea, total, items}`；`items` 为 `[{address, name, call_count, call_sites}]` |
| `get_callees` | `addr: int | str` | `{"addr":"main"}` | `{query, function, start_ea, end_ea, total, items}`；`items` 为 `[{address, name, call_count, call_sites}]` |
| `get_function_signature` | `addr: int | str` | `{"addr":"0x401000"}` | `{query, function, start_ea, end_ea, signature, source, inferred}` |
| `xrefs_to` | `addr: int | str` | `{"addr":"0x401000,0x402000"}` | `[{query, address, total, xrefs, error}]`；`xrefs` 为 `[{frm, type, iscode}]` |
| `xrefs_from` | `addr: int | str` | `{"addr":"0x401000"}` | `[{query, address, total, xrefs, error}]`；`xrefs` 为 `[{to, type, iscode}]` |
| `xrefs_to_field` | `struct_name: str`, `field_name: str` | `{"struct_name":"MY_STRUCT","field_name":"vtable"}` | `{struct, field, offset, matches, truncated?, note?}`；`matches` 为 `[{ea, line}]` |
| `find_bytes` | `pattern: str`, `start?: str`, `end?: str`, `limit?: int` | `{"pattern":"48 8B ?? ?? 48 89","limit":20}` | `{pattern, ida_pattern, total, matches, truncated?}`；`matches` 为 `[{ea, bytes, function}]` |
| `get_basic_blocks` | `addr: int | str` | `{"addr":"main"}` | `{query, function, start_ea, end_ea, total, blocks}`；`blocks` 为 `[{start_ea, end_ea, size, predecessors, successors, type?}]` |
| `find_regex` | `pattern: str`, `limit?: int`, `offset?: int` | `{"pattern":"^sub_40"}` | `{pattern, count, items:[{ea, name}], truncated?}` |
| `search_text` | `query: str`, `regex?: bool`, `limit?: int` | `{"query":"CreateFile"}` | `{query, regex, count, items:[{ea, text, comment, function}], truncated?}` |
| `find_instructions` | `mnemonic?: str`, `pattern?: str`, `limit?: int` | `{"mnemonic":"call","pattern":"recv"}` | `{mnemonic, pattern, count, items:[{ea, mnemonic, text, function}], truncated?}` |
| `callgraph` | `roots: int | str | list`, `max_depth?: int`, `max_nodes?: int` | `{"roots":"main","max_depth":3}` | `{roots, total_nodes, total_edges, nodes:[{ea, name, depth}], edges:[{caller, callee}], truncated?}` |
| `trace_data_flow` | `address: int | str`, `direction?: str`, `max_depth?: int`, `max_nodes?: int` | `{"address":"g_state","direction":"both"}` | `{query, start, direction, nodes:[{ea, name, depth}], edges:[{frm, to, type}], truncated?}` |

### 4.3 Memory Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `get_bytes` | `addr: int | str`, `size?: int` | `{"addr":"0x401000","size":16}` | `[{query, address, size, bytes, hex}]` 或每项 `{error, query, address?}` |
| `read_scalar` | `addr: int | str`, `width?: int`, `signed?: bool` | `{"addr":"0x401000","width":4,"signed":false}` | `[{query, address, width, signed, value, unsigned, hex}]` |
| `get_string` | `addr: int | str`, `max_len?: int` | `{"addr":"0x404000","max_len":128}` | `[{query, address, length, text}]` |

### 4.4 Modeling Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `create_function` | `address: int | str`, `end?: int | str` | `{"address":"0x401000"}` | `{address, requested_end, function, changed, note?}` 或 `{error}` |
| `delete_function` | `address: int | str` | `{"address":"0x401000"}` | `{address, old_function?, changed, note?}` |
| `make_code` | `address: int | str` | `{"address":"0x401020"}` | `{address, old_item, new_item, changed, note?}` 或 `{error}` |
| `undefine_items` | `address: int | str`, `size: int` | `{"address":"0x401020","size":16}` | `{address, size, old_item, new_item?, changed, note?}` 或 `{error}` |
| `make_data` | `address: int | str`, `data_type: str`, `count?: int` | `{"address":"0x404000","data_type":"dword","count":4}` | `{address, data_type, normalized_type, count, item_size, old_item, new_item, changed}` 或 `{error}` |
| `make_string` | `address: int | str`, `string_type?: str`, `length?: int` | `{"address":"0x404000","string_type":"c","length":32}` | `{address, string_type, length, old_item, new_item, changed}` 或 `{error}` |

`old_item/new_item` 通常包含：

```json
{
  "ea": "0x404000",
  "head": "0x404000",
  "size": 4,
  "kind": "data",
  "function": {
    "name": "sub_401000",
    "start_ea": "0x401000",
    "end_ea": "0x401050"
  }
}
```

### 4.5 Modify Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `set_comment` | `items: [{address, comment}]` | `{"items":[{"address":"0x401000","comment":"entry"}]}` | `[{address, old, new, changed, error}]` |
| `rename_function` | `address: int | str`, `new_name: str` | `{"address":"0x401000","new_name":"handle_init"}` | `{start_ea, old_name, new_name, changed, note?}` 或 `{error}` |
| `rename_local_variable` | `function_address: int | str`, `old_name: str`, `new_name: str` | `{"function_address":"0x401000","old_name":"v1","new_name":"ctx"}` | `{function, start_ea, old_name, new_name, changed}` 或 `{error}` |
| `rename_global_variable` | `old_name: str`, `new_name: str` | `{"old_name":"dword_404000","new_name":"g_state"}` | `{ea, old_name, new_name, changed, note?}` 或 `{error}` |
| `patch_bytes` | `items: [{address, bytes}]` | `{"items":[{"address":"0x401000","bytes":"90 90 90"}]}` | `[{address, size, patched, old_bytes, new_bytes, error}]` |
| `apply_patch` | `output_path?: str`, `overwrite?: bool` | `{"output_path":"a.patched.exe","overwrite":false}` | `{input_file, output_file, input_size, applied, skipped, patches, skipped_patches, truncated}` 或 `{error}` |
| `add_bookmark` | `address: int | str`, `description?: str` | `{"address":"0x401000","description":"entry"}` | `{address, slot, description, added}` 或 `{error}` |
| `patch_asm` (unsafe) | `items: [{address, asm}]` | `{"items":[{"address":"0x401000","asm":"nop"}]}` | `[{address, asm, bytes, size, patched}]` 或每项 `{error}` |
| `set_op_type` | `items: [{address, type, operand?}]` | `{"items":[{"address":"0x401010","type":"char"}]}` | `[{address, operand, type, applied}]`；type 支持 hex/dec/oct/bin/char/stkvar |
| `force_recompile` | `addresses?: int | str | list` | `{"addresses":"main"}` | `{cleared:"all"}` 或 `{cleared:"selected", results:[{address, marked_dirty}]}` |
| `diff_before_after` (unsafe) | `address: int | str`, `action: str`, `action_args?: obj` | `{"address":"main","action":"rename_function","action_args":{"address":"main","new_name":"entry"}}` | `{query, function, action, action_result, changed, diff, truncated?}` 或 `{error}` |

### 4.6 Stack Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `stack_frame` | `addr: int | str` | `{"addr":"main"}` | `[{query, name, start_ea, method?, variables, frame_variables?, local_variables?, error?, note?}]` |
| `declare_stack` | `items: [{function_address, offset, name, type?, size?}]` | `{"items":[{"function_address":"0x401000","offset":-0x20,"name":"buf","type":"char[32]","size":32}]}` | `[{function_address, offset, name, declared_type?, size?, changed, error?, note?}]` |
| `delete_stack` | `items: [{function_address, name}]` | `{"items":[{"function_address":"0x401000","name":"buf"}]}` | `[{function_address, name, changed, deleted, error}]` |

### 4.7 Type Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `declare_struct` | `decl: str` | `{"decl":"struct MY_S { int a; char b; };"}` | `{name, kind:"struct", created, replaced, success}` 或 `{error}` |
| `declare_enum` | `decl: str` | `{"decl":"enum MY_E { A=0, B=1 };"}` | `{name, kind:"enum", created, replaced, success}` 或 `{error}` |
| `declare_typedef` | `decl: str` | `{"decl":"typedef unsigned int MY_U32;"}` | `{name, kind:"typedef", created, replaced, success}` 或 `{error}` |
| `set_function_prototype` | `function_address: int | str`, `prototype: str` | `{"function_address":"0x401000","prototype":"int __fastcall sub_401000(int a1);"}` | `{start_ea, applied, old_type, new_type, parsed_name}` 或 `{error}` |
| `set_local_variable_type` | `function_address: int | str`, `variable_name: str`, `new_type: str` | `{"function_address":"0x401000","variable_name":"ctx","new_type":"MY_CTX *"}` | `{function, start_ea, variable_name, old_type, new_type, applied}` 或 `{error}` |
| `set_global_variable_type` | `variable_name: str`, `new_type: str` | `{"variable_name":"g_state","new_type":"int"}` | `{ea, variable_name, old_type, new_type, applied}` 或 `{error}` |
| `list_structs` | `pattern?: str` | `{"pattern":"web*"}` | `{total, items:[{ordinal, name, kind, size, members}]}` |
| `get_struct_info` | `name: str` | `{"name":"MY_S"}` | `{name, kind, size, members, member_count}` 或 `{error}` |
| `infer_types` | `addresses: int | str | list` | `{"addresses":"0x404000,g_state"}` | `[{query, address, type, applied}]` 或每项 `{error}` |

### 4.8 Python Tool

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `py_eval` | `code: str` | `{"code":"print(hex(ida_kernwin.get_screen_ea()))"}` | `{result, stdout, stderr}` |

说明：

- `py_eval` 被标记为 unsafe
- `result` 为字符串化结果
- 运行异常时 `stderr` 中包含 traceback

### 4.9 Debug Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `dbg_regs` | none | `{}` | `{ok, registers, notes?, note?}`；`registers` 为 `[{name, value, int?}]` |
| `dbg_callstack` | none | `{}` | `{ok, frames, note?}`；`frames` 为 `[{index, ea, func}]` |
| `dbg_list_bps` | none | `{}` | `{ok, total, breakpoints}`；`breakpoints` 为 `[{ea, enabled?, size?, type?}]` |
| `dbg_start` | none | `{}` | `{ok, started, pid, suspended}` 或 `{error}` |
| `dbg_exit` | none | `{}` | `{ok, exited, note?}` 或 `{error}` |
| `dbg_continue` | none | `{}` | `{ok, continued, note?}` 或 `{error}` |
| `dbg_run_to` | `addr: int | str` | `{"addr":"0x401000"}` | `{ok, requested, continued, suspended?, used_temp_bpt, cleaned_temp_bpt, note?}` 或 `{error}` |
| `dbg_add_bp` | `addr: int | str` | `{"addr":"0x401000,0x401020"}` | `[{query, ok, ea, existed, added, error, note?}]` |
| `dbg_delete_bp` | `addr: int | str` | `{"addr":"0x401000"}` | `[{query, ok, ea, existed, deleted, error, note?}]` |
| `dbg_enable_bp` | `items: [{address, enable}]` | `{"items":[{"address":"0x401000","enable":false}]}` | `[{ok, ea, existed, enabled, changed, note?}]` 或每项 `{error}` |
| `dbg_step_into` | none | `{}` | `{ok, stepped, note?}` 或 `{error}` |
| `dbg_step_over` | none | `{}` | `{ok, stepped, note?}` 或 `{error}` |
| `dbg_read_mem` | `regions: [{address, size}]` | `{"regions":[{"address":"0x7FF600001000","size":32}]}` | `[{address, size, bytes, hex, error}]` |
| `dbg_write_mem` | `regions: [{address, bytes}]` | `{"regions":[{"address":"0x7FF600001000","bytes":[144,144]}]}` | `[{address, size, written, error}]` |
| `dbg_status` | none | `{}` | `{ok, debugger_on, state, pid, threads, current_thread, ip, sp}` |
| `dbg_thread_regs` | `thread_ids?: int | str | list`, `names?: str` | `{"names":"RIP,RSP"}` | `{ok, threads:[{tid, registers:[{name, value, int?}]}]}` |

说明：

- 全部 debug 工具都被标记为 unsafe
- 大多数 debug 工具要求调试器已激活；未激活时通常返回 `{ok:false,...}` 或 `{error:"debugger not active"}`

### 4.10 Instance Lifecycle Tool

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `close_ida` | `save?: bool` | `{"save":true}` | `{status:"ok", message:"IDA is closing"}` 或 `{error}` |
| `save_idb` | `path?: str` | `{}` | `{saved: true, path}` 或 `{error}` |

## 5. Resource Catalog

资源只在 direct instance MCP 暴露，不通过 Gateway MCP proxy 转发。

逻辑读取方式为 `resources/read uri="..."`。

### 5.1 Common Resource Payloads

列表资源统一近似为：

```json
{
  "kind": "functions",
  "count": 2,
  "items": []
}
```

详情资源统一近似为：

```json
{
  "kind": "function",
  "address": "0x401000",
  "name": "main"
}
```

资源错误统一为：

```json
{
  "error": {
    "code": "function_not_found",
    "message": "Function not found.",
    "details": {
      "address": "0x401000"
    }
  }
}
```

### 5.2 Resource List

| URI | Parameters | Read Example | Expected Payload |
| --- | --- | --- | --- |
| `ida://idb/metadata` | none | `{"uri":"ida://idb/metadata"}` | `{kind:"idb_metadata", input_file, arch, bits, endian, hash}` |
| `ida://functions` | none | `{"uri":"ida://functions"}` | `{kind:"functions", count, items:[{address, name, end_address, size}]}` |
| `ida://function/{addr}` | `addr` path param | `{"uri":"ida://function/0x401000"}` | `{kind:"function", address, name, end_address, size}` |
| `ida://function/{addr}/decompile` | `addr` path param | `{"uri":"ida://function/0x401000/decompile"}` | `{kind:"function_decompile", address, name, end_address, decompiled}` |
| `ida://function/{addr}/disasm` | `addr` path param | `{"uri":"ida://function/0x401000/disasm"}` | `{kind:"function_disasm", address, name, end_address, count, items}`；`items` 为 `[{address, bytes, text, comment}]` |
| `ida://function/{addr}/basic_blocks` | `addr` path param | `{"uri":"ida://function/0x401000/basic_blocks"}` | `{kind:"function_basic_blocks", address, name, end_address, count, items}` |
| `ida://function/{addr}/stack` | `addr` path param | `{"uri":"ida://function/0x401000/stack"}` | `{kind:"function_stack", address, name, method, count, items, frame_variables?, local_variables?}` |
| `ida://strings` | none | `{"uri":"ida://strings"}` | `{kind:"strings", count, items:[{address, length, type, text}]}` |
| `ida://globals` | none | `{"uri":"ida://globals"}` | `{kind:"globals", count, items:[{address, name, size}]}` |
| `ida://types` | none | `{"uri":"ida://types"}` | `{kind:"types", count, items:[{ordinal, name, decl}]}` |
| `ida://segments` | none | `{"uri":"ida://segments"}` | `{kind:"segments", count, items:[{name, start_address, end_address, size, perm, class, bitness}]}` |
| `ida://segment/{name_or_addr}` | segment name or address | `{"uri":"ida://segment/.text"}` | `{kind:"segment", name, start_address, end_address, size, perm, class, bitness}` |
| `ida://imports` | none | `{"uri":"ida://imports"}` | `{kind:"imports", count, items:[{module, name, address, ordinal}]}` |
| `ida://imports/{module}` | module name | `{"uri":"ida://imports/kernel32"}` | `{kind:"imports_module", module, count, items}` |
| `ida://exports` | none | `{"uri":"ida://exports"}` | `{kind:"exports", count, items:[{name, address, ordinal}]}` |
| `ida://entry_points` | none | `{"uri":"ida://entry_points"}` | `{kind:"entry_points", count, items:[{name, address, ordinal}]}` |
| `ida://structs` | none | `{"uri":"ida://structs"}` | `{kind:"structs", count, items:[{ordinal, name, kind, size, members}]}` |
| `ida://struct/{name}` | struct name | `{"uri":"ida://struct/MY_S"}` | `{kind:"struct", name, struct_kind, size, count, items}` |
| `ida://xrefs/to/{addr}` | address | `{"uri":"ida://xrefs/to/0x401000"}` | `{kind:"xrefs_to", address, count, items:[{address, type, is_code}]}` |
| `ida://xrefs/to/{addr}/summary` | address | `{"uri":"ida://xrefs/to/0x401000/summary"}` | `{kind:"xrefs_to_summary", address, count, code_count, data_count, items}` |
| `ida://xrefs/from/{addr}` | address | `{"uri":"ida://xrefs/from/0x401000"}` | `{kind:"xrefs_from", address, count, items:[{address, type, is_code}]}` |
| `ida://xrefs/from/{addr}/summary` | address | `{"uri":"ida://xrefs/from/0x401000/summary"}` | `{kind:"xrefs_from_summary", address, count, code_count, data_count, items}` |
| `ida://memory/{addr}` | address path param, `size` query param | `{"uri":"ida://memory/0x401000?size=32"}` | `{kind:"memory", address, size, bytes, hex}` |

## 6. Gateway Internal HTTP Endpoints

这些路由不是 MCP 协议的一部分，但它们是当前网关实现实际暴露的 HTTP API。

Base URL:

```text
http://127.0.0.1:11338/internal
```

`http_host` 控制 gateway 监听地址。来自 `127.0.0.1` / `::1` 的本机请求无需 token；非本机请求必须携带共享 token，且 `gateway_token` 为空时拒绝远程请求：

```http
Authorization: Bearer <gateway_token>
```

也支持 `X-IDA-MCP-Token: <gateway_token>`。是否允许非本机访问由 `http_host`、系统防火墙和网络环境决定；非本机访问应使用随机高强度 token，并保持 `enable_unsafe=false`，除非确实需要高危工具。

| Method | Path | Request Body | Expected Response |
| --- | --- | --- | --- |
| `GET` | `/healthz` | none | `{ok, gateway, gateway_proxy, instance_count, started_at}` |
| `GET` | `/instances` | none | 当前注册实例数组 |
| `GET` | `/current_instance` | none | `{port}` |
| `GET` | `/debug` | none | `{enabled}` |
| `POST` | `/debug` | `{"enable": true}` 或 `{"enabled": true}` | `{status:"ok", enabled}` |
| `GET` | `/gateway_proxy_status` | none | `{enabled, running, url, host, bind_host, port, path, last_error}` |
| `POST` | `/ensure_gateway_proxy` | none | 与 `/gateway_proxy_status` 相同 |
| `POST` | `/shutdown` | `{"force": false}` | 成功 `{status:"ok", message, forced, instance_count}`；存在实例且未 `force` 时 HTTP 409 |
| `POST` | `/register` | `{"pid":..., "port":..., ...}` | `{status:"ok"}`；缺字段时 HTTP 400 |
| `POST` | `/deregister` | `{"pid":...}` | `{status:"ok"}`；缺字段时 HTTP 400 |
| `POST` | `/select_instance` | `{"port":10000}` 或 `{}` | `{status:"ok", selected_port}`；找不到实例时 HTTP 404 |
| `POST` | `/call` | `{"tool":"list_functions","params":{},"port":10000,"timeout":30}` | 成功 `{tool, data}`；失败时 `{error}` |

### 6.1 `/call` Forwarding Rules

`POST /internal/call` 请求体字段：

- `tool: string`
- `params?: object`
- `pid?: int`
- `port?: int`
- `timeout?: int`

成功示例：

```json
{
  "tool": "get_metadata",
  "data": {
    "input_file": "D:\\samples\\a.exe",
    "arch": "x86_64",
    "bits": 64,
    "endian": "little",
    "hash": "..."
  }
}
```

失败示例：

```json
{
  "error": {
    "code": "instance_not_found",
    "message": "instance not found"
  }
}
```

## 7. Discovery Notes

标准 MCP discovery 仍然可用：

- `tools/list`
- `resources/list`
- `resources/read`

当前实现上的实际区别是：

- Gateway MCP proxy：主要用于多实例 tools
- Direct instance MCP：用于 tools + `ida://` resources
- 内部 HTTP：只给 gateway/proxy/runtime 使用，不建议普通 MCP client 直接依赖

## MCP 2026-07-28 / sessionless transport

Gateway MCP HTTP 已切换到 MCP `2026-07-28` 现代无状态传输：请求通过 `MCP-Protocol-Version` 和 `params._meta` 携带协议版本、client capabilities 等 envelope，不依赖 `initialize` 或 `Mcp-Session-Id`；默认返回单个 `application/json` 响应。旧版 initialize/session 客户端默认继续兼容；将 `mcp_legacy_protocol` 设为 `false` 后，握手时代的请求（`initialize`、`notifications/initialized` 或携带旧版 `MCP-Protocol-Version` 头）会被网关与实例服务器以 `-32601` JSON-RPC 错误拒绝，仅服务 `2026-07-28` 流量。

配置项（对外宣告的协议版本始终跟随 SDK 的 `LATEST_PROTOCOL_VERSION`，不可配置）：

```ini
mcp_sessionless = true
mcp_json_response = true
mcp_legacy_protocol = true
```

非 loopback 客户端需携带配置的 `gateway_token` 作为 bearer token；本机 loopback 继续免认证。
