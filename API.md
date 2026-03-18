# IDA-MCP API Reference

本文档基于当前工作区实现整理，覆盖：

- MCP 对外传输端点
- Gateway MCP proxy 工具
- 直连 IDA instance 工具
- `ida://` 资源
- Gateway 内部 HTTP 路由

## 1. Transport Endpoints

| Surface | URL | Purpose |
| --- | --- | --- |
| Gateway MCP proxy | `http://127.0.0.1:11338/mcp` | 多实例统一入口，只暴露 tools，不转发 `ida://` resources |
| Direct IDA instance MCP | `http://127.0.0.1:<instance_port>/mcp/` | 单实例直连入口，暴露 tools 和 `ida://` resources |
| Gateway internal HTTP | `http://127.0.0.1:11338/internal/*` | 非 MCP 内部控制/注册/转发接口 |

说明：

- `http_host` 可以绑定到 `0.0.0.0`，但客户端连接地址仍应使用 `127.0.0.1`
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

proxy/control 面的包装错误常见格式：

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
| `select_instance` | `port?: int` | `{"port": 10000}` | `{selected_port}` 或包装错误 |

### 3.2 Lifecycle

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `open_in_ida` | `file_path: str`, `extra_args?: string[]` | `{"file_path":"D:\\samples\\a.exe"}` | 成功时 `{status, message, requested_port, launch_bundle, staged_file, launch_target}`；失败时 `{error}` |
| `close_ida` | `save?: bool`, `port?: int`, `timeout?: int` | `{"save":false,"port":10000}` | 直返目标实例 `close_ida` 结果，典型为 `{status:"ok", message:"IDA is closing"}` 或包装错误 |
| `shutdown_gateway` | `force?: bool`, `timeout?: int` | `{"force":true}` | `{status:"ok", message, forced, instance_count}` 或 `{error}` |

`open_in_ida` 当前行为：

- 启动 IDA 子进程时设置 `IDA_MCP_AUTO_START=1`
- 同时设置预留端口环境变量 `IDA_MCP_PORT`
- 如果 `IDA_MCP_BUNDLE_DIR` 或 `open_in_ida_bundle_dir` 已配置，则会在该目录下创建时间戳子目录
- 若目标旁边存在匹配的 `.i64/.idb`，则优先打开数据库，以避免再次弹出 loader/options 确认框

## 4. Backend Tool Catalog

以下工具在 direct instance MCP 直接可用。

以下工具在 Gateway MCP proxy 上也可用，但会额外接受 `port?` 与 `timeout?`。

如果 `enable_unsafe=false` 或环境变量 `IDA_MCP_ENABLE_UNSAFE=0`，则 `py_eval` 与全部 `dbg_*` 工具不会注册。

### 4.1 Core Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `check_connection` | none | `{}` | `{ok: bool, count: int}` |
| `list_instances` | none | `{}` | `[{pid, port, input_file, idb, started, ...}]` |
| `get_metadata` | none | `{}` | `{input_file, arch, bits, endian, hash}` |
| `list_functions` | `offset?: int`, `count?: int`, `pattern?: str` | `{"offset":0,"count":20,"pattern":"sub_*"}` | 分页结果；`items` 为 `[{name, start_ea, end_ea}]` |
| `list_globals` | `offset?: int`, `count?: int`, `pattern?: str` | `{"pattern":"g_*"}` | 分页结果；`items` 为 `[{name, ea, size}]` |
| `list_strings` | `offset?: int`, `count?: int`, `pattern?: str` | `{"pattern":"http"}` | 分页结果；`items` 为 `[{ea, length, type, text}]` |
| `list_local_types` | none | `{}` | `{total, items:[{ordinal, name, decl}]}` |
| `get_entry_points` | none | `{}` | `{total, items:[{ordinal, ea, name}]}` |
| `convert_number` | `text: str`, `size?: int` | `{"text":"401000h","size":64}` | `{input, size, value, hex, dec, unsigned, signed, bin, bytes_le, bytes_be}` |
| `list_imports` | `offset?: int`, `count?: int`, `pattern?: str` | `{"pattern":"kernel32"}` | 分页结果；`items` 为 `[{ea, name, ordinal, module}]` |
| `list_exports` | `offset?: int`, `count?: int`, `pattern?: str` | `{"count":50}` | 分页结果；`items` 为 `[{ea, name, ordinal}]` |
| `list_segments` | none | `{}` | `{total, items:[{name, start_ea, end_ea, size, perm, class, bitness}]}` |
| `get_cursor` | none | `{}` | `{ea, ea_int, function?, selection?}` |

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

### 4.6 Stack Tools

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `stack_frame` | `addr: int | str` | `{"addr":"main"}` | `[{query, name, start_ea, method?, variables, frame_structure?, error?, note?}]` |
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

说明：

- 全部 debug 工具都被标记为 unsafe
- 大多数 debug 工具要求调试器已激活；未激活时通常返回 `{ok:false,...}` 或 `{error:"debugger not active"}`

### 4.10 Instance Lifecycle Tool

| Tool | Parameters | Request Example | Expected Response |
| --- | --- | --- | --- |
| `close_ida` | `save?: bool` | `{"save":true}` | `{status:"ok", message:"IDA is closing"}` 或 `{error}` |

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
| `ida://function/{addr}/stack` | `addr` path param | `{"uri":"ida://function/0x401000/stack"}` | `{kind:"function_stack", address, name, method, count, items, frame_structure?}` |
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

| Method | Path | Request Body | Expected Response |
| --- | --- | --- | --- |
| `GET` | `/healthz` | none | `{ok, gateway, proxy, instance_count, started_at}` |
| `GET` | `/instances` | none | 当前注册实例数组 |
| `GET` | `/current_instance` | none | `{port}` |
| `GET` | `/debug` | none | `{enabled}` |
| `POST` | `/debug` | `{"enable": true}` 或 `{"enabled": true}` | `{status:"ok", enabled}` |
| `GET` | `/proxy_status` | none | `{enabled, running, url, host, bind_host, port, path, last_error}` |
| `POST` | `/ensure_proxy` | none | 与 `/proxy_status` 相同 |
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
  "error": "instance not found"
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
