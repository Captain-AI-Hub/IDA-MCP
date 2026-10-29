# IDA-MCP API Reference

本文档覆盖当前架构（v0.10，stdio 单传输 + 实例桥 + 纯 idalib 无头 worker）的对外契约：

1. MCP 服务器（stdio）工具面
2. 实例桥 JSON-RPC 协议（内部，回环）
3. 共享实例清单格式
4. 配置项
5. 后端工具目录概览

## 1. MCP 工具面（`idamcp stdio`）

所有工具返回 JSON 文本；错误统一为 `{"error": {"code", "message", ...}}`。

### 1.1 生命周期

| 工具 | 参数 | 说明 |
| --- | --- | --- |
| `open_database` | `path`；`wait_for_analysis=true`；`timeout=300` | 附加同文件的活跃 worker，否则启动无头 idalib worker（自动创建/分析 .i64）。返回 `{status, mode, instance}`，多实例时后续调用需引用 `instance.instance_id` |
| `list_databases` | — | 全部活跃实例 |
| `save_database` | `instance_id?`, `timeout?` | 保存 .i64 |
| `close_database` | `instance_id?`, `terminate=false`, `save=true` | 释放 worker：最后一个使用者 detach 时保存并关闭；`terminate=true` 无视其他租约强制关闭 |
| `check_connection` | — | 已解析实例的健康检查（pid/端口/路径/IDA 版本） |

### 1.2 文档

| 工具 | 参数 | 说明 |
| --- | --- | --- |
| `ida_python_reference` | `query`；`module?`（如 `ida_funcs`）；`limit=20` | 对当前 IDA 运行时的官方 IDAPython API 建 BM25 索引并检索；`query="modules"` 列出模块 |

### 1.3 转发的后端工具

`api_*.py` 注册的全部工具（90 个，除 `check_connection`/`list_instances`，
由管理工具替代）逐一经桥转发，签名与后端一致，并追加两个
可选参数：

- `instance_id?: string` — 目标实例（见下述路由规则）
- `timeout?: int` — 秒

**实例路由（无状态，无默认选中）**：`select_database` 已移除，服务器不再
保存"当前实例"。每次调用独立路由：显式 `instance_id` 永远优先；省略时若
恰好只有一个活跃实例则路由到它；多于一个活跃实例时，省略 `instance_id`
的调用返回 `instance_ambiguous` 错误并列出全部实例。多个 agent 并发使用
同一服务器时互不影响——任何一方都无法改变其他调用的目标。

`py_eval`、`patch_*`、`apply_patch`、`dbg_*` 等原 unsafe 工具全量开放，
不再有门禁（桥默认仅监听回环地址）。

### 1.4 地址参数约定

所有接受地址的工具（`address` / `addr` / `function_address` / `start` 等）
统一走 `utils.resolve_address`：十六进制/十进制/整数，解析失败后回退
`idaapi.get_name_ea` 符号名解析（函数名、全局名、字符串名如 `aIdaMcpTest`）。

## 2. 实例桥协议（内部，固定 127.0.0.1:13337 起递增）

每个无头 idalib worker 进程内运行一个纯标准库 HTTP 服务：

| 方法 | 路径 | 请求 | 响应 |
| --- | --- | --- | --- |
| GET | `/healthz` | — | `{"ok": true}` |
| GET | `/meta` | — | `{"result": {instance_id, pid, port, input_file, database_path, ida_version, headless, ...}}` |
| POST | `/rpc` | `{"tool", "params", "timeout"?}` | `{"result": ...}` 或 `{"error": {code, message, details?}}`（404 未知工具 / 403 unsafe / 500 失败 / 504 超时） |
| GET | `/docs/modules` | — | `{"result": [{module, entries, description}]}` |
| POST | `/docs` | `{"module"}` | `{"result": {module, module_doc, entries: [...]}}` |
| POST | `/shutdown` | `{"save": bool}` | 受控退出（保存后退出） |

桥固定监听 `127.0.0.1`（端口自 13337 向上递增），仅本机可达，无认证。

执行模型：idalib 仅允许主线程调用 SDK；worker 将桥的 HTTP 调用排入主线程队列
串行执行，加载期由 ready 门闸挂起 `wait_for_analysis`。

## 3. 实例清单（`<IDAUSR>/ida-mcp/instances.json`）

```json
{
  "version": 1,
  "instances": [
    {
      "instance_id": "i-a1b2c3d4",
      "pid": 12345,
      "port": 13337,
      "host": "127.0.0.1",
      "input_file": "/path/to/app.exe",
      "database_path": "/path/to/app.exe.i64",
      "headless": true,
      "started_at": 1792000000.0,
      "last_seen_at": 1792000030.0,
      "version": "0.9.0"
    }
  ]
}
```

写入为原子替换 + 文件锁；读取方自动剔除进程已死的条目。`IDA_MCP_STATE_DIR`
或 `IDAUSR` 可重定向状态目录。

## 4. 配置项

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `instance_host` / `instance_port` | `127.0.0.1` / `13337` | 桥监听与起始端口 |
| `instance_token` | "" | 非回环监听必填 |
| `auto_start` | true | 数据库打开后自动启动桥 |
| `ida_python` | "" | IDAPython 运行时，兼作无头 idalib worker 解释器（自动检测） |
| `request_timeout` / `debug` | 30 / false | 通用 |

桥监听（127.0.0.1:13337+）为固定行为，
不提供配置。

优先级：内置默认 → 包内 `config.conf` → 用户级 `<state>/config.conf` →
`IDA_MCP_CONFIG_*` 环境变量 → HCLI ida-settings（仅 IDA 内）。

## 5. 后端工具目录概览（90 个）

- **Core**：`get_metadata`、`list_functions/globals/strings/local_types`、
  `get_entry_points`、`convert_number`、`list_imports/exports/segments`、
  `add_segment`、`delete_segment`、`get_cursor`、`survey_binary`
- **Analysis**：`decompile`、`disasm`、`linear_disasm`、`get_callers/callees`、
  `get_function_signature`、`xrefs_to/from`、`xrefs_to_field`（`strict=true` 仅保留操作数带结构体类型
信息的命中，过滤 `[reg+disp]` 文本误报；默认启发式并给每条命中标注
`typed`）、`find_bytes`、
  `get_basic_blocks`、`find_regex`、`search_text`、`find_instructions`、
  `callgraph`、`trace_data_flow`、签名系列（`make_signature*`、`find_xref_signatures`）
- **Memory**：`get_bytes`、`read_scalar`、`get_string`
- **Modify**：`set_comment`、`rename_*`、`add_bookmark`、`set_op_type`、
  `force_recompile`、`diff_before_after`、`patch_bytes`、`apply_patch`、
  `patch_asm`
- **Modeling**：`create/delete_function`、`make_code/data/string`、`undefine_items`
- **Types**：`declare_struct/enum/typedef`、`set_*_type`、`list_structs`、
  `get_struct_info`、`infer_types`
- **Stack**：`stack_frame`、`declare_stack`、`delete_stack`
- **Python**：`py_eval`、`py_exec_file`
- **Debug**：`dbg_*` 系列（无头可用：`dbg_start` 自动加载本机调试器，可传
  `debugger` 参数指定如 `gdb`；IDA 9 无官方调用栈 API，`dbg_callstack` 由
  帧指针链（RBP/EBP/X29）重建，省略帧指针的二进制可能截断）
- **Lifecycle**：`save_idb`、`wait_for_analysis`

各工具参数以 MCP `tools/list` 的 schema 为准（`idamcp tool call <name>`
可直接试用）。

## 变更记录（契约层面）

- v0.9：删除 HTTP 传输、网关/端口注册转发、`ida://` 资源、gateway token
  与 `enable_unsafe` 门禁（工具全量开放）；MCP 仅 stdio；新增实例桥协议、
  无头 worker、共享实例清单、`open_database` 等生命周期工具与
  `ida_python_reference`。
