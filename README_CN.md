# IDA-MCP

**[English](README.md)** | **[中文](README_CN.md)**

<img src="ida-mcp.png" width="50%">

[![MCP Badge](https://lobehub.com/badge/mcp/captain-ai-hub-ida-mcp)](https://lobehub.com/mcp/captain-ai-hub-ida-mcp)

[wiki](https://github.com/jelasin/IDA-MCP/wiki) [deepwiki](https://deepwiki.com/jelasin/IDA-MCP)

## IDA-MCP (FastMCP + 多实例协调器)

* 每个 IDA 实例都会暴露自己的 **FastMCP Streamable HTTP** 端点 `/mcp`
* 第一个抢到 `127.0.0.1:11337` 的实例会成为内部**协调器**，维护内存注册表并转发工具调用
* 协调器还可以启动面向 MCP 客户端的 HTTP 代理，默认地址是 `127.0.0.1:11338`
* stdio 代理是独立子进程入口，但复用同一套 proxy 工具定义
* MCP Resources 由各个 IDA 实例直接暴露，不走 coordinator/proxy

## 架构

项目采用模块化架构：

### 核心基础设施

* `rpc.py` - `@tool` / `@resource` / `@unsafe` 装饰器与注册机制
* `sync.py` - `@idaread` / `@idawrite` IDA 线程同步装饰器
* `utils.py` - 地址解析、分页、模式过滤等工具函数
* `compat.py` - IDA 8.x/9.x 兼容层

### API 模块（IDA 后端）

* `api_core.py` - IDB 元数据、函数/字符串/全局变量列表
* `api_analysis.py` - 反编译、反汇编、交叉引用
* `api_memory.py` - 内存读取操作
* `api_types.py` - 类型操作（原型、本地类型）
* `api_modify.py` - 注释、重命名
* `api_stack.py` - 栈帧操作
* `api_debug.py` - 调试器控制（标记为不安全）
* `api_python.py` - Python 代码执行（标记为不安全）
* `api_resources.py` - MCP 资源（`ida://` URI 模式）

### 核心特性

* **装饰器链模式**：`@tool` + `@idaread`/`@idawrite` 实现简洁的 API 定义
* **批量操作**：大多数工具支持列表参数进行批量处理
* **MCP 资源**：REST 风格的 `ida://` URI 模式，提供面向单实例直连的只读数据访问
* **多实例支持**：端口 11337 上的协调器管理多个 IDA 实例
* **默认偏向 HTTP**：仓库内默认配置为 `enable_http=true`、`enable_stdio=false`
* **IDA 8.x/9.x 兼容**：兼容层处理 API 差异
* **字符串缓存**：字符串列表缓存避免每次调用重建，插件启动时后台预热
* **自定义超时**：所有工具支持自定义超时参数，AI 可按需传入
* **并发安全**：per-port 锁序列化并发调用 + Session 粘滞中间件

## 当前工具

### 核心工具 (`api_core.py`)

* `check_connection` – 健康检查（ok/count）
* `list_instances` – 列出所有已注册的 IDA 实例
* `get_metadata` – IDB 元数据（hash/arch/bits/endian）
* `list_functions` – 分页函数列表，支持可选模式过滤
* `get_function` – 通过名称或地址查找函数
* `list_globals` – 全局符号（非函数）
* `list_strings` – 提取的字符串（带缓存加速）
* `list_local_types` – 本地类型定义
* `get_entry_points` – 程序入口点
* `convert_number` – 数字格式转换
* `list_imports` – 列出导入函数及模块名
* `list_exports` – 列出导出函数/符号
* `list_segments` – 列出内存段及权限
* `get_cursor` – 获取当前光标位置和上下文

### 分析工具 (`api_analysis.py`)

* `decompile` – 批量反编译函数（Hex-Rays）
* `disasm` – 批量反汇编函数
* `linear_disassemble` – 从任意地址线性反汇编
* `xrefs_to` – 批量获取到地址的交叉引用
* `xrefs_from` – 批量获取从地址的交叉引用
* `xrefs_to_field` – 启发式结构体字段引用
* `find_bytes` – 搜索带通配符的字节模式
* `get_basic_blocks` – 获取基本块及控制流

### 内存工具 (`api_memory.py`)

* `get_bytes` – 读取原始字节
* `get_u8` / `get_u16` / `get_u32` / `get_u64` – 读取整数
* `get_string` – 读取空终止字符串

### 类型工具 (`api_types.py`)

* `declare_type` – 创建/更新本地类型
* `set_function_prototype` – 设置函数签名
* `set_local_variable_type` – 设置局部变量类型（Hex-Rays）
* `set_global_variable_type` – 设置全局变量类型
* `list_structs` – 列出所有结构体/联合体
* `get_struct_info` – 获取结构体定义及字段

### 修改工具 (`api_modify.py`)

* `set_comment` – 批量设置注释
* `rename_function` – 重命名函数
* `rename_local_variable` – 重命名局部变量（Hex-Rays）
* `rename_global_variable` – 重命名全局符号
* `patch_bytes` – 在地址处修补字节

### 栈帧工具 (`api_stack.py`)

* `stack_frame` – 获取栈帧变量
* `declare_stack` – 创建栈变量
* `delete_stack` – 删除栈变量

### Python 工具 (`api_python.py`) - 不安全

* `py_eval` – 在 IDA 上下文中执行 Python 代码，返回 result/stdout/stderr

### 调试工具 (`api_debug.py`) - 不安全

* `dbg_regs` – 获取所有寄存器
* `dbg_callstack` – 获取调用栈
* `dbg_list_bps` – 列出断点
* `dbg_start` – 启动调试
* `dbg_exit` – 终止调试
* `dbg_continue` – 继续执行
* `dbg_run_to` – 运行到地址
* `dbg_add_bp` – 添加断点
* `dbg_delete_bp` – 删除断点
* `dbg_enable_bp` – 启用/禁用断点
* `dbg_step_into` – 单步进入指令
* `dbg_step_over` – 单步跳过指令
* `dbg_read_mem` – 读取调试器内存
* `dbg_write_mem` – 写入调试器内存

### MCP 资源 (`api_resources.py`)

* `ida://idb/metadata` – IDB 元数据
* `ida://functions` / `ida://functions/{pattern}` – 函数
* `ida://function/{addr}` – 单个函数详情
* `ida://strings` / `ida://strings/{pattern}` – 字符串
* `ida://globals` / `ida://globals/{pattern}` – 全局符号
* `ida://types` / `ida://types/{pattern}` – 本地类型
* `ida://segments` – 段列表
* `ida://imports` – 导入列表
* `ida://exports` – 导出列表
* `ida://xrefs/to/{addr}` – 到地址的交叉引用
* `ida://xrefs/from/{addr}` – 从地址的交叉引用
* `ida://memory/{addr}?size=N` – 读取内存

## 目录结构

```text
IDA-MCP/
  ida_mcp.py              # 插件入口：启动/停止单实例 HTTP MCP 服务 + 注册协调器
  ida_mcp/
    __init__.py           # 包初始化，自动发现，导出
    config.py             # 配置加载器（config.conf 解析器）
    config.conf           # 用户配置文件
    rpc.py                # @tool/@resource/@unsafe 装饰器
    sync.py               # @idaread/@idawrite 线程同步
    utils.py              # 工具函数
    compat.py             # IDA 8.x/9.x 兼容层
    api_core.py           # 核心 API（元数据、列表）
    api_analysis.py       # 分析 API（反编译、反汇编、交叉引用）
    api_memory.py         # 内存 API
    api_types.py          # 类型 API
    api_modify.py         # 修改 API
    api_stack.py          # 栈帧 API
    api_debug.py          # 调试器 API（不安全）
    api_python.py         # Python 执行 API（不安全）
    api_resources.py      # MCP 资源
    registry.py           # 协调器 / 多实例注册
    proxy/                # 基于 stdio 的 MCP 代理
      __init__.py         # 代理模块导出
      ida_mcp_proxy.py    # 主入口（stdio MCP 服务端）
      _http.py            # 与协调器通信的 HTTP 辅助函数
      _state.py           # 状态管理和端口验证
      _server.py          # FastMCP 服务端实例和工具注册
      proxy_core.py       # 核心转发工具
      proxy_analysis.py   # 分析转发工具
      proxy_memory.py     # 内存转发工具
      proxy_types.py      # 类型转发工具
      proxy_modify.py     # 修改转发工具
      proxy_stack.py      # 栈帧转发工具
      proxy_debug.py      # 调试转发工具
      proxy_python.py     # Python 执行转发工具
    http/                 # 基于 HTTP 的 MCP 代理（自动启动，复用 stdio 代理）
      __init__.py         # HTTP 模块导出
      http_server.py      # HTTP 传输包装器（复用 ida_mcp_proxy.server）
  mcp.json                # MCP 客户端配置（两种模式）
  README.md               # 英文 README
  README_CN.md            # 中文 README
  requirements.txt        # fastmcp 依赖
```

## 启动步骤

1. 将 `ida_mcp.py` 和 `ida_mcp/` 目录复制到 IDA 的 `plugins/`。
2. 打开目标二进制并等待初始分析完成。
3. 在 IDA 中手动触发插件，或者通过 proxy 调用 `open_in_ida`。
4. 启动后，当前实例会：
   * 从 `10000` 开始选择一个空闲实例端口
   * 在 `http://127.0.0.1:<instance_port>/mcp/` 上提供该实例自己的 MCP 服务
   * 向 `127.0.0.1:11337` 上的协调器注册
   * 只有当前进程成为协调器且启用了 HTTP proxy 时，才会同时启动 `11338` 上的共享 HTTP proxy
5. 再次触发插件会停止实例服务并注销。

`open_in_ida` 是 proxy 侧的生命周期工具。它会带上 `IDA_MCP_AUTO_START=1` 启动 IDA，并在未显式指定时默认注入 `-A`，用于尽量减少启动交互，但不保证所有 IDA / loader / plugin 弹窗都被压掉。

## 传输概览

项目里有三个不同端点，这一点很重要：

* `127.0.0.1:11337`：内部 coordinator HTTP API，用于实例注册和工具转发
* `127.0.0.1:11338/mcp`：面向 MCP 客户端的 HTTP proxy，由 coordinator 在启用时启动
* `127.0.0.1:<instance_port>/mcp/`：某一个具体 IDA 实例的直连 MCP 端点

仓库附带的 `mcp.json` 以及当前默认配置，都是围绕 `11338` 这个 HTTP proxy 来设计的。

## 代理使用

proxy 通过 HTTP 和 stdio 暴露同一套转发工具：

### 传输模式

| 模式 | 说明 | 配置 |
|------|------|------|
| **HTTP proxy**（推荐） | 连接到 coordinator 持有的 `11338` proxy | 只需配置 `url` |
| **stdio proxy** | MCP 客户端以子进程方式启动 `ida_mcp/proxy/ida_mcp_proxy.py` | 需要配置 `command` 和 `args` |
| **实例直连 HTTP** | 直接连到单个 IDA 实例，主要用于 `ida://` resources | 需要目标实例端口 |

**代理工具：**

| 类别 | 工具 |
|------|------|
| 管理 | `check_connection`, `list_instances`, `select_instance` |
| 生命周期 | `open_in_ida`, `close_ida` |
| 核心 | `list_functions`, `get_metadata`, `list_strings`, `list_globals`, `list_local_types`, `get_entry_points`, `get_function`, `list_imports`, `list_exports`, `list_segments`, `get_cursor` |
| 分析 | `decompile`, `disasm`, `linear_disassemble`, `xrefs_to`, `xrefs_from`, `xrefs_to_field`, `find_bytes`, `get_basic_blocks` |
| 修改 | `set_comment`, `rename_function`, `rename_global_variable`, `rename_local_variable`, `patch_bytes` |
| 内存 | `get_bytes`, `get_u8`, `get_u16`, `get_u32`, `get_u64`, `get_string` |
| 类型 | `set_function_prototype`, `set_local_variable_type`, `set_global_variable_type`, `declare_type`, `list_structs`, `get_struct_info` |
| 栈帧 | `stack_frame`, `declare_stack`, `delete_stack` |
| Python | `py_eval` |
| 调试 | `dbg_start`, `dbg_continue`, `dbg_step_into`, `dbg_step_over`, `dbg_regs`, `dbg_add_bp`, `dbg_delete_bp`, ... |

可在 Codex / Claude Code / LangChain / Cursor / VSCode 等任何 MCP 客户端上使用。

proxy 和直连实例的参数名已经对齐。例如 `rename_function` 在两条路径上都使用 `address`，并同时接受符号名或数值地址。

### 配置文件

编辑 `ida_mcp/config.conf` 自定义设置：

```ini
# 传输开关
# enable_stdio = false
# enable_http = true

# 协调器设置
# coordinator_port = 11337

# HTTP 代理设置
# http_host = "127.0.0.1"
# http_port = 11338
# http_path = "/mcp"

# IDA 实例设置
# ida_default_port = 10000
# ida_path = "C:\\Path\\To\\ida.exe"

# 通用设置
# request_timeout = 30
# debug = false
```

说明：

* coordinator host 和 direct instance host 在代码里固定为 `127.0.0.1`
* `IDA_PATH` 的优先级高于 `config.conf` 里的 `ida_path`
* 如果 `enable_stdio` 和 `enable_http` 都关掉，插件不会启动 coordinator / transport 栈

### 方式一：HTTP Proxy 模式（推荐）

当 coordinator 已运行且启用了 HTTP proxy 时，客户端只需要 proxy URL，无需子进程。

**Claude / Cherry Studio / Cursor 示例：**

```json
{
  "mcpServers": {
    "ida-mcp": {
      "url": "http://127.0.0.1:11338/mcp"
    }
  }
}
```

**LangChain 示例：**

```json
{
  "mcpServers": {
    "ida-mcp": {
      "transport": "streamable-http",
      "url": "http://127.0.0.1:11338/mcp"
    }
  }
}
```

**VSCode 示例：**

```json
{
  "servers": {
    "ida-mcp": {
      "url": "http://127.0.0.1:11338/mcp"
    }
  }
}
```

### 方式二：stdio Proxy 模式

客户端以子进程方式启动代理。该 proxy 会连接 `11337` 上的 coordinator，并暴露与 HTTP proxy 相同的那套 proxy-side tools。

**Claude / Cherry Studio / Cursor 示例：**

```json
{
  "mcpServers": {
    "ida-mcp-proxy": {
      "command": "python 的路径（IDA 的 python）",
      "args": ["ida_mcp/proxy/ida_mcp_proxy.py 的路径"]
    }
  }
}
```

**VSCode 示例：**

```json
{
  "servers": {
    "ida-mcp-proxy": {
      "command": "python 的路径（IDA 的 python）",
      "args": ["ida_mcp/proxy/ida_mcp_proxy.py 的路径"]
    }
  }
}
```

## Resources

`ida://` resources 注册在单个 IDA 实例自己的 MCP 服务上，不在 proxy 上。这意味着：

* `list_resources` / `read_resource` 必须连到 `http://127.0.0.1:<instance_port>/mcp/`
* `11338` 上的 HTTP proxy 只转发 tools，不转发 resources
* resource 返回的是 JSON 文本内容，MCP 客户端通常还需要再把文本解析成 JSON
* resources 当前是只读能力，只覆盖常见 metadata / list / xref / memory 视图，不等价于全部工具面

典型流程：

1. 先通过 proxy 调 `list_instances` 找到目标实例端口。
2. 再直接连接 `http://127.0.0.1:<instance_port>/mcp/`。
3. 在这个直连客户端上调用 `list_resources` / `read_resource("ida://...")`。

## 自动安装

直接运行：

```bash
python install.py
```

安装脚本会：

* 在 Windows / Linux / macOS 上自动发现本机 IDA 安装
* 使用 IDA 自带的 Python 执行 `pip install -r requirements.txt`
* 将 `ida_mcp.py` 和 `ida_mcp/` 复制到 IDA 的 `plugins/` 目录
* 交互式生成目标 `ida_mcp/config.conf`

如果只想先验证发现结果和配置项，可运行 `python install.py --dry-run`。

## 依赖

需要使用 IDA 的 Python 环境安装：

```bash
python -m pip install -r requirements.txt
```

## 开发理念

工具不在多，而在精准；API 的能力才是真正重要的。此外，工具应该全面，工具越多，模型调用的障碍越多。如果某些工具可以通过现有工具实现，那这些工具就是多余的。我需要的是缺失的工具——现有工具无法完成的那些。

## 未来计划

添加 UI 界面，支持内部模型调用，在 LangChain 正式更新到 1.0.0 后添加多智能体 A2A 自动化逆向工程功能。
