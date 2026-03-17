# IDA-MCP

**[English](README.md)** | **[中文](README_CN.md)**

<img src="ida-mcp.png" width="50%">

[![MCP Badge](https://lobehub.com/badge/mcp/captain-ai-hub-ida-mcp)](https://lobehub.com/mcp/captain-ai-hub-ida-mcp)

[wiki](https://github.com/jelasin/IDA-MCP/wiki) [deepwiki](https://deepwiki.com/jelasin/IDA-MCP)

## IDA-MCP (FastMCP + 多实例网关)

* 每个 IDA 实例都会暴露自己的 **FastMCP Streamable HTTP** 端点 `/mcp`
* 独立网关守护进程负责维护内存中的实例注册表并转发工具调用
* 同一个网关进程默认在 `127.0.0.1:11338` 上同时提供 `/internal` 内部 API 和 `/mcp` 客户端 MCP 入口
* stdio 代理是独立子进程入口，但复用同一套 proxy 工具定义
* MCP Resources 由各个 IDA 实例直接暴露，不走 gateway/proxy

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
* `api_modeling.py` - 数据库塑形（函数、code/data/string 创建）
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
* **多实例支持**：默认监听在 11338 的独立网关管理多个 IDA 实例
* **默认偏向 HTTP**：仓库内默认配置为 `enable_http=true`、`enable_stdio=false`、`enable_unsafe=true`
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
* `linear_disasm` – 从任意地址线性反汇编
* `xrefs_to` – 批量获取到地址的交叉引用
* `xrefs_from` – 批量获取从地址的交叉引用
* `xrefs_to_field` – 启发式结构体字段引用
* `find_bytes` – 搜索带通配符的字节模式
* `get_basic_blocks` – 获取基本块及控制流

### 内存工具 (`api_memory.py`)

* `get_bytes` – 读取原始字节
* `get_u8` / `get_u16` / `get_u32` / `get_u64` – 读取整数
* `get_string` – 读取空终止字符串

### 建模工具 (`api_modeling.py`)

* `create_function` – 在地址处创建函数
* `delete_function` – 删除已有函数
* `make_code` – 把地址处字节转换为代码
* `undefine_items` – 取消定义一段字节范围
* `make_data` – 创建带类型的数据项
* `make_string` – 创建字符串字面量
* `create_array` – 创建带类型的数据数组

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
* `ida://functions` – 函数列表
* `ida://function/{addr}` – 单个函数详情
* `ida://function/{addr}/decompile` – 函数反编译快照
* `ida://function/{addr}/disasm` – 函数反汇编快照
* `ida://function/{addr}/basic_blocks` – 函数基本块 / CFG 视图
* `ida://function/{addr}/stack` – 函数栈帧 / 局部变量视图
* `ida://strings` – 字符串
* `ida://globals` – 全局符号
* `ida://types` – 本地类型
* `ida://segments` / `ida://segment/{name_or_addr}` – 段列表与详情
* `ida://imports` / `ida://imports/{module}` – 导入列表与按模块视图
* `ida://exports` – 导出列表
* `ida://entry_points` – 入口点
* `ida://structs` / `ida://struct/{name}` – 结构体列表与详情
* `ida://xrefs/to/{addr}` – 到地址的交叉引用
* `ida://xrefs/to/{addr}/summary` – 入向 xref 聚合摘要
* `ida://xrefs/from/{addr}` – 从地址的交叉引用
* `ida://xrefs/from/{addr}/summary` – 出向 xref 聚合摘要
* `ida://memory/{addr}?size=N` – 读取内存

## 目录结构

```text
IDA-MCP/
  ida_mcp.py              # 插件入口：启动/停止单实例 HTTP MCP 服务 + 向网关注册
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
    api_modeling.py       # 建模 API（函数、code/data/string 创建）
    api_types.py          # 类型 API
    api_modify.py         # 修改 API
    api_stack.py          # 栈帧 API
    api_debug.py          # 调试器 API（不安全）
    api_python.py         # Python 执行 API（不安全）
    api_lifecycle.py      # IDA 实例内生命周期 API（关闭/退出）
    api_resources.py      # MCP 资源
    registry.py           # 网关客户端辅助逻辑 / 多实例注册
    proxy/                # 基于 stdio 的 MCP 代理
      __init__.py         # 代理模块导出
      ida_mcp_proxy.py    # 主入口（stdio MCP 服务端）
      lifecycle.py        # proxy 侧生命周期操作
      _http.py            # 与网关通信的 HTTP 辅助函数
      _state.py           # 状态管理和端口验证
      _server.py          # FastMCP 服务端实例和工具注册
      register_tools.py   # 集中注册所有转发工具
      http_server.py      # HTTP 传输包装器（复用 ida_mcp_proxy.server）
  mcp.json                # MCP 客户端配置（两种模式）
  roadmap.md              # 逐阶段降低 py_eval 依赖的路线图
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
   * 确保独立网关守护进程可通过 `127.0.0.1:11338` 访问
   * 通过 `http://127.0.0.1:11338/internal` 向网关内部 API 注册自己
5. 再次触发插件会停止实例服务并注销。

关闭某个 IDA 实例只会注销该实例；独立网关会继续运行，后续新实例仍可继续接入。

`open_in_ida` 是 proxy 侧的生命周期工具。它会使用 `IDA_PATH` 或 `config.conf` 中的 `ida_path` 解析 IDA 可执行文件，并带上 `IDA_MCP_AUTO_START=1` 让插件自动启动。默认保持 IDA 的正常交互式 GUI 模式；如果你确实需要 batch/autonomous 模式，再通过 `extra_args` 显式传入 `-A`。

IDA-MCP 支持 WSL 兼容运行。在 WSL 环境下，`open_in_ida` 可以从 Linux 侧工具链直接启动 Windows 版 IDA，并会在启动前自动把目标文件路径转换成 Windows 路径。

## 传输概览

项目里有两个网关侧端点，再加上每个实例自己的直连端点，这一点很重要：

* `127.0.0.1:11338/internal`：网关内部 HTTP API，用于实例注册和工具转发
* `127.0.0.1:11338/mcp`：同一个独立网关进程暴露给 MCP 客户端的 HTTP proxy
* `127.0.0.1:<instance_port>/mcp/`：某一个具体 IDA 实例的直连 MCP 端点

仓库附带的 `mcp.json` 以及当前默认配置，都是围绕 `11338` 这个 HTTP proxy 来设计的。

## 代理使用

proxy 通过 HTTP 和 stdio 暴露同一套转发工具：

### 传输模式

| 模式 | 说明 | 配置 |
|------|------|------|
| **HTTP proxy**（推荐） | 连接到独立网关暴露的 `11338` proxy | 只需配置 `url` |
| **stdio proxy** | MCP 客户端以子进程方式启动 `ida_mcp/proxy/ida_mcp_proxy.py` | 需要配置 `command` 和 `args` |
| **实例直连 HTTP** | 直接连到单个 IDA 实例，主要用于 `ida://` resources | 需要目标实例端口 |

**代理工具：**

| 类别 | 工具 |
|------|------|
| 管理 | `check_connection`, `list_instances`, `select_instance` |
| 生命周期 | `open_in_ida`, `close_ida` |
| 核心 | `list_functions`, `get_metadata`, `list_strings`, `list_globals`, `list_local_types`, `get_entry_points`, `get_function`, `list_imports`, `list_exports`, `list_segments`, `get_cursor` |
| 分析 | `decompile`, `disasm`, `linear_disasm`, `xrefs_to`, `xrefs_from`, `xrefs_to_field`, `find_bytes`, `get_basic_blocks` |
| 建模 | `create_function`, `delete_function`, `make_code`, `undefine_items`, `make_data`, `make_string`, `create_array` |
| 修改 | `set_comment`, `rename_function`, `rename_global_variable`, `rename_local_variable`, `patch_bytes` |
| 内存 | `get_bytes`, `get_u8`, `get_u16`, `get_u32`, `get_u64`, `get_string` |
| 类型 | `set_function_prototype`, `set_local_variable_type`, `set_global_variable_type`, `declare_type`, `list_structs`, `get_struct_info` |
| 栈帧 | `stack_frame`, `declare_stack`, `delete_stack` |
| Python | `py_eval` |
| 调试 | `dbg_start`, `dbg_continue`, `dbg_step_into`, `dbg_step_over`, `dbg_regs`, `dbg_add_bp`, `dbg_delete_bp`, ... |

可在 Codex / Claude Code / LangChain / Cursor / VSCode 等任何 MCP 客户端上使用。

proxy 和直连实例的参数名已经对齐。例如 `rename_function` 在两条路径上都使用 `address`，并同时接受符号名或数值地址。多实例场景下，建议优先在 proxy 工具上显式传 `port`，不要依赖进程级默认实例状态。

### 配置文件

编辑 `ida_mcp/config.conf` 自定义设置：

```ini
# 传输开关
# enable_stdio = false
# enable_http = true
# enable_unsafe = true

# 协调器设置
# coordinator_port = 11337  # 兼容旧配置；当前内部 API 已并入 http_port

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

* gateway host 和 direct instance host 对客户端来说在代码里固定为 `127.0.0.1`
* `IDA_PATH` 的优先级高于 `config.conf` 里的 `ida_path`
* `IDA_MCP_ENABLE_UNSAFE=1|0` 的优先级高于 `config.conf` 里的 `enable_unsafe`
* `open_in_ida` 不再接受 `ida_path` 工具参数；请通过 `IDA_PATH` 或 `config.conf` 配置 IDA 路径
* 支持 WSL：可以在 WSL 里使用整套工具，并通过 `open_in_ida` 启动 Windows 版 IDA
* 如果 `enable_stdio` 和 `enable_http` 都关掉，插件不会启动 gateway / transport 栈

### 方式一：HTTP Proxy 模式（推荐）

当独立网关已运行且启用了 HTTP proxy 时，客户端只需要 proxy URL，无需子进程。

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

客户端以子进程方式启动代理。该 proxy 会连接 `11338` 上的独立网关，并暴露与 HTTP proxy 相同的那套 proxy-side tools。

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
* resources 只提供稳定的只读上下文视图，不等价于完整 tool 面

resource payload 约定：

* 列表资源统一返回 `{kind, count, items}`
* 详情资源统一返回 `{kind, address|name, ...}`
* 错误统一返回 `{error: {code, message, details?}}`
* 旧的 pattern 风格 URI，例如 `ida://functions/{pattern}`，已经移除，统一改成规范化的 list/detail URI

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

## 命令行入口

可以使用 `command.py` 做本地控制、脚本化和 CI 场景下的直接调用：

```bash
python command.py gateway start
python command.py gateway restart
python command.py gateway status
python command.py ida list
python command.py ida open ./test/samples/simple.exe
python command.py ida select --port 10000
python command.py tool call get_metadata --port 10000
python command.py resource read ida://functions --port 10000
python command.py gateway stop --force
```

如果需要机器可读输出，任意命令后都可以加 `--json`；默认输出仍然是人类可读格式。

## 依赖

需要使用 IDA 的 Python 环境安装：

```bash
python -m pip install -r requirements.txt
```

## 开发理念

工具不在多，而在精准；API 的能力才是真正重要的。此外，工具应该全面，工具越多，模型调用的障碍越多。如果某些工具可以通过现有工具实现，那这些工具就是多余的。我需要的是缺失的工具——现有工具无法完成的那些。

## 未来计划

添加 UI 界面，支持内部模型调用，在 LangChain 正式更新到 1.0.0 后添加多智能体 A2A 自动化逆向工程功能。
