# IDA-MCP

**[English](README.md)** | **[中文](README_CN.md)**

<img src="ida-mcp.png" width="50%">

[![MCP Badge](https://lobehub.com/badge/mcp/captain-ai-hub-ida-mcp)](https://lobehub.com/mcp/captain-ai-hub-ida-mcp)

[wiki](https://github.com/jelasin/IDA-MCP/wiki) [deepwiki](https://deepwiki.com/jelasin/IDA-MCP)

## IDA-MCP (FastMCP + 多实例协调器)

* 每个 IDA 实例启动一个 **FastMCP** 服务端 (`/mcp`)
* 第一个实例占用 `127.0.0.1:11337` 作为**协调器**，维护内存注册表并支持工具转发
* 后续实例自动注册到协调器；无需共享文件或手动配置端口
* 通过模块化**代理**统一访问/聚合实例工具（MCP 客户端可通过 command/args 启动代理）

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
* **MCP 资源**：REST 风格的 `ida://` URI 模式，提供只读数据访问
* **多实例支持**：端口 11337 上的协调器管理多个 IDA 实例
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
  ida_mcp.py              # 插件入口：启动/停止 SSE 服务 + 注册协调器
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

1. 将 `ida_mcp.py` + `ida_mcp` 文件夹复制到 IDA 的 `plugins/` 目录。
2. 打开目标二进制文件，等待分析完成。
3. 通过菜单/快捷键触发插件：首次启动将：
   * 选择空闲端口（从 10000 开始）运行 SSE 服务 `http://127.0.0.1:<port>/mcp/`
   * 如果 11337 空闲 → 启动协调器；否则注册到现有协调器
4. 再次触发插件 = 停止并注销实例。

## 代理使用

代理**同时支持两种传输模式** — 选择最适合你的 MCP 客户端的方式：

### 传输模式

| 模式 | 说明 | 配置 |
|------|------|------|
| **HTTP**（推荐） | 协调器自动启动，无需子进程 | 只需配置 `url` |
| **stdio** | MCP 客户端启动子进程 | 需要配置 `command` 和 `args` |

插件运行时两种模式始终可用。

**代理工具：**

| 类别 | 工具 |
|------|------|
| 管理 | `check_connection`, `list_instances`, `select_instance` |
| 核心 | `list_functions`, `get_metadata`, `list_strings`, `list_globals`, `list_local_types`, `get_entry_points`, `get_function` |
| 分析 | `decompile`, `disasm`, `linear_disassemble`, `xrefs_to`, `xrefs_from`, `find_bytes`, `get_basic_blocks` |
| 修改 | `set_comment`, `rename_function`, `rename_global_variable`, `rename_local_variable` |
| 内存 | `get_bytes`, `get_u8`, `get_u16`, `get_u32`, `get_u64`, `get_string` |
| 类型 | `set_function_prototype`, `set_local_variable_type`, `set_global_variable_type`, `declare_type` |
| Python | `py_eval` |
| 调试 | `dbg_start`, `dbg_continue`, `dbg_step_into`, `dbg_step_over`, `dbg_regs`, `dbg_add_bp`, `dbg_delete_bp`, ... |

可在 Codex / Claude Code / LangChain / Cursor / VSCode 等任何 MCP 客户端上使用。

### 配置文件

编辑 `ida_mcp/config.conf` 自定义设置：

```ini
# 协调器设置
# coordinator_host = "127.0.0.1"
# coordinator_port = 11337

# HTTP 代理设置
# http_host = "127.0.0.1"  # 使用 0.0.0.0 允许远程访问
# http_port = 11338
# http_path = "/mcp"

# IDA 实例设置
# ida_default_port = 10000

# 通用设置
# request_timeout = 30
# debug = false
```

### 方式一：HTTP 模式（推荐）

IDA 插件加载时 HTTP 代理自动启动。客户端只需配置 URL — 无需子进程。

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

### 方式二：stdio 模式

客户端以子进程方式启动代理。适用于 HTTP 不可用的场景。

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

⚠️ 注意：使用 VSCode Copilot 可能导致账号被封禁。

## 依赖

需要使用 IDA 的 Python 环境安装：

```bash
python -m pip install -r requirements.txt
```

## 开发理念

工具不在多，而在精准；API 的能力才是真正重要的。此外，工具应该全面，工具越多，模型调用的障碍越多。如果某些工具可以通过现有工具实现，那这些工具就是多余的。我需要的是缺失的工具——现有工具无法完成的那些。

## 未来计划

添加 UI 界面，支持内部模型调用，在 LangChain 正式更新到 1.0.0 后添加多智能体 A2A 自动化逆向工程功能。
