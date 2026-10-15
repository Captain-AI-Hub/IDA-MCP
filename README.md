# IDA-MCP-Hub

IDA Pro 的 MCP（Model Context Protocol）服务器：**stdio 传输**、无头 idalib worker、
多实例生命周期管理与官方 IDAPython 文档查询。工具目录为本项目自有的
反汇编/反编译/修改/调试全量 API（93 个工具）。

```text
MCP 客户端 ──stdio──▶ idamcp-hub 独立进程
                        │  ├─ 实例发现：<IDAUSR>/ida-mcp/instances.json
                        │  └─ 直连各 IDA 进程内的 JSON-RPC 桥（无网关、无端口注册转发）
                        ▼
             GUI IDA（插件桥）  +  无头 idalib worker（自动创建/分析 .i64）
```

## 核心特性

- **stdio 唯一传输**（`uvx idamcp-hub stdio`）。HTTP/网关/端口注册转发机制已删除。
- **open_database**：附加已打开的 GUI 实例，或启动**无头 idalib worker**（自动创建并分析
  .i64），或显式 `headless="gui"` 拉起 GUI。
- **多实例**：`list_databases / select_database / save_database / close_database`，
  官方式 instance_id 语义；无头 worker 随最后一个使用者关闭（默认先保存）。
- **官方 IDAPython 文档**：`ida_python_reference(query)` 基于当前 IDA 运行时构建
  BM25 索引（约 2 万条 API 签名 + 文档字符串），版本永远匹配。
- **IDA 进程内零第三方依赖**：桥为纯标准库实现，不再向 IDAPython 安装
  fastmcp/uvicorn 等包。

## 安装

### 1. IDA 插件（GUI 附加用；纯无头可跳过）

```bash
python install.py            # 复制 ida_mcp.py + ida_mcp/ 到 IDA plugins 目录
# 或
hcli plugin install IDA-MCP-Hub@https://github.com/Captain-AI-Hub/IDA-MCP
```

插件加载后桥自动启动：固定监听 `127.0.0.1`（端口自 13337 向上递增），
并登记到 `~/.idapro/ida-mcp/instances.json`，无需任何配置。

### 2. 独立 MCP 服务器

```bash
# 无需克隆，直接从 GitHub 运行（也可换成任意 ref / 本地路径）：
uvx idamcp-hub stdio
# 指定仓库/分支（未发布新版时）：
uvx --from git+https://github.com/Captain-AI-Hub/IDA-MCP idamcp-hub stdio
# 或从源码：
python -m ida_mcp stdio
```

PyPI 包名 **`idamcp-hub`**（`idamcp` 与官方 `ida-mcp` 过于相似被 PyPI 拒绝），
已发布，`uvx idamcp-hub stdio` 即开即用。

**发布方式**：推送 `v*` tag 触发 `.github/workflows/pypi-publish.yml`
（优先用仓库 secret `PYPI_API_TOKEN`，未设置时走 trusted publisher）。

MCP 客户端配置（HCLI/安装器安装完成后打印同款，可直接复制）：

```json
{
  "mcpServers": {
    "ida-mcp": { "command": "uvx", "args": ["idamcp-hub", "stdio"] }
  }
}
```

### 3. 无头 worker 的 Python（idalib）

无头 `open_database` 需要一个 **`import idapro` 可用** 的 Python。检测顺序：

1. 配置 `idalib_python`
2. 配置/检测的 `ida_python`
3. `~/.idapro/ida-config.json` 中 `ida-install-dir` 下的 `ida-python`（自编译运行时）
4. `<state>/idalib-venv` 与 `~/.idapro/venv`

首次探测成功会写入用户级配置 `~/.idapro/ida-mcp/config.conf` 缓存。
若还没有激活的运行时：`pip install <IDA>/idalib/python/idapro-*.whl` 后运行
`python <IDA>/py-activate-idalib.py`。

> **关于 `~/.idapro/venv` 一直没生效**：IDA 通过 idapyswitch 选定的
> `libpython3.12.so`（注册于 `~/.idapro/ida.reg` 的 `Python3TargetDLL`）加载
> Python，不读取任何 venv；venv 本身也没有自己的 libpython，所以对 IDA 永远
> 不可见，也不存在“每次激活”一说。对 IDA 唯一生效的是 `Python3TargetDLL`
> 指向的那套安装。新架构下 IDA 内零依赖，该问题不复存在；这个 venv 仅当其中
> 装有 idapro 包时才会被选作无头 worker 解释器。

## CLI

```bash
idamcp-hub                  # = idamcp-hub stdio
idamcp-hub instances list       # 列出活跃实例（GUI + 无头）
idamcp-hub open <path> [--gui]  # 附加或无头打开（自动创建/分析 .i64）
idamcp-hub close [--id ID] [--terminate]
idamcp-hub save [--id ID]
idamcp-hub tool call <name> --params '{"addr":"main"}'
idamcp-hub reference "decompile function" [--module ida_funcs]
idamcp-hub config show
```

## 配置

`ida_mcp/config.conf`（包内）与 `~/.idapro/ida-mcp/config.conf`（用户级，优先生效），
仅 4 个键：`ida_path`（GUI 启动）、`ida_python`（IDAPython 运行时，无头 idalib
worker 也用它——正常就是同一个解释器）、`request_timeout`、`debug`。两个路径在
**install.py / hcli_install.py / package_hcli.py（本地打 zip 时写入提示默认值）安装
时自动探测**并缓存到用户级配置（首启时也会兜底重探测），日常无需手工配置。
实例桥固定 `127.0.0.1:13337+` 且插件自动启动，无需配置。
环境变量覆盖：`IDA_MCP_CONFIG_<KEY>`。

## 工具面

- 生命周期：`open_database`、`list_databases`、`select_database`、
  `save_database`、`close_database`、`check_connection`
- 文档：`ida_python_reference(query, module=None)`
- 后端目录（93 个，每个都可带 `instance_id` 覆盖目标）：反编译/反汇编/xref/搜索/
  重命名/注释/patch/类型/结构体/栈帧/内存/`py_eval`/`dbg_*` 等全量开放，见 [API.md](API.md)。

## 运行时边界

- IDA 运行时：所有 SDK 调用经 `@idaread/@idawrite` 在 IDA 主线程执行
  （GUI 用 `execute_sync`；idalib worker 由主线程队列串行执行）。
- 独立进程：任何 Python ≥3.11；fastmcp 4.x；不接触 IDA SDK。
- 测试：`pytest`——无可用 IDA/idalib 时后端测试自动跳过；本机有 idalib 时会
  无头启动 `test/samples/complex.exe` 实例实测（`--ida-open-timeout` 可调）。

## 布局

```text
IDA-MCP/
├── ida_mcp.py          # IDA 插件入口（PLUGIN_ENTRY）
├── ida-plugin.json     # HCLI 插件元数据
├── ida_mcp/
│   ├── bridge_server.py   # 实例内 JSON-RPC 桥（纯标准库）
│   ├── worker.py          # 无头 idalib worker 进程
│   ├── mcp_server.py      # 独立 stdio MCP 服务器
│   ├── instances.py       # 共享 JSON 实例清单
│   ├── lifecycle.py       # open/close/save/attach 生命周期
│   ├── bridge_client.py   # 桥 HTTP 客户端
│   ├── idapython_docs.py  # 官方 IDAPython 文档索引（BM25）
│   ├── api_*.py           # 工具目录（反汇编/反编译/修改/调试…）
│   └── sync.py / rpc.py   # 主线程调度与工具注册
├── install.py          # 插件安装器
├── scripts/            # HCLI 打包与安装辅助
├── test/               # pytest 套件（单元 + 无头真机）
└── API.md / project.md / roadmap.md
```
