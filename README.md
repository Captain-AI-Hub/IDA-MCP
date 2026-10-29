# IDA-MCP-Hub

IDA Pro 的 MCP（Model Context Protocol）服务器：**stdio 传输**、无头 idalib worker、
多实例生命周期管理与官方 IDAPython 文档查询。工具目录为本项目自有的
反汇编/反编译/修改/调试全量 API（90 个工具）。**纯 idalib 架构：无 GUI 插件、
无 IDA 可执行文件路径依赖。**

```text
MCP 客户端 ──stdio──▶ idamcp-hub 独立进程
                        │  ├─ 实例发现：<IDAUSR>/ida-mcp/instances.json
                        │  └─ 直连各 worker 进程内的 JSON-RPC 桥（无网关、无端口注册转发）
                        ▼
             无头 idalib worker ×N（自动创建/分析 .i64，含调试器）
```

## 核心特性

- **stdio 唯一传输**（`uvx idamcp-hub stdio`）。HTTP/网关/端口注册转发机制已删除。
- **open_database**：附加已存在的同文件 worker，或启动**无头 idalib worker**
  （自动创建并分析 .i64）。
- **多实例（无状态路由）**：`list_databases / save_database / close_database`，
  以 instance_id 标识各数据库；无 `select_database` 默认选中——每次调用显式传
  `instance_id`，省略时仅在恰好一个活跃实例时隐式路由，多实例并存时省略即报错
  （多 agent 并发不会互相改道）。无头 worker 随最后一个使用者关闭（默认先保存）。
- **官方 IDAPython 文档**：`ida_python_reference(query)` 基于当前 IDA 运行时构建
  BM25 索引（约 2 万条 API 签名 + 文档字符串），版本永远匹配。
- **worker 进程内零第三方依赖**：桥为纯标准库实现。
- **调试器无头可用**：`dbg_start` 自动加载本机调试器（linux/win32/macos，可传
  `debugger="gdb"` 走远程），IDA 9 删除官方调用栈 API 后由帧指针链自动重建。

## 安装

前置：IDA Pro 9.0+（含 idalib）。推荐 HCLI 一条龙（无需手填任何路径）：

```bash
hcli ida install --download-id ida-pro:latest --set-default --accept-eula --yes
```

### 1. 配置无头 worker 解释器（可选——运行时也会自动探测）

```bash
python scripts/hcli_install.py        # 探测能 import idapro 的解释器（通常即
                                      # IDA 自带 ida-python 运行时）并缓存 ida_python
```

### 2. 独立 MCP 服务器

```bash
# 无需克隆，直接从 GitHub 运行（也可换成任意 ref / 本地路径）：
uvx idamcp-hub stdio
# 指定仓库/分支（未发布新版时）：
uvx --from git+https://github.com/Captain-AI-Hub/IDA-MCP idamcp-hub stdio
# 或从源码：
python -m ida_mcp stdio
```

PyPI 包名 **`idamcp-hub`**，已发布，`uvx idamcp-hub stdio` 即开即用。

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


## CLI

```bash
idamcp-hub                  # = idamcp-hub stdio
idamcp-hub instances list       # 列出活跃 worker 实例
idamcp-hub open <path>          # 无头打开（自动创建/分析 .i64）
idamcp-hub close [--id ID] [--terminate]
idamcp-hub save [--id ID]
idamcp-hub tool call <name> --params '{"addr":"main"}'
idamcp-hub reference "decompile function" [--module ida_funcs]
idamcp-hub config show
```

## 配置

`ida_mcp/config.conf`（包内）与 `~/.idapro/ida-mcp/config.conf`（用户级，优先生效），
仅 3 个键：`ida_python`（能 `import idapro` 的解释器，通常为 IDA 自带
ida-python 运行时；留空则按 用户配置 → IDA 安装目录自带 → 托管 venv 探测并
缓存）、`request_timeout`、`debug`。`scripts/hcli_install.py` 可一次性写入；
日常无需手工配置。实例桥固定 `127.0.0.1:13337+`，无需配置。
环境变量覆盖：`IDA_MCP_CONFIG_<KEY>`。

## 工具面

- 生命周期：`open_database`、`list_databases`、
  `save_database`、`close_database`、`check_connection`
- 文档：`ida_python_reference(query, module=None)`
- 后端目录（90 个，每个都可带 `instance_id` 指定目标实例；多实例并存时必传）：
  反编译/反汇编/xref/搜索/重命名/注释/patch/类型/结构体/栈帧/内存/`py_eval`/`dbg_*`
  等全量开放，见 [API.md](API.md)。

## 运行时边界

- IDA 运行时：所有 SDK 调用经 worker 主线程队列串行执行（idalib 单线程约束）。
- 独立进程：任何 Python ≥3.11；fastmcp 4.x；不接触 IDA SDK。
- 测试：`pytest`——无可用 IDA/idalib 时后端测试自动跳过；本机有 idalib 时会
  无头启动 `test/samples/complex.exe` 实例实测（`--ida-open-timeout` 可调）。

## 布局

```text
IDA-MCP/
├── ida_mcp/
│   ├── bridge_server.py   # worker 内 JSON-RPC 桥（纯标准库）
│   ├── worker.py          # 无头 idalib worker 进程
│   ├── mcp_server.py      # 独立 stdio MCP 服务器
│   ├── instances.py       # 共享 JSON 实例清单
│   ├── lifecycle.py       # open/close/save/attach 生命周期
│   ├── bridge_client.py   # 桥 HTTP 客户端
│   ├── idapython_docs.py  # 官方 IDAPython 文档索引（BM25）
│   ├── api_*.py           # 工具目录（反汇编/反编译/修改/调试…）
│   └── sync.py / rpc.py   # 工具注册与调用标记
├── scripts/hcli_install.py  # idalib 解释器探测/配置
├── test/               # pytest 套件（单元 + 无头真机含调试器）
└── API.md / project.md / roadmap.md
```
