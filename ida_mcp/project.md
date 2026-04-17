# ida-mcp Project Map

## 子项目定位

`ida_mcp/` 是仓库的核心能力层。

它负责：

- IDA 插件接入
- MCP / HTTP gateway / proxy
- 多实例状态与生命周期
- 分析、修改、建模、资源与控制能力

它不负责 Web 产品层工作流。

---

## 目录树

```text
ida_mcp/
├── __init__.py
├── config.py                   # 配置加载
├── config.conf                 # 默认配置
├── compat.py                   # IDA 兼容层
├── sync.py                     # IDA 主线程同步
├── utils.py                    # 通用工具函数
├── rpc.py                      # tool/resource/unsafe 注册约定
├── server_factory.py           # IDA 内 FastMCP server 组装
├── registry.py                 # gateway 启动、状态探测、注册管理
├── registry_server.py          # gateway HTTP/internal server
├── runtime.py                  # 运行时辅助
├── control.py                  # CLI/脚本友好控制层
├── errors.py                   # 错误定义
├── strings_cache.py            # 字符串缓存辅助
├── api_core.py                 # 元数据、函数、字符串、导入导出
├── api_analysis.py             # 反编译、反汇编、xrefs、搜索
├── api_memory.py               # 字节、内存、标量、字符串
├── api_types.py                # 类型、结构体、枚举、typedef
├── api_modify.py               # 注释、重命名、补丁
├── api_modeling.py             # 创建/删除函数与代码/数据建模
├── api_stack.py                # 栈帧与局部变量
├── api_debug.py                # 调试相关 unsafe 能力
├── api_python.py               # Python 执行 unsafe 能力
├── api_lifecycle.py            # 关闭 IDA 等生命周期能力
├── api_resources.py            # ida:// 资源端点
├── proxy/
│   ├── register_tools.py       # proxy 侧注册与包装工具
│   ├── lifecycle.py            # open_in_ida / close / staging / bridge
│   ├── _http.py                # HTTP 请求辅助
│   ├── _state.py               # 实例选择与状态
│   ├── _server.py              # 共享 proxy server
│   ├── http_server.py          # HTTP transport 入口
│   └── ida_mcp_proxy.py        # stdio proxy 入口
├── roadmap.md                  # 子项目规划
└── project.md                  # 子项目结构地图
```

---

## 模块地图

### 配置与基础设施

- `config.py`：统一读取 transport、端口、路径、超时等配置
- `compat.py`：适配不同 IDA 版本行为差异
- `sync.py`：确保关键操作在 IDA 正确线程执行
- `utils.py`：分页、过滤、解析等通用逻辑
- `rpc.py`：定义 tool/resource/unsafe 的注册方式

### 服务组装层

- `server_factory.py`：将 `api_*` 能力注册到实例内 MCP server

### 生命周期与实例控制层

- `registry.py`：负责 gateway 进程与内部 API 调用包装
- `registry_server.py`：维护实例表、健康状态、调用转发、shutdown
- `runtime.py`：运行时启动辅助
- `control.py`：给 CLI/脚本提供稳定控制接口

### 业务能力层

- `api_core.py`：浏览性元数据
- `api_analysis.py`：分析能力
- `api_memory.py`：内存与字节读取
- `api_types.py`：类型系统能力
- `api_modify.py`：修改能力
- `api_modeling.py`：建模能力
- `api_stack.py`：栈与局部变量能力
- `api_debug.py`：调试相关高风险能力
- `api_python.py`：Python 执行高风险能力
- `api_lifecycle.py`：实例关闭等生命周期能力
- `api_resources.py`：资源浏览入口

### Proxy 层

- `proxy/register_tools.py`：将后端能力映射到 proxy
- `proxy/lifecycle.py`：处理 `open_in_ida` 与路径桥接等复杂流程
- `proxy/_state.py`：实例状态、选择、路由策略
- `proxy/_http.py`：对 gateway/internal 的 HTTP 请求封装
- `proxy/_server.py`：共享 server
- `proxy/http_server.py`：HTTP 形式暴露 proxy
- `proxy/ida_mcp_proxy.py`：stdio 形式暴露 proxy

---

## 关键调用链

### 1. IDA 插件启动链

`ida_mcp.py` -> `server_factory.py` -> `registry.py` / `registry_server.py`

### 2. CLI 调用链

`command.py` -> `control.py` -> `registry.py` / `proxy/lifecycle.py` / gateway

### 3. Tool 转发链

调用方 -> gateway `/internal/call` -> 目标 IDA 实例 `/mcp/`

### 4. 资源读取链

调用方 -> `control.py` -> 目标实例资源接口

---

## 与 Web 子项目的边界

`ida_mcp/` 对 `ide/` 提供的是能力，不是产品状态。

Web 子项目可以依赖：

- gateway 健康状态
- 实例列表与状态
- `open_in_ida` / close / shutdown
- tool call
- resource read/list

Web 子项目不应把以下内容塞回 `ida_mcp/`：

- workspace / SQLite 持久化
- chat / thread / message
- audit run / audit plan
- artifact / checkpoint / report

---

## 后续开发放置规则

### 该放在 `ida_mcp/` 的

- IDA 新能力
- tool / resource 新接口
- gateway / proxy / lifecycle 改进
- CLI / control 能力增强
- transport / health / registry 稳定性改进

### 不该放在 `ida_mcp/` 的

- Web UI 交互状态
- 审计流程编排逻辑
- 工作目录级数据库模型
- 多 Agent 会话与计划管理

---

## 一句话总结

`ida_mcp/` 是稳定、可复用、可测试的底层逆向能力层；任何面向产品工作台的状态与编排逻辑，都应放在 `ide/` 子项目中。
