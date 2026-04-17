# ida-mcp Roadmap

## 子项目定位

`ida_mcp/` 是仓库的核心能力层，负责把 IDA 的分析、修改、建模、资源读取与生命周期能力，以稳定的 MCP / HTTP / control 方式暴露出来。

它不是 Web 产品层，不负责：

- 工作目录与 SQLite 持久化
- 多 Agent 群编排
- 聊天、计划进度、文件查看器等前端产品逻辑

这些能力应位于 `ide/` 子项目中。

---

## 核心职责

### 1. IDA 插件接入

- 在 IDA 内启动 per-instance MCP server
- 注册到 gateway
- 维护 heartbeat、shutdown 与资源释放

### 2. Gateway / Registry / Proxy

- 管理多实例注册、状态与选择
- 提供 HTTP internal API 与 MCP proxy
- 支持 `open_in_ida`、关闭实例、网关控制

### 3. 分析与修改能力

- 元数据、函数、字符串、导入导出
- 反编译、反汇编、xrefs、搜索
- 类型、结构体、枚举、栈帧、局部变量
- 注释、重命名、补丁、建模

### 4. 资源层

- 暴露 `ida://` 资源
- 为上层系统提供稳定只读浏览能力

### 5. CLI 与测试支撑

- `command.py` 与 `control.py` 提供脚本与手工操作入口
- `test/` 保证多 transport、多模块行为稳定

---

## 当前基线

当前已具备：

- 稳定的 IDA 实例内 FastMCP 组装
- gateway / registry / proxy 基础能力
- 大部分常用逆向分析与修改 API
- lifecycle 与 `open_in_ida`
- 资源访问与 CLI 包装

当前仍需要持续打磨：

- 错误模型统一
- 多实例状态与异常恢复边界
- 资源/工具契约稳定性
- 文档与测试覆盖深度
- 与 `ide/` 子项目的边界稳定性

---

## 目标方向

### A. 稳定核心契约

目标：让 `ida_mcp` 成为可长期复用的底层能力层。

工作项：

- 稳定 `/internal` 与 control 层语义
- 明确 tool/resource 返回结构与错误结构
- 降低 Web / CLI / agent 调用方对内部实现细节的感知

### B. 提高多实例可靠性

目标：在一个 gateway 下更稳定地管理多个 IDA 实例。

工作项：

- 改善实例状态判定与心跳鲁棒性
- 完善 unresponsive / quarantined / closed 行为定义
- 完善并发调用与超时控制

### C. 强化资源层与只读浏览能力

目标：为上层 Web 工作台提供更稳的浏览入口。

工作项：

- 完善 `ida://` 资源覆盖面
- 统一分页、过滤、错误与大对象响应约定
- 区分浏览优先与修改优先接口

### D. 强化 unsafe 边界

目标：让高风险能力更清晰、更可控。

工作项：

- 明确 `py_eval`、`dbg_*`、修改类接口的风险分级
- 强化文档标注
- 为上层调用方保留策略控制点

### E. 提高可测试性

目标：保证核心层迭代不破坏行为契约。

工作项：

- 增补 gateway / proxy / lifecycle / resource 测试
- 提高分析与修改接口的回归覆盖
- 明确 transport 维度测试矩阵

---

## 阶段规划

## P0：核心层边界与契约收敛

- 整理 `ida_mcp/` 子项目文档
- 固化 control、gateway、resource、tool 边界
- 清理与 Web 产品层耦合的表述

## P1：可靠性与错误处理增强

- 统一错误结构
- 强化实例状态与调用锁语义
- 提高 lifecycle 与 shutdown 稳定性

## P2：资源层与只读浏览优化

- 扩展 `ida://` 资源覆盖
- 改善分页、过滤和大型响应处理
- 为上层浏览场景提供更稳契约

## P3：测试与文档完善

- 增补 gateway / proxy / lifecycle / resources 测试
- 提高 README / API / 子项目文档一致性
- 为 `ide/` 与第三方调用方补齐对接说明

---

## 明确不做的方向

- 不在 `ida_mcp/` 中实现 Web 工作台产品状态
- 不在核心层直接承载聊天、计划、workspace 持久化
- 不让 `ida_mcp/` 反向依赖 `ide/`
- 不把 Agent 编排逻辑塞进 IDA 插件或 gateway 内部

---

## 近期执行顺序

1. 固化 `ida_mcp/project.md` 与 `ida_mcp/roadmap.md`
2. 梳理 control / gateway / resource / tool 契约
3. 增补错误处理与可靠性文档
4. 为 Web 子项目预留稳定集成接口
