# Backend

计划使用 `FastAPI + LangGraph + DeepAgents` 构建编排层。

建议职责：

- 作为浏览器与 `ida-mcp` 之间的中间层
- 提供 REST/SSE 接口
- 编排 A2A 自动审计流程
- 管理任务状态、事件流、报告产物

预留目录：

- `app/api/`：HTTP 接口
- `app/agents/`：LangGraph / DeepAgents 编排
- `app/services/`：对接 ida-mcp、存储、事件流
- `app/schemas/`：请求、响应、状态模型
- `tests/`：后端测试
