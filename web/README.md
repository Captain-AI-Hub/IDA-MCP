# Web Workspace

该目录承载 IDA-MCP 的 Web 层实现，不直接替代现有 `ida_mcp/`。

## 目标

- `frontend/`：浏览器 UI，默认采用 Next.js
- `backend/`：编排与 API 层，默认采用 FastAPI + LangGraph + DeepAgents

## 运行分层

```text
Browser -> frontend -> backend -> ida-mcp -> IDA instance
```

## 默认端口

- Frontend: `http://127.0.0.1:3000`
- Backend: `http://127.0.0.1:8000`
- IDA-MCP: `http://127.0.0.1:11338`

## 当前状态

目前仅完成基础目录初始化；下一步将分别补齐：

- FastAPI app 入口
- Next.js app 入口
- gateway 状态页
- A2A 审计任务 MVP
