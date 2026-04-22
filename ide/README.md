# IDE

`ide/` 是 IDA-MCP 的 PySide6 桌面 IDE。

它不是 Web 前端，也不是 IDA 插件；它是独立分发的桌面工作台，负责：

- 安装、配置、启动、停止、检查 `ida_mcp`
- Gateway 生命周期管理与健康监控
- 文件工作区（目录树 + hex/text/image 预览）
- 设置页（中英双语，Config / Install / Upgrade）
- 状态监控面板

## 运行

```bash
python launcher.py
```

## 核心分层

| 层 | 目录 | 职责 |
|---|---|---|
| UI | `app/ui/` | PySide6 页面与控件 |
| 展示层 | `app/presenters/` | 数据映射（model ↔ form state） |
| 服务层 | `app/services/` | 业务服务（supervisor 封装、设置、文件预览） |
| 控制面 | `supervisor/` | Gateway 控制、安装、配置、环境探测 |
| 共享 | `shared/` | 路径工具、ida_mcp config 读写 |
| 资源 | `resources/ida_mcp/` | 受管 ida_mcp 源码（安装时复制到 IDA plugins/） |
| 测试 | `tests/` | pytest |

## 边界约束

- `ide/` 不在代码层面 import `ida_mcp` 的任何模块（无法在非 IDA Python 中运行）
- `ida_mcp` 作为受管资源打包在 `resources/` 中
- IDE 通过 subprocess 调用 `command.py` 启动 gateway
- 安装探测只扫描 IDA 全局 plugins 目录，不扫描 resources 目录
- 所有路径通过 `shared/paths.py` 管理，支持开发态和 Nuitka 打包态

## 打包

Nuitka 打包脚本在 `build_helpers/build_nuitka.py`。打包时 `resources/` 目录会被包含在分发物中。
