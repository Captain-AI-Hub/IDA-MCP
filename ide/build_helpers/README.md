# Build Helpers

本目录管理 Sarma IDE 的 **Nuitka** 打包流程。

## 前置条件

1. **Python 3.12** 虚拟环境（`ide/.venv/`）
2. **依赖安装**：`pip install -r requirements.txt`（含 `nuitka==4.0.8`、`zstandard`）
3. **MSVC Build Tools**：安装 [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)，勾选"使用 C++ 的桌面开发"

## 使用方式

### PowerShell（推荐）

```powershell
cd ide

# standalone 模式（开发调试用）
.\build_helpers\build_windows.ps1 standalone

# onefile 模式（单文件发布）
.\build_helpers\build_windows.ps1 onefile

# 附加参数：去除调试信息、指定编译线程数
.\build_helpers\build_windows.ps1 standalone --no-debug -j 4
```

### 直接调用 Python

```powershell
cd ide

# 预览命令（不执行）
.venv\Scripts\python build_helpers\build_nuitka.py --print-only

# standalone 构建
.venv\Scripts\python build_helpers\build_nuitka.py --mode standalone

# onefile 构建
.venv\Scripts\python build_helpers\build_nuitka.py --mode onefile

# 去除调试信息
.venv\Scripts\python build_helpers\build_nuitka.py --mode standalone --no-debug
```

## 输出位置

所有构建产物输出到 `ide/build/nuitka/`：

| 模式 | 产物 |
|------|------|
| standalone | `launcher.dist/` 目录，含 `launcher.exe` 及所有依赖 DLL |
| onefile | 单个 `launcher.exe` |

## 构建参数说明

| 参数 | 说明 |
|------|------|
| `--enable-plugin=pyside6` | 自动处理 PySide6 Qt 插件和平台依赖 |
| `--msvc=latest` | 使用最新 MSVC 编译器 |
| `--windows-console-mode=disable` | 不弹出控制台窗口 |
| `--include-package=app/shared/supervisor/bootstrap` | 四个核心包 |
| `--include-data-dir=resources` | 打包 `ida_mcp` 受管资源 |
| `--windows-icon-from-ico` | 应用图标（优先 `.ico`，回退 `.png`） |
| `--nofollow-import-to=...` | 排除 langchain/numpy 等未使用的传递依赖 |

## 推荐流程

1. **standalone 先行** → 运行 `launcher.dist/launcher.exe` 验证功能
2. **排查问题** → `--print-only` 查看完整命令，检查是否缺少模块/资源
3. **确认无误 → onefile** → 生成最终单文件可执行体

## 约束

- 打包后不依赖仓库源码树运行
- 不依赖动态模块发现
- 资源路径必须通过 `shared.paths` / `shared.runtime` 获取
- `ida_mcp` 作为 data-dir 资源打包，运行时不 import
