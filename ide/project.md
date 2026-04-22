# IDE Project Map

## 定位

`ide/` 是基于 PySide6 的桌面 IDE，负责：

- `ida_mcp` 安装、配置、启动、停止和状态检查
- Gateway 生命周期管理
- 文件工作区与预览
- 设置页面（中英双语）
- 健康检查与环境探测

## 真实目录树

```text
ide/
├── launcher.py               # IDE 启动入口
├── app/
│   ├── i18n.py               # 中英双语翻译
│   ├── services/
│   │   ├── supervisor_client.py  # 调用 SupervisorManager
│   │   ├── settings_service.py   # 设置读写
│   │   └── file_preview_service.py  # 文件类型判定与预览路由
│   ├── presenters/
│   │   ├── main_window_presenter.py  # 主窗口数据映射
│   │   └── settings_presenter.py    # 设置页数据映射
│   └── ui/
│       ├── main_window.py    # 主窗口（sidebar + 堆叠页面）
│       ├── settings/
│       │   └── page.py       # 设置页（Config / Install / Upgrade）
│       ├── workspace/
│       │   ├── directory_tree.py  # 文件树 + Open Folder
│       │   ├── hex_view.py        # 十六进制查看器
│       │   ├── code_view.py       # 文本编辑器 + Markdown 预览
│       │   └── image_view.py      # 图片查看器
│       ├── theme.py          # 主题与样式
│       └── chat/             # 聊天面板（占位）
├── supervisor/
│   ├── models.py             # IdeConfig / IdaMcpConfig / GatewayStatus 等
│   ├── manager.py            # 统一管理器（配置 + gateway + 健康）
│   ├── gateway_controller.py # Gateway 启停与状态探测
│   ├── install_runner.py     # 安装执行器（从 resources 复制文件 + pip install）
│   ├── installer.py          # 环境探测（IDA/Python 发现）
│   ├── config_store.py       # IDE 配置持久化
│   ├── health.py             # 健康报告聚合
│   └── main.py               # CLI 入口
├── shared/
│   ├── paths.py              # 路径辅助（project root / resources / user config）
│   ├── ida_mcp_config.py     # ida_mcp config.conf 读写
│   └── runtime.py            # 运行时辅助
├── resources/
│   └── ida_mcp/              # 受管资源（安装到 IDA plugins/）
│       ├── ida_mcp.py
│       ├── ida_mcp/          # 完整 ida_mcp 包
│       └── requirements.txt
├── build_helpers/
│   └── build_nuitka.py       # Nuitka 打包
└── tests/                    # pytest 测试
```

## 活跃主链

```
MainWindow → SupervisorClient → SupervisorManager → GatewayController
                                                   → EnvironmentInstaller
                                                   → IdeConfigStore
                                                   → IdaMcpConfigStore
```

设置页面：
```
SettingsPage → SettingsService → SupervisorClient → SupervisorManager
             → SettingsPresenter (数据映射)
```

文件预览：
```
DirectoryTreeWidget → file_preview_service.classify_file() → {Hex/Code/Image}View
```

## 模块职责

### `supervisor/` — 后台控制面

| 文件 | 职责 |
|------|------|
| `models.py` | IdeConfig / IdaMcpConfig / GatewayStatus / SupervisorSnapshot 等 dataclass |
| `manager.py` | 统一调度：配置读写、gateway 启停、健康报告、安装 |
| `gateway_controller.py` | TCP 探测 / HTTP healthz / command.py subprocess 启动 gateway |
| `install_runner.py` | 从 resources/ida_mcp 复制文件到 plugins/ + pip install |
| `installer.py` | 环境探测：IDA 路径、Python 路径、已安装插件检测 |
| `config_store.py` | IDE 配置 JSON 持久化 |
| `health.py` | 聚合 supervisor/gateway/environment 健康报告 |

### `app/` — UI 层

| 文件 | 职责 |
|------|------|
| `ui/main_window.py` | 主窗口：sidebar + 4 页堆叠（Chat / FS / Settings / Status） |
| `ui/settings/page.py` | 设置页：Config / Install / Upgrade 三个分类 |
| `ui/workspace/` | 文件树 + hex/code/image 预览 |
| `presenters/` | 数据映射层（model ↔ form state） |
| `services/` | 业务服务（supervisor 封装、设置、文件预览路由） |
| `i18n.py` | 中英双语翻译字典 |

### `shared/` — 共享工具

| 文件 | 职责 |
|------|------|
| `paths.py` | 项目根 / resources 根 / 用户配置目录 / Nuitka 输出目录 |
| `ida_mcp_config.py` | 读写 ida_mcp config.conf（保留注释、逐行解析） |

## 与 ida_mcp 的边界

- `ide/` 不在代码层面 `import ida_mcp` 的任何模块
- `ida_mcp` 作为受管资源打包在 `ide/resources/ida_mcp/` 中
- 安装时由 `install_runner.py` 将资源复制到 IDA plugins 目录
- 启动 gateway 时通过 `command.py`（subprocess）调用 ida_mcp 的功能
- `installer.py` 的探测逻辑只扫描 IDA 全局 plugins 目录，不扫描 resources 目录
