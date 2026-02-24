"""IDA-MCP 包初始化模块。

职责概述
====================
* 对外导出 `create_mcp_server` 供插件入口 (`ida_mcp.py`) 创建 FastMCP 服务。
* 自动发现并注册所有 api_*.py 模块中的工具。
* 提供装饰器和辅助函数的统一导出。

模块结构 (重构后)
====================
基础设施:
    * `rpc.py`       : @tool/@resource/@unsafe 装饰器 + 注册表
    * `sync.py`      : @idaread/@idawrite IDA 线程同步装饰器
    * `utils.py`     : 地址解析、分页、模式过滤等辅助函数

API 模块:
    * `api_core.py`      : IDB 元数据、函数/字符串/全局变量列表
    * `api_analysis.py`  : 反编译、反汇编、交叉引用
    * `api_memory.py`    : 内存读取
    * `api_types.py`     : 类型操作
    * `api_modify.py`    : 注释、重命名
    * `api_stack.py`     : 栈帧操作
    * `api_debug.py`     : 调试器控制
    * `api_resources.py` : MCP Resources (ida:// URI)

保留模块:
    * `registry.py`  : 多实例协调器 (端口 11337)
    * `proxy/`       : 代理转发

"""
from __future__ import annotations

import os
from typing import Optional

__version__ = "0.2.0"

# 从配置文件加载默认端口，若失败则使用默认值
try:
    from .config import get_ida_default_port
    DEFAULT_PORT = get_ida_default_port()
except Exception:
    DEFAULT_PORT = 10000  # 选择 10000 以避开 Windows Hyper-V 保留端口范围

# 导出装饰器
from .rpc import tool, resource, unsafe, get_tools, get_resources, is_unsafe
from .sync import idaread, idawrite

# 导出工具函数
from .utils import (
    parse_address,
    normalize_list_input,
    paginate,
    pattern_filter,
    is_valid_c_identifier,
)

# 导入所有 API 模块 (触发装饰器注册)
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python
from . import api_resources

# 导入协调器模块
from . import registry

def create_mcp_server(
    name: Optional[str] = None,
    enable_unsafe: bool = True,  # 默认启用调试器工具 (与原行为一致)
) -> "FastMCP": # type: ignore
    """创建配置好的 FastMCP 服务器实例。
    
    参数:
        name: 服务器名称 (默认从环境变量 IDA_MCP_NAME 或 "IDA-MCP")
        enable_unsafe: 是否启用 unsafe 工具 (调试器控制等)，默认 True
    
    返回:
        配置好所有工具的 FastMCP 实例
    """
    from fastmcp import FastMCP
    
    if name is None:
        name = os.getenv("IDA_MCP_NAME", "IDA-MCP")
    
    mcp = FastMCP(
        name=name,
        instructions="通过 MCP 工具访问 IDA 反汇编/分析数据。支持批量操作和 ida:// URI 资源访问。"
    )
    
    # 注册所有工具
    tools = get_tools()
    
    for fn_name, fn in tools.items():
        # 检查是否为 unsafe 工具
        if is_unsafe(fn) and not enable_unsafe:
            continue
        
        # 获取工具描述
        doc = fn.__doc__ or fn_name
        description = doc.split('\n')[0].strip() if doc else fn_name
        
        # 获取原始函数 (解开装饰器)
        original_fn = fn
        while hasattr(original_fn, '__wrapped__'):
            original_fn = original_fn.__wrapped__
        
        # 使用 FastMCP 的装饰器注册
        # 直接注册包装后的函数，保持参数签名
        mcp.tool(description=description)(fn)
    
    # 注册所有资源
    resources = get_resources()
    for uri, fn in resources.items():
        doc = fn.__doc__ or uri
        description = doc.split('\n')[0].strip() if doc else uri
        
        try:
            mcp.resource(uri)(fn)
        except Exception:
            # 某些 FastMCP 版本可能不支持 resource
            pass
    
    return mcp
