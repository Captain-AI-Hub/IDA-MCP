"""RPC 装饰器和工具注册表。

提供:
    @tool          - 注册 MCP 工具
    @resource      - 注册 MCP Resource URI
    @unsafe        - 标记为不安全操作 (需要 --unsafe 启用)
    get_tools()    - 获取所有已注册工具
    get_resources() - 获取所有已注册资源
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, Optional, get_type_hints

# 全局注册表
_tools: Dict[str, Callable] = {}
_resources: Dict[str, Callable] = {}


def tool(fn: Callable) -> Callable:
    """注册 MCP 工具，自动提取类型注解和文档字符串。
    
    用法:
        @tool
        @idaread
        def my_function(param: Annotated[str, "description"]) -> dict:
            '''Tool description (first line used in MCP schema)'''
            ...
    """
    _tools[fn.__name__] = fn
    return fn


def resource(uri: str):
    """注册 MCP Resource URI 模式。
    
    用法:
        @resource(uri="ida://functions/{pattern}")
        @idaread
        def functions_resource(pattern: str = "*") -> list:
            '''Resource description'''
            ...
    """
    def decorator(fn: Callable) -> Callable:
        fn._resource_uri = uri  # type: ignore
        _resources[uri] = fn
        return fn
    return decorator


def unsafe(fn: Callable) -> Callable:
    """标记为不安全操作 (需要 --unsafe 启用)。
    
    用法:
        @unsafe
        @tool
        @idawrite
        def dangerous_operation():
            ...
    """
    fn._unsafe = True  # type: ignore
    return fn


def get_tools() -> Dict[str, Callable]:
    """获取所有已注册的工具函数。"""
    return dict(_tools)


def get_resources() -> Dict[str, Callable]:
    """获取所有已注册的资源函数。"""
    return dict(_resources)


def get_tool_info(fn: Callable) -> dict:
    """提取工具函数的元信息 (用于生成 MCP schema)。
    
    返回:
        {
            name: 函数名,
            description: 文档字符串首行,
            parameters: 参数信息列表,
            is_unsafe: 是否标记为 unsafe,
        }
    """
    doc = inspect.getdoc(fn) or ""
    description = doc.split('\n')[0] if doc else fn.__name__
    
    # 提取参数信息
    sig = inspect.signature(fn)
    params = []
    
    try:
        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}
    
    for param_name, param in sig.parameters.items():
        param_info: dict[str, Any] = {"name": param_name}
        
        # 获取类型
        if param_name in hints:
            hint = hints[param_name]
            # 处理 Annotated 类型
            if hasattr(hint, '__metadata__'):
                param_info["type"] = str(hint.__origin__) if hasattr(hint, '__origin__') else str(hint)
                # 提取描述 (Annotated 的 metadata)
                for meta in hint.__metadata__:
                    if isinstance(meta, str):
                        param_info["description"] = meta
                    elif hasattr(meta, 'description'):
                        param_info["description"] = meta.description
            else:
                param_info["type"] = str(hint)
        
        # 默认值
        if param.default is not inspect.Parameter.empty:
            param_info["default"] = param.default
            param_info["required"] = False
        else:
            param_info["required"] = True
        
        params.append(param_info)
    
    return {
        "name": fn.__name__,
        "description": description,
        "parameters": params,
        "is_unsafe": is_unsafe(fn),
    }


def is_unsafe(fn: Callable) -> bool:
    """检查函数是否标记为 unsafe。"""
    module_name = getattr(fn, "__module__", "")
    return bool(getattr(fn, '_unsafe', False) or module_name.endswith(".api_debug"))


def clear_registry():
    """清空注册表 (用于测试)。"""
    _tools.clear()
    _resources.clear()

