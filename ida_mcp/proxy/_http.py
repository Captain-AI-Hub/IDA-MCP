"""HTTP 辅助函数 - 与协调器通信。"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Any

# 添加父目录以导入配置模块
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

# 从配置文件加载，若失败则使用默认值
try:
    from config import get_coordinator_url, get_request_timeout
    COORD_URL = get_coordinator_url()
    REQUEST_TIMEOUT = get_request_timeout()
except Exception:
    COORD_URL = "http://127.0.0.1:11337"
    REQUEST_TIMEOUT = 30


def http_get(path: str) -> Any:
    """GET 请求到协调器。"""
    try:
        with urllib.request.urlopen(COORD_URL + path, timeout=REQUEST_TIMEOUT) as r:
            return json.loads(r.read().decode('utf-8') or 'null')
    except Exception:
        return None


def http_post(path: str, obj: dict, timeout: int | None = None) -> Any:
    """POST 请求到协调器。"""
    data = json.dumps(obj).encode('utf-8')
    req = urllib.request.Request(
        COORD_URL + path,
        data=data,
        method='POST',
        headers={'Content-Type': 'application/json'}
    )
    effective_timeout = timeout if timeout and timeout > 0 else REQUEST_TIMEOUT
    try:
        with urllib.request.urlopen(req, timeout=effective_timeout) as r:
            return json.loads(r.read().decode('utf-8') or 'null')
    except Exception as e:
        return {"error": str(e)}
