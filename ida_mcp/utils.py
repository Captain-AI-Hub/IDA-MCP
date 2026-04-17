"""通用辅助函数。

提供:
    parse_address()        - 统一地址解析
    hex_addr()             - 地址转十六进制字符串
    normalize_list_input() - 批量输入标准化
    paginate()             - 分页辅助
    pattern_filter()       - Glob 模式过滤
    is_valid_c_identifier() - C 标识符验证
"""

from __future__ import annotations

import re
import string
import fnmatch
from typing import Any, List, Dict, Optional, Tuple, Union, TypedDict


class ParseResult(TypedDict):
    """地址解析结果。"""

    ok: bool
    value: Optional[int]
    error: Optional[str]


class Page(TypedDict):
    """分页结果。"""

    total: int
    offset: int
    count: int
    items: List[Any]


def parse_address(value: Union[int, str]) -> ParseResult:
    """统一地址解析。

    支持格式:
        - 1234                (十进制)
        - 0x401000 / 0X401000 (十六进制前缀)
        - 401000h / 401000H   (结尾 h/H 十六进制)
        - 0x40_10_00          (下划线分隔)

    参数:
        value: 地址值 (int 或 str)

    返回:
        ParseResult: { ok, value, error }

    说明:
        - 不接受负值
        - 解析失败返回 ok=False
    """
    if isinstance(value, int):
        if value < 0:
            return {"ok": False, "value": None, "error": "invalid address"}
        return {"ok": True, "value": int(value), "error": None}

    if isinstance(value, str):
        txt = value.strip()
        if not txt:
            return {"ok": False, "value": None, "error": "invalid address"}

        txt = txt.replace("_", "")
        neg = False

        if txt.startswith(("+", "-")):
            if txt[0] == "-":
                neg = True
            txt = txt[1:]

        try:
            val: Optional[int] = None

            # trailing h 形式
            if txt.lower().endswith("h") and len(txt) > 1:
                core = txt[:-1]
                if all(c in string.hexdigits for c in core):
                    val = int(core, 16)
                else:
                    return {"ok": False, "value": None, "error": "invalid address"}
            else:
                # base=0 支持 0x / 0o / 0b
                val = int(txt, 0)

            if neg:
                val = -val  # type: ignore

            if val is None or val < 0:
                return {"ok": False, "value": None, "error": "invalid address"}

            return {"ok": True, "value": int(val), "error": None}
        except Exception:
            return {"ok": False, "value": None, "error": "invalid address"}

    return {"ok": False, "value": None, "error": "invalid address type"}


def hex_addr(addr: Union[int, str]) -> str:
    """将整数地址格式化为十六进制字符串。

    使用 0x 前缀，大写字母。

    参数:
        addr: 整数地址或已格式化的十六进制字符串

    返回:
        "0x401000" 格式的字符串
    """
    if isinstance(addr, str):
        return addr
    return f"0x{addr:X}"


def normalize_list_input(input_value: Union[int, str, List[Any]]) -> List[str]:
    """批量输入标准化。

    将逗号分隔的字符串、整数或列表转换为字符串列表。

    参数:
        input_value: "0x401000, main" 或 ["0x401000", "main"] 或 0x401000

    返回:
        ["0x401000", "main"]
    """
    if isinstance(input_value, str):
        return [s.strip() for s in input_value.split(",") if s.strip()]
    elif isinstance(input_value, list):
        return [str(item).strip() for item in input_value if item]
    else:
        return [str(input_value)]


def parse_addresses(
    input_value: Union[str, List[Any]],
) -> List[Tuple[str, ParseResult]]:
    """解析多个地址。

    参数:
        input_value: 地址列表或逗号分隔字符串

    返回:
        [(原始输入, ParseResult), ...]
    """
    items = normalize_list_input(input_value)
    return [(item, parse_address(item)) for item in items]


def paginate(
    items: List[Any], offset: int = 0, count: int = 100, max_count: int = 1000
) -> Page:
    """分页辅助。

    参数:
        items: 完整项目列表
        offset: 起始偏移 (>=0)
        count: 每页数量 (1..max_count)
        max_count: 允许的最大 count

    返回:
        Page: { total, offset, count, items }
    """
    total = len(items)

    # 参数校验
    offset = max(0, offset)
    count = max(1, min(count, max_count))

    # 切片
    slice_items = items[offset : offset + count]

    return {
        "total": total,
        "offset": offset,
        "count": len(slice_items),
        "items": slice_items,
    }


def pattern_filter(
    items: List[Dict[str, Any]],
    key: str,
    pattern: Optional[str],
    case_sensitive: bool = False,
) -> List[Dict[str, Any]]:
    """Glob 模式过滤。

    参数:
        items: 字典列表
        key: 用于匹配的键名
        pattern: Glob 模式 (如 "sub_*", "*main*")，None 或空表示不过滤
        case_sensitive: 是否区分大小写

    返回:
        过滤后的列表
    """
    if not pattern:
        return items

    if not case_sensitive:
        pattern = pattern.lower()

    result = []
    for item in items:
        value = item.get(key, "")
        if value is None:
            continue
        value_str = str(value)
        if not case_sensitive:
            value_str = value_str.lower()

        # 支持 glob 模式和子串匹配
        if fnmatch.fnmatch(value_str, pattern) or pattern in value_str:
            result.append(item)

    return result


def is_valid_c_identifier(name: str) -> bool:
    """验证是否为有效的 C 标识符。

    参数:
        name: 待验证的名称

    返回:
        True 如果是有效的 C 标识符
    """
    if not name:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name))


def truncate_string(s: str, max_len: int = 512, suffix: str = "...") -> str:
    """截断字符串。

    参数:
        s: 原始字符串
        max_len: 最大长度
        suffix: 截断后缀

    返回:
        截断后的字符串
    """
    if len(s) <= max_len:
        return s
    return s[: max_len - len(suffix)] + suffix


def format_hex(value: int, bits: int = 0) -> str:
    """格式化为十六进制字符串。

    参数:
        value: 数值
        bits: 位宽 (用于确定零填充宽度, 0=自动)

    返回:
        "0x..." 格式的字符串
    """
    if bits > 0:
        width = bits // 4
        return f"0x{value:0{width}X}"
    else:
        return f"0x{value:X}"


def safe_int(value: Any, default: int = 0) -> int:
    """安全转换为整数。

    参数:
        value: 待转换的值
        default: 转换失败时的默认值

    返回:
        整数值
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def normalize_arch(raw: Optional[str], bits: int) -> Optional[str]:
    """归一化架构名称。

    参数:
        raw: IDA 返回的原始架构名
        bits: 位宽 (32/64)

    返回:
        归一化后的架构名 (x86/x86_64/arm/arm64/...)
    """
    if not raw:
        return None

    r = raw.lower()

    # x86 family
    if r in ("pc", "metapc", "i386", "x86"):
        return "x86_64" if bits == 64 else "x86"
    if r in ("amd64", "x86_64", "x64"):
        return "x86_64"

    # ARM family
    if r in ("aarch64", "arm64") or r.startswith("arm64"):
        return "arm64"
    if r.startswith("arm"):
        return "arm"

    # MIPS
    if r in ("mips64", "mips64el"):
        return "mips64"
    if r.startswith("mips"):
        return "mips"

    # PowerPC
    if r in ("powerpc64", "ppc64") or r.startswith("ppc64"):
        return "ppc64"
    if r.startswith("ppc") or r.startswith("powerpc"):
        return "ppc"

    return raw
