"""内存 API - 内存读取操作。

提供工具:
    - get_bytes          读取原始字节
    - get_u8/u16/u32/u64 读取整数
    - get_string         读取字符串
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, normalize_list_input, hex_addr

# IDA 模块导入
try:
    import idaapi  # type: ignore
    import ida_bytes  # type: ignore
    import ida_name  # type: ignore
    import ida_kernwin  # type: ignore
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_name = None
    ida_kernwin = None


# ============================================================================
# 字节读取
# ============================================================================

@tool
@idaread
def get_bytes(
    addr: Annotated[Union[int, str], "Address(es) to read from - single or comma-separated"],
    size: Annotated[int, "Number of bytes to read (1..4096)"] = 16,
) -> List[dict]:
    """Read raw bytes at address(es)."""
    if size <= 0:
        return [{"error": "size must be > 0"}]
    if size > 4096:
        return [{"error": "size too large (max 4096)"}]
    
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        parsed = parse_address(query)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "query": query})
            continue
        
        address = parsed["value"]
        try:
            data = idaapi.get_bytes(address, size)
            if data is None:
                results.append({"error": "failed to read", "query": query, "address": hex_addr(address)})
                continue
            
            byte_list = list(data)
            hex_str = ' '.join(f'{b:02X}' for b in byte_list)
            
            results.append({
                "query": query,
                "address": hex_addr(address),
                "size": len(byte_list),
                "bytes": byte_list,
                "hex": hex_str,
                "error": None,
            })
        except Exception as e:
            results.append({"error": str(e), "query": query, "address": hex_addr(address)})
    
    return results


# ============================================================================
# 整数读取
# ============================================================================

@tool
@idaread
def get_u8(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
) -> List[dict]:
    """Read 8-bit unsigned integer(s)."""
    return _read_int(addr, 1, signed=False)


@tool
@idaread
def get_u16(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
) -> List[dict]:
    """Read 16-bit unsigned integer(s)."""
    return _read_int(addr, 2, signed=False)


@tool
@idaread
def get_u32(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
) -> List[dict]:
    """Read 32-bit unsigned integer(s)."""
    return _read_int(addr, 4, signed=False)


@tool
@idaread
def get_u64(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
) -> List[dict]:
    """Read 64-bit unsigned integer(s)."""
    return _read_int(addr, 8, signed=False)


def _read_int(addr: Union[int, str], size: int, signed: bool = False) -> List[dict]:
    """内部: 读取整数。"""
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        parsed = parse_address(query)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "query": query})
            continue
        
        address = parsed["value"]
        try:
            data = idaapi.get_bytes(address, size)
            if data is None:
                results.append({"error": "failed to read", "query": query, "address": hex_addr(address)})
                continue
            
            endian = 'little'
            try:
                inf = idaapi.get_inf_structure()
                if hasattr(inf, 'is_be') and inf.is_be():
                    endian = 'big'
            except Exception:
                pass
            value = int.from_bytes(data, byteorder=endian, signed=signed)
            
            results.append({
                "query": query,
                "address": hex_addr(address),
                "value": value,
                "hex": f"0x{value:0{size*2}X}",
                "error": None,
            })
        except Exception as e:
            results.append({"error": str(e), "query": query, "address": hex_addr(address)})
    
    return results


# ============================================================================
# 字符串读取
# ============================================================================

@tool
@idaread
def get_string(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
    max_len: Annotated[int, "Maximum string length"] = 256,
) -> List[dict]:
    """Read null-terminated string(s)."""
    if max_len <= 0:
        return [{"error": "max_len must be > 0"}]
    if max_len > 4096:
        max_len = 4096
    
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        parsed = parse_address(query)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "query": query})
            continue
        
        address = parsed["value"]
        try:
            # 读取字节直到 null
            data = idaapi.get_bytes(address, max_len)
            if data is None:
                results.append({"error": "failed to read", "query": query, "address": hex_addr(address)})
                continue
            
            # 查找 null 终止符
            null_pos = data.find(b'\x00')
            if null_pos >= 0:
                data = data[:null_pos]
            
            # 尝试解码
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text = data.decode('latin-1')
                except Exception:
                    text = data.hex()
            
            results.append({
                "query": query,
                "address": hex_addr(address),
                "length": len(data),
                "text": text,
                "error": None,
            })
        except Exception as e:
            results.append({"error": str(e), "query": query, "address": hex_addr(address)})
    
    return results

