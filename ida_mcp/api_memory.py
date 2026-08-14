"""Memory API - memory read operations.

Provides tools:
    - get_bytes          read raw bytes
    - read_scalar        read scalar integers
    - get_string         read strings
"""
from __future__ import annotations

from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread
from .utils import parse_address, normalize_list_input, hex_addr

# IDA module imports
try:
    import ida_bytes  # type: ignore
    import ida_ida  # type: ignore
except ImportError:
    ida_bytes = None
    ida_ida = None


# ============================================================================
# Byte reading
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
    if ida_bytes is None:
        return [{"error": "ida_bytes unavailable"}]
    
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        parsed = parse_address(query)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "query": query})
            continue
        
        address = parsed["value"]
        try:
            data = ida_bytes.get_bytes(address, size)
            if data is None:
                results.append({"error": "failed to read", "query": query, "address": hex_addr(address)})
                continue
            
            byte_list = list(data)
            hex_str = ' '.join(f'{b:02X}' for b in byte_list)
            
            results.append({
                "address": hex_addr(address),
                "size": len(byte_list),
                "hex": hex_str,
            })
        except Exception as e:
            results.append({"error": str(e), "query": query, "address": hex_addr(address)})
    
    return results


# ============================================================================
# Scalar reading
# ============================================================================

@tool
@idaread
def read_scalar(
    addr: Annotated[Union[int, str], "Address(es) - single or comma-separated"],
    width: Annotated[int, "Scalar width in bytes: 1, 2, 4, or 8"] = 4,
    signed: Annotated[bool, "Whether to decode as signed integer"] = False,
) -> List[dict]:
    """Read scalar integer(s) with explicit width."""
    return _read_scalar(addr, width, signed=signed)


def _read_scalar(addr: Union[int, str], width: int, signed: bool = False) -> List[dict]:
    """Internal: read scalar integer."""
    if width not in (1, 2, 4, 8):
        return [{"error": "width must be one of 1, 2, 4, or 8", "width": width}]
    if ida_bytes is None:
        return [{"error": "ida_bytes unavailable"}]

    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        parsed = parse_address(query)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "query": query})
            continue
        
        address = parsed["value"]
        try:
            data = ida_bytes.get_bytes(address, width)
            if data is None:
                results.append({"error": "failed to read", "query": query, "address": hex_addr(address)})
                continue
            
            endian = 'little'
            try:
                if ida_ida is not None and ida_ida.inf_is_be():
                    endian = 'big'
            except Exception:
                pass
            unsigned_value = int.from_bytes(data, byteorder=endian, signed=False)
            value = int.from_bytes(data, byteorder=endian, signed=signed)
            
            results.append({
                "address": hex_addr(address),
                "value": value,
                "hex": f"0x{unsigned_value:0{width*2}X}",
            })
        except Exception as e:
            results.append({"error": str(e), "query": query, "address": hex_addr(address)})
    
    return results


# ============================================================================
# String reading
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
    if ida_bytes is None:
        return [{"error": "ida_bytes unavailable"}]
    
    queries = normalize_list_input(addr)
    results = []
    
    for query in queries:
        parsed = parse_address(query)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "query": query})
            continue
        
        address = parsed["value"]
        try:
            # read bytes until null terminator
            data = ida_bytes.get_bytes(address, max_len)
            if data is None:
                results.append({"error": "failed to read", "query": query, "address": hex_addr(address)})
                continue
            
            # find null terminator
            null_pos = data.find(b'\x00')
            if null_pos >= 0:
                data = data[:null_pos]
            
            # attempt decoding
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text = data.decode('latin-1')
                except Exception:
                    text = data.hex()
            
            results.append({
                "address": hex_addr(address),
                "length": len(data),
                "text": text,
            })
        except Exception as e:
            results.append({"error": str(e), "query": query, "address": hex_addr(address)})
    
    return results
