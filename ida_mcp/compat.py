"""IDA 版本兼容层。

处理 IDA 8.x 和 IDA 9.x 之间的 API 差异。
IDA 9.x 移除了 ida_struct 模块，结构体操作改用 ida_typeinf。
"""
from __future__ import annotations

from typing import Optional, Any

try:
    import idaapi  # type: ignore
except ImportError:
    idaapi = None

# 检测 IDA 版本
if idaapi:
    IDA_VERSION = idaapi.IDA_SDK_VERSION if hasattr(idaapi, 'IDA_SDK_VERSION') else 0
else:
    IDA_VERSION = 0
IDA9_OR_LATER = IDA_VERSION >= 900

# 尝试导入 ida_struct (IDA 8.x)
try:
    import ida_struct as _ida_struct  # type: ignore
    HAS_IDA_STRUCT = True
except ImportError:
    _ida_struct = None
    HAS_IDA_STRUCT = False

try:
    import ida_typeinf  # type: ignore
except ImportError:
    ida_typeinf = None

try:
    import idc  # type: ignore
except ImportError:
    idc = None


# ============================================================================
# 结构体 ID 和获取
# ============================================================================

def get_struc_id(name: str) -> int:
    """获取结构体 ID。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_struc_id(name)  # type: ignore
    # IDA 9.x: 使用 idc
    return idc.get_struc_id(name)


def get_struc(sid: int) -> Any:
    """获取结构体对象。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_struc(sid)  # type: ignore
    # IDA 9.x: 返回 sid 本身作为标识
    if sid == idaapi.BADADDR:
        return None
    return sid


def get_struc_size(s: Any) -> int:
    """获取结构体大小。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_struc_size(s)  # type: ignore
    # IDA 9.x: s 是 sid
    if s is None:
        return 0
    result = idc.get_struc_size(s)
    return result if isinstance(result, int) else 0


# ============================================================================
# 成员操作
# ============================================================================

def get_member(s: Any, offset: int) -> Any:
    """获取指定偏移的成员。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member(s, offset)  # type: ignore
    # IDA 9.x: 使用 idc
    if s is None:
        return None
    mid = idc.get_member_id(s, offset)
    if mid == idaapi.BADADDR or mid == -1:
        return None
    # 返回一个简单的成员对象
    return _MemberCompat(s, offset, mid)


def get_member_by_name(s: Any, name: str) -> Any:
    """按名称获取成员。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_by_name(s, name)  # type: ignore
    # IDA 9.x: 遍历查找
    if s is None:
        return None
    size = get_struc_size(s)
    offset = 0
    while offset < size:
        mid = idc.get_member_id(s, offset)
        if mid != idaapi.BADADDR and mid != -1:
            mname = idc.get_member_name(s, offset)
            if mname == name:
                return _MemberCompat(s, offset, mid)
            msize = idc.get_member_size(s, offset)
            if msize > 0:
                offset += msize
            else:
                offset += 1
        else:
            offset += 1
    return None


def get_first_member(s: Any) -> Any:
    """获取第一个成员。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_first_member(s)  # type: ignore
    # IDA 9.x
    if s is None:
        return None
    return get_member(s, 0)


def get_next_member(s: Any, offset: int) -> Any:
    """获取下一个成员。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_next_member(s, offset)  # type: ignore
    # IDA 9.x
    if s is None:
        return None
    size = get_struc_size(s)
    # 跳过当前成员
    msize = idc.get_member_size(s, offset)
    next_off = offset + (msize if msize > 0 else 1)
    while next_off < size:
        mid = idc.get_member_id(s, next_off)
        if mid != idaapi.BADADDR and mid != -1:
            return _MemberCompat(s, next_off, mid)
        next_off += 1
    return None


def get_member_name(mid_or_member: Any) -> Optional[str]:
    """获取成员名称。"""
    if HAS_IDA_STRUCT:
        if isinstance(mid_or_member, int):
            return _ida_struct.get_member_name(mid_or_member)  # type: ignore
        return _ida_struct.get_member_name(mid_or_member.id)  # type: ignore
    # IDA 9.x
    if isinstance(mid_or_member, _MemberCompat):
        return idc.get_member_name(mid_or_member.sid, mid_or_member.offset)
    return None


def get_member_id(m: Any) -> int:
    """获取成员 ID。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_id(m)  # type: ignore
    # IDA 9.x
    if isinstance(m, _MemberCompat):
        return m.mid
    return idaapi.BADADDR


def get_member_size(m: Any) -> int:
    """获取成员大小。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_size(m)  # type: ignore
    # IDA 9.x
    if isinstance(m, _MemberCompat):
        return idc.get_member_size(m.sid, m.offset)
    return 0


def get_member_offset(m: Any) -> int:
    """获取成员偏移。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_offset(m)  # type: ignore
    # IDA 9.x
    if isinstance(m, _MemberCompat):
        return m.offset
    return 0


def get_member_tinfo(tif: Any, m: Any) -> bool:
    """获取成员类型信息。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_tinfo(tif, m)  # type: ignore
    # IDA 9.x: 使用 ida_typeinf
    if isinstance(m, _MemberCompat):
        try:
            # IDA 9.x 中结构体成员类型需要通过 ida_typeinf 获取
            sptr = ida_typeinf.get_idati().get_numbered_type(m.sid)
            if sptr:
                udt = ida_typeinf.udt_type_data_t()
                if sptr.get_udt_details(udt):
                    for udm in udt:
                        if udm.offset // 8 == m.offset:
                            tif.copy_from(udm.type)
                            return True
            return False
        except Exception:
            return False
    return False


# ============================================================================
# 成员添加/删除
# ============================================================================

def add_struc_member(
    s: Any,
    name: str,
    offset: int,
    flag: int,
    typeid: Any,
    size: int
) -> int:
    """添加结构体成员。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.add_struc_member(s, name, offset, flag, typeid, size)  # type: ignore
    # IDA 9.x: 使用 idc
    if s is None:
        return -1
    result = idc.add_struc_member(s, name, offset, flag, typeid, size)
    return result if isinstance(result, int) else -1


def del_struc_member(s: Any, offset: int) -> bool:
    """删除结构体成员。"""
    if HAS_IDA_STRUCT:
        return _ida_struct.del_struc_member(s, offset)  # type: ignore
    # IDA 9.x: 使用 idc
    if s is None:
        return False
    return bool(idc.del_struc_member(s, offset))


# ============================================================================
# 兼容类
# ============================================================================

class _MemberCompat:
    """IDA 9.x 成员兼容对象。"""
    
    def __init__(self, sid: int, offset: int, mid: int):
        self.sid = sid
        self.offset = offset
        self.mid = mid
        self.id = mid
        self.soff = offset
    
    def __bool__(self) -> bool:
        return self.mid != idaapi.BADADDR and self.mid != -1

