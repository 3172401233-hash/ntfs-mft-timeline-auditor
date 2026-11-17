"""FILE record 底层解析：fixup、属性头、runlist。

所有属性长度与 run 偏移都做边界检查；任何越界都会抛出
AttributeBoundsError / RunlistError，或在记录级降级为 errors 条目。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

SECTOR_SIZE = 512
DEFAULT_RECORD_SIZE = 1024

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_END = 0xFFFFFFFF

ATTR_FLAG_COMPRESSED = 0x0001
ATTR_FLAG_ENCRYPTED = 0x4000
ATTR_FLAG_SPARSE = 0x8000

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class MftError(Exception):
    """解析器错误基类。"""


class BadFixupError(MftError):
    """fixup 校验失败：扇区尾部与更新序列号不一致。"""


class TruncatedRecordError(MftError):
    """镜像截断导致记录不完整。"""


class AttributeBoundsError(MftError):
    """属性长度或偏移越界。"""


class RunlistError(MftError):
    """data run 解码失败（偏移越界或 LCN 非法）。"""


def filetime_to_datetime(value: int) -> Optional[datetime]:
    """FILETIME (100ns since 1601-01-01 UTC) 转 datetime；0 视为未设置。"""
    if value == 0:
        return None
    try:
        return _EPOCH + timedelta(microseconds=value / 10)
    except OverflowError:
        return None


def apply_fixup(raw: bytes, record_size: int = DEFAULT_RECORD_SIZE,
                sector_size: int = SECTOR_SIZE) -> bytes:
    """校验并应用 update sequence fixup，返回修正后的记录字节。

    每个扇区最后 2 字节必须等于更新序列号，否则抛 BadFixupError。
    """
    if len(raw) < record_size:
        raise TruncatedRecordError(
            f"record truncated: {len(raw)} of {record_size} bytes")
    if len(raw) < 0x08:
        raise TruncatedRecordError("record too short for fixup header")
    usa_offset, usa_count = struct.unpack_from("<HH", raw, 0x04)
    sectors = record_size // sector_size
    if usa_count != sectors + 1:
        raise BadFixupError(
            f"fixup count {usa_count} != sectors+1 {sectors + 1}")
    if usa_offset + usa_count * 2 > record_size:
        raise BadFixupError("fixup array extends past end of record")
    usn = struct.unpack_from("<H", raw, usa_offset)[0]
    data = bytearray(raw[:record_size])
    for i in range(sectors):
        tail = (i + 1) * sector_size - 2
        if struct.unpack_from("<H", data, tail)[0] != usn:
            raise BadFixupError(
                f"sector {i} tail mismatch (offset {tail:#x})")
        data[tail:tail + 2] = raw[usa_offset + 2 + i * 2:
                                  usa_offset + 4 + i * 2]
    return bytes(data)


def decode_runlist(buf: bytes, offset: int, end: int) -> List["Run"]:
    """解码 data run 列表。offset size 为 0 的 run 是稀疏 run。

    所有读取都限制在 [offset, end) 内，越界抛 RunlistError。
    """
    if not (0 <= offset <= end <= len(buf)):
        raise RunlistError("runlist offset out of bounds")
    runs: List[Run] = []
    lcn = 0
    pos = offset
    while pos < end:
        header = buf[pos]
        pos += 1
        if header == 0:
            break
        len_size = header & 0x0F
        off_size = (header >> 4) & 0x0F
        if len_size == 0 or len_size > 8 or off_size > 8:
            raise RunlistError(
                f"invalid runlist header {header:#x} at {pos - 1:#x}")
        if pos + len_size + off_size > end:
            raise RunlistError("runlist entry extends past run data")
        length = int.from_bytes(buf[pos:pos + len_size], "little")
        pos += len_size
        if length == 0:
            raise RunlistError("run with zero cluster length")
        if off_size == 0:
            runs.append(Run(length=length, lcn=None, sparse=True))
            continue
        delta = int.from_bytes(buf[pos:pos + off_size], "little")
        if buf[pos + off_size - 1] & 0x80:
            delta -= 1 << (8 * off_size)
        pos += off_size
        lcn += delta
        if lcn < 0:
            raise RunlistError(f"negative LCN {lcn}")
        runs.append(Run(length=length, lcn=lcn, sparse=False))
    return runs


@dataclass
class Run:
    length: int
    lcn: Optional[int]
    sparse: bool = False


@dataclass
class Attribute:
    type: int
    name: str
    non_resident: bool
    attr_id: int
    flags: int
    value: bytes = b""
    runlist: List[Run] = field(default_factory=list)
    start_vcn: int = 0
    last_vcn: int = 0
    real_size: int = 0
    allocated_size: int = 0

    @property
    def sparse(self) -> bool:
        return bool(self.flags & ATTR_FLAG_SPARSE)


class FileRecord:
    """单条 FILE record 的解析结果。"""

    def __init__(self, data: bytes, record_number: int):
        self.record_number = record_number
        self.errors: List[str] = []
        self.attributes: List[Attribute] = []
        if len(data) < 0x30:
            raise TruncatedRecordError("record shorter than FILE header")
        self.magic = data[0:4]
        if self.magic not in (b"FILE", b"BAAD"):
            raise MftError(f"bad magic {self.magic!r}")
        (self.sequence, self.link_count, first_attr, self.flags,
         self.used_size, self.allocated_size) = struct.unpack_from(
            "<HHHHII", data, 0x10)
        self.base_record_ref = struct.unpack_from("<Q", data, 0x20)[0]
        self._parse_attributes(data, first_attr)

    @property
    def in_use(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def is_directory(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def is_extension(self) -> bool:
        return self.base_record_ref != 0

    @property
    def base_record_number(self) -> int:
        return self.base_record_ref & 0x0000FFFFFFFFFFFF

    def _parse_attributes(self, data: bytes, first_offset: int) -> None:
        limit = min(len(data), max(self.used_size, first_offset))
        offset = first_offset
        while offset + 16 <= limit:
            attr_type, attr_len = struct.unpack_from("<II", data, offset)
            if attr_type == ATTR_END:
                break
            if attr_len < 16:
                self.errors.append(
                    f"attribute at {offset:#x} has invalid length {attr_len}")
                break
            if offset + attr_len > limit:
                self.errors.append(
                    f"attribute type {attr_type:#x} at {offset:#x} "
                    f"length {attr_len} exceeds record bounds")
                break
            try:
                self.attributes.append(
                    self._parse_attribute(data, offset, attr_len))
            except (AttributeBoundsError, RunlistError) as exc:
                self.errors.append(
                    f"attribute type {attr_type:#x} at {offset:#x}: {exc}")
            offset += attr_len

    def _parse_attribute(self, data: bytes, offset: int,
                         attr_len: int) -> Attribute:
        (attr_type, _length, non_resident, name_len, name_off,
         flags, attr_id) = struct.unpack_from("<IIBBBHH", data, offset)
        if name_len:
            name_end = offset + name_off + name_len * 2
            if name_off < 16 or name_end > offset + attr_len:
                raise AttributeBoundsError("attribute name out of bounds")
            name = data[offset + name_off:name_end].decode(
                "utf-16-le", errors="replace")
        else:
            name = ""
        attr = Attribute(type=attr_type, name=name,
                         non_resident=bool(non_resident), attr_id=attr_id,
                         flags=flags)
        if not non_resident:
            if attr_len < 0x18:
                raise AttributeBoundsError("resident attribute header too short")
            value_len, value_off = struct.unpack_from("<IH", data, offset + 0x10)
            if value_off < 0x18 or value_off + value_len > attr_len:
                raise AttributeBoundsError(
                    f"resident value [{value_off}, +{value_len}) "
                    f"outside attribute length {attr_len}")
            attr.value = data[offset + value_off:
                              offset + value_off + value_len]
            attr.real_size = value_len
        else:
            if attr_len < 0x40:
                raise AttributeBoundsError(
                    "non-resident attribute header too short")
            (attr.start_vcn, attr.last_vcn) = struct.unpack_from(
                "<QQ", data, offset + 0x10)
            run_off = struct.unpack_from("<H", data, offset + 0x20)[0]
            (attr.allocated_size, attr.real_size) = struct.unpack_from(
                "<QQ", data, offset + 0x28)
            if run_off < 0x40 or run_off > attr_len:
                raise AttributeBoundsError(
                    f"runlist offset {run_off} outside attribute length "
                    f"{attr_len}")
            attr.runlist = decode_runlist(data, offset + run_off,
                                          offset + attr_len)
        return attr

    def find(self, attr_type: int) -> List[Attribute]:
        return [a for a in self.attributes if a.type == attr_type]
