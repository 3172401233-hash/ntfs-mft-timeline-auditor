"""实体模型：按 (记录号, 序列号) 聚合实体与链接关系。

- 记录号复用：同一记录号不同序列号是不同的实体版本。
- 硬链接：同一实体的多个 $FILE_NAME 属性。
- ADS：同一实体的多个命名 $DATA 流。
- 目录索引：$INDEX_ROOT / $INDEX_ALLOCATION 中的子项引用。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterator, List, Optional, Tuple

from .record import (
    ATTR_DATA,
    ATTR_FILE_NAME,
    ATTR_INDEX_ALLOCATION,
    ATTR_INDEX_ROOT,
    ATTR_STANDARD_INFORMATION,
    DEFAULT_RECORD_SIZE,
    Attribute,
    FileRecord,
    MftError,
    TruncatedRecordError,
    apply_fixup,
    filetime_to_datetime,
)

NAMESPACE_NAMES = {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32+DOS"}


@dataclass
class SiTimestamps:
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    mft_changed: Optional[datetime] = None
    accessed: Optional[datetime] = None


@dataclass
class FileNameInfo:
    parent_record: int
    parent_sequence: int
    name: str
    namespace: int
    timestamps: SiTimestamps
    real_size: int
    flags: int

    @property
    def namespace_name(self) -> str:
        return NAMESPACE_NAMES.get(self.namespace, f"unknown({self.namespace})")


@dataclass
class DataStream:
    name: str
    resident: bool
    size: int
    runs: list = field(default_factory=list)
    data: bytes = b""
    sparse: bool = False

    @property
    def is_ads(self) -> bool:
        return bool(self.name)


@dataclass
class IndexEntry:
    child_record: int
    child_sequence: int
    name: str
    timestamps: SiTimestamps
    real_size: int
    flags: int
    has_subnode: bool = False


@dataclass
class Entity:
    """一个 MFT 实体版本：(record_number, sequence) 唯一标识。"""

    record_number: int
    sequence: int
    in_use: bool
    is_directory: bool
    link_count: int
    si: SiTimestamps = field(default_factory=SiTimestamps)
    file_names: List[FileNameInfo] = field(default_factory=list)
    streams: List[DataStream] = field(default_factory=list)
    index_entries: List[IndexEntry] = field(default_factory=list)
    base_record: int = 0
    is_extension: bool = False
    extensions: List[int] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def deleted(self) -> bool:
        return not self.in_use

    @property
    def hard_link_count(self) -> int:
        return len(self.file_names)

    @property
    def primary_name(self) -> Optional[FileNameInfo]:
        for fn in self.file_names:
            if fn.namespace in (1, 3):
                return fn
        return self.file_names[0] if self.file_names else None

    @property
    def ads_streams(self) -> List[DataStream]:
        return [s for s in self.streams if s.is_ads]


def _parse_si(value: bytes) -> SiTimestamps:
    if len(value) < 0x20:
        return SiTimestamps()
    created, modified, mft_changed, accessed = struct.unpack_from(
        "<QQQQ", value, 0)
    return SiTimestamps(
        created=filetime_to_datetime(created),
        modified=filetime_to_datetime(modified),
        mft_changed=filetime_to_datetime(mft_changed),
        accessed=filetime_to_datetime(accessed),
    )


def _parse_file_name(value: bytes) -> Optional[FileNameInfo]:
    if len(value) < 0x42:
        return None
    parent_ref = struct.unpack_from("<Q", value, 0)[0]
    created, modified, mft_changed, accessed = struct.unpack_from(
        "<QQQQ", value, 0x08)
    real_size = struct.unpack_from("<Q", value, 0x30)[0]
    flags = struct.unpack_from("<I", value, 0x38)[0]
    name_len = value[0x40]
    namespace = value[0x41]
    if 0x42 + name_len * 2 > len(value):
        return None
    name = value[0x42:0x42 + name_len * 2].decode(
        "utf-16-le", errors="replace")
    return FileNameInfo(
        parent_record=parent_ref & 0x0000FFFFFFFFFFFF,
        parent_sequence=(parent_ref >> 48) & 0xFFFF,
        name=name,
        namespace=namespace,
        timestamps=SiTimestamps(
            created=filetime_to_datetime(created),
            modified=filetime_to_datetime(modified),
            mft_changed=filetime_to_datetime(mft_changed),
            accessed=filetime_to_datetime(accessed),
        ),
        real_size=real_size,
        flags=flags,
    )


def _parse_index_root(value: bytes) -> List[IndexEntry]:
    """解析 $INDEX_ROOT 内的索引项（目录下为 FILE_NAME 结构）。"""
    entries: List[IndexEntry] = []
    if len(value) < 0x20:
        return entries
    entries_offset = struct.unpack_from("<I", value, 0x10)[0]
    pos = 0x10 + entries_offset
    while pos + 0x10 <= len(value):
        child_ref, entry_size, stream_size, flags = struct.unpack_from(
            "<QHHI", value, pos)
        if entry_size < 0x10 or pos + entry_size > len(value):
            break
        if flags & 0x02:  # last entry
            break
        stream = value[pos + 0x10:pos + 0x10 + stream_size]
        fn = _parse_file_name(stream)
        if fn is not None:
            entries.append(IndexEntry(
                child_record=child_ref & 0x0000FFFFFFFFFFFF,
                child_sequence=(child_ref >> 48) & 0xFFFF,
                name=fn.name,
                timestamps=fn.timestamps,
                real_size=fn.real_size,
                flags=fn.flags,
                has_subnode=bool(flags & 0x01),
            ))
        pos += entry_size
    return entries


def _entity_from_record(record: FileRecord) -> Entity:
    entity = Entity(
        record_number=record.record_number,
        sequence=record.sequence,
        in_use=record.in_use,
        is_directory=record.is_directory,
        link_count=record.link_count,
        base_record=record.base_record_number,
        is_extension=record.is_extension,
        errors=list(record.errors),
    )
    for attr in record.attributes:
        if attr.type == ATTR_STANDARD_INFORMATION and not attr.non_resident:
            entity.si = _parse_si(attr.value)
        elif attr.type == ATTR_FILE_NAME and not attr.non_resident:
            fn = _parse_file_name(attr.value)
            if fn is not None:
                entity.file_names.append(fn)
            else:
                entity.errors.append("malformed $FILE_NAME value")
        elif attr.type == ATTR_DATA:
            entity.streams.append(DataStream(
                name=attr.name,
                resident=not attr.non_resident,
                size=attr.real_size,
                runs=list(attr.runlist),
                data=attr.value if not attr.non_resident else b"",
                sparse=attr.sparse or any(r.sparse for r in attr.runlist),
            ))
        elif attr.type == ATTR_INDEX_ROOT and not attr.non_resident:
            entity.index_entries.extend(_parse_index_root(attr.value))
        elif attr.type == ATTR_INDEX_ALLOCATION:
            entity.errors.append(
                "$INDEX_ALLOCATION present; subnodes not materialized")
    return entity


class MftImage:
    """$MFT 镜像：扫描记录、构建实体、解析父子与硬链接关系。"""

    def __init__(self, data: bytes, record_size: int = DEFAULT_RECORD_SIZE):
        self.record_size = record_size
        self.entities: Dict[Tuple[int, int], Entity] = {}
        self.versions: Dict[int, List[Entity]] = {}
        self.scan_errors: List[str] = []
        self.truncated = False
        self._scan(data)
        self._link_extensions()

    def _scan(self, data: bytes) -> None:
        total = len(data) // self.record_size
        if len(data) % self.record_size:
            self.truncated = True
            self.scan_errors.append(
                f"image truncated: {len(data) % self.record_size} trailing "
                f"bytes after record {total}")
        for number in range(total):
            raw = data[number * self.record_size:
                       (number + 1) * self.record_size]
            if raw[:4] not in (b"FILE", b"BAAD"):
                continue
            try:
                fixed = apply_fixup(raw, self.record_size)
            except MftError as exc:
                self.scan_errors.append(f"record {number}: {exc}")
                continue
            try:
                record = FileRecord(fixed, number)
            except TruncatedRecordError as exc:
                self.scan_errors.append(f"record {number}: {exc}")
                continue
            entity = _entity_from_record(record)
            key = (entity.record_number, entity.sequence)
            self.entities[key] = entity
            self.versions.setdefault(number, []).append(entity)

    def _link_extensions(self) -> None:
        """把扩展记录（base_record_ref != 0）合并进基本记录实体。

        多链文件的属性分散在多条记录中：扩展记录的流、文件名和
        索引项并入基本实体，基本实体记录扩展记录号。
        """
        for entity in list(self.entities.values()):
            if not entity.is_extension:
                continue
            base = self.get(entity.base_record)
            if base is None or base is entity:
                self.scan_errors.append(
                    f"record {entity.record_number}: extension without base "
                    f"record {entity.base_record}")
                continue
            base.extensions.append(entity.record_number)
            base.streams.extend(entity.streams)
            base.file_names.extend(entity.file_names)
            base.index_entries.extend(entity.index_entries)
            base.errors.extend(
                f"ext {entity.record_number}: {e}" for e in entity.errors)

    def get(self, record_number: int,
            sequence: Optional[int] = None) -> Optional[Entity]:
        if sequence is not None:
            return self.entities.get((record_number, sequence))
        versions = self.versions.get(record_number, [])
        return versions[-1] if versions else None

    def __iter__(self) -> Iterator[Entity]:
        for key in sorted(self.entities):
            yield self.entities[key]

    def parent_of(self, entity: Entity) -> Optional[Entity]:
        fn = entity.primary_name
        if fn is None:
            return None
        return self.get(fn.parent_record, fn.parent_sequence) or \
            self.get(fn.parent_record)

    def children_of(self, entity: Entity) -> List[Entity]:
        result = []
        for other in self.entities.values():
            fn = other.primary_name
            if fn and fn.parent_record == entity.record_number:
                result.append(other)
        return result

    def path_of(self, entity: Entity, name: Optional[FileNameInfo] = None,
                _depth: int = 0) -> str:
        """尽力解析完整路径；父记录缺失或复用时标注 <?>。"""
        if _depth > 64:
            return "<?>"
        fn = name or entity.primary_name
        if fn is None:
            return f"<unnamed:{entity.record_number}>"
        parent = self.get(fn.parent_record, fn.parent_sequence) or \
            self.get(fn.parent_record)
        if parent is None or parent is entity:
            return fn.name
        parent_path = self.path_of(parent, _depth=_depth + 1)
        return parent_path.rstrip("\\") + "\\" + fn.name
