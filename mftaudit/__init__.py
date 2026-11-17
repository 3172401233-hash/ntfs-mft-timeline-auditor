"""NTFS $MFT 记录解析与时间线审计库。

按 (记录号, 序列号) 构建实体，区分记录号复用；支持删除记录、
ADS、硬链接、稀疏 run、截断镜像和时间戳修正差异检测。
"""

from .record import (
    SECTOR_SIZE,
    DEFAULT_RECORD_SIZE,
    MftError,
    BadFixupError,
    TruncatedRecordError,
    AttributeBoundsError,
    RunlistError,
    Run,
    Attribute,
    FileRecord,
    apply_fixup,
    decode_runlist,
    filetime_to_datetime,
)
from .model import (
    FileNameInfo,
    DataStream,
    IndexEntry,
    Entity,
    MftImage,
)
from .timeline import (
    TimelineEvent,
    TimestampAnomaly,
    build_timeline,
    detect_timestamp_anomalies,
    timeline_to_csv,
)

__all__ = [
    "SECTOR_SIZE",
    "DEFAULT_RECORD_SIZE",
    "MftError",
    "BadFixupError",
    "TruncatedRecordError",
    "AttributeBoundsError",
    "RunlistError",
    "Run",
    "Attribute",
    "FileRecord",
    "apply_fixup",
    "decode_runlist",
    "filetime_to_datetime",
    "FileNameInfo",
    "DataStream",
    "IndexEntry",
    "Entity",
    "MftImage",
    "TimelineEvent",
    "TimestampAnomaly",
    "build_timeline",
    "detect_timestamp_anomalies",
    "timeline_to_csv",
]
