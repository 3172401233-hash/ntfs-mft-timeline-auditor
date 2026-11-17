"""事件时间线与时间戳修正差异检测。

每个事件标注来源属性（$STANDARD_INFORMATION / $FILE_NAME / $INDEX_ROOT），
因为不同来源的证据含义不同（见 README）。
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional

from .model import Entity, MftImage, SiTimestamps

EVENT_FIELDS = ("created", "modified", "mft_changed", "accessed")

_SI_LABELS = {
    "created": "文件创建",
    "modified": "内容修改",
    "mft_changed": "MFT 记录变更",
    "accessed": "最后访问",
}


@dataclass
class TimelineEvent:
    timestamp: datetime
    record_number: int
    sequence: int
    path: str
    source: str
    event: str
    deleted: bool
    description: str


@dataclass
class TimestampAnomaly:
    record_number: int
    sequence: int
    path: str
    kind: str
    detail: str


def _events_from_si(entity: Entity, path: str,
                    si: SiTimestamps, source: str) -> List[TimelineEvent]:
    events = []
    for field_name in EVENT_FIELDS:
        ts = getattr(si, field_name)
        if ts is None:
            continue
        events.append(TimelineEvent(
            timestamp=ts,
            record_number=entity.record_number,
            sequence=entity.sequence,
            path=path,
            source=source,
            event=field_name,
            deleted=entity.deleted,
            description=f"{source} {_SI_LABELS[field_name]}",
        ))
    return events


def build_timeline(image: MftImage,
                   entities: Optional[Iterable[Entity]] = None,
                   ) -> List[TimelineEvent]:
    """汇总所有实体的 SI / FN / 目录索引时间戳，按时间排序。"""
    events: List[TimelineEvent] = []
    for entity in (entities if entities is not None else image):
        path = image.path_of(entity)
        events.extend(_events_from_si(entity, path, entity.si,
                                      "$STANDARD_INFORMATION"))
        for fn in entity.file_names:
            fn_path = image.path_of(entity, fn)
            events.extend(_events_from_si(entity, fn_path, fn.timestamps,
                                          "$FILE_NAME"))
        if entity.is_directory:
            for entry in entity.index_entries:
                for field_name in EVENT_FIELDS:
                    ts = getattr(entry.timestamps, field_name)
                    if ts is None:
                        continue
                    events.append(TimelineEvent(
                        timestamp=ts,
                        record_number=entry.child_record,
                        sequence=entry.child_sequence,
                        path=path.rstrip("\\") + "\\" + entry.name,
                        source="$INDEX_ROOT",
                        event=field_name,
                        deleted=entity.deleted,
                        description=f"$INDEX_ROOT 索引项 {_SI_LABELS[field_name]}",
                    ))
    events.sort(key=lambda e: (e.timestamp, e.record_number, e.source))
    return events


def detect_timestamp_anomalies(image: MftImage,
                               tolerance_seconds: float = 1.0,
                               ) -> List[TimestampAnomaly]:
    """检测时间戳修正（timestomp）痕迹。

    $FILE_NAME 时间戳只能由内核更新，用户态难以伪造；
    $STANDARD_INFORMATION 可被 SetFileTime 任意改写。
    当 SI 时间明显早于 FN 时间时，是典型的改时间痕迹。
    """
    anomalies: List[TimestampAnomaly] = []
    for entity in image:
        fn = entity.primary_name
        if fn is None:
            continue
        path = image.path_of(entity)
        for field_name in ("created", "modified"):
            si_ts = getattr(entity.si, field_name)
            fn_ts = getattr(fn.timestamps, field_name)
            if si_ts is None or fn_ts is None:
                continue
            delta = (fn_ts - si_ts).total_seconds()
            if delta > tolerance_seconds:
                anomalies.append(TimestampAnomaly(
                    record_number=entity.record_number,
                    sequence=entity.sequence,
                    path=path,
                    kind="si_before_fn",
                    detail=(
                        f"$STANDARD_INFORMATION.{field_name} "
                        f"({si_ts.isoformat()}) 比 $FILE_NAME.{field_name} "
                        f"({fn_ts.isoformat()}) 早 {delta:.0f}s，"
                        f"疑似时间戳修正"),
                ))
        si = entity.si
        if (si.mft_changed and si.modified
                and si.mft_changed < si.modified):
            anomalies.append(TimestampAnomaly(
                record_number=entity.record_number,
                sequence=entity.sequence,
                path=path,
                kind="mft_changed_before_modified",
                detail="$MFT 记录变更时间早于内容修改时间，时间线不自洽",
            ))
    return anomalies


def timeline_to_csv(events: Iterable[TimelineEvent]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "record_number", "sequence", "path",
                     "source", "event", "deleted", "description"])
    for e in events:
        writer.writerow([e.timestamp.isoformat(), e.record_number,
                         e.sequence, e.path, e.source, e.event,
                         int(e.deleted), e.description])
    return buf.getvalue()
