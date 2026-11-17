# ntfs-mft-timeline-auditor

Python NTFS `$MFT` 时间线审计库：解析 FILE record、fixup、属性与 data run，
按 **(记录号, 序列号)** 构建实体与链接关系，输出带来源标注的事件时间线。

## 特性

- FILE record 解析与 update sequence fixup 校验（坏 fixup 记录隔离，不污染整体扫描）
- 属性解析：`$STANDARD_INFORMATION`、`$FILE_NAME`、`$DATA`（常驻/非常驻）、`$INDEX_ROOT`
- data run 解码：多段 extent、稀疏 run（offset size = 0）、负 delta 的 LCN 回绕
- 已删除记录（in-use 标志清除）照常解析并在时间线中标注
- 记录号复用：实体以 `(record_number, sequence)` 为键，父引用按序列号精确匹配、缺失时降级
- ADS：命名 `$DATA` 流单独成流；硬链接：多个 `$FILE_NAME` 各自生成时间线事件
- 多链文件：扩展记录（base record reference ≠ 0）的属性合并回基本实体
- 截断镜像：尾部不足一条记录时记录 `truncated` 标志并继续
- 边界检查：所有属性长度、resident value 区间、runlist 偏移均校验，越界降级为实体级 error
- 时间戳修正（timestomp）差异检测

## 用法

```python
from mftaudit import MftImage, build_timeline, detect_timestamp_anomalies, timeline_to_csv

with open("MFT.raw", "rb") as f:
    image = MftImage(f.read())

for entity in image:                      # 按 (记录号, 序列号) 排序迭代
    print(entity.record_number, entity.sequence, entity.deleted,
          [fn.name for fn in entity.file_names],
          [s.name for s in entity.ads_streams])

events = build_timeline(image)            # 按时间排序的事件列表
print(timeline_to_csv(events))            # CSV 输出

for a in detect_timestamp_anomalies(image):
    print(a.path, a.kind, a.detail)
```

## 时间戳的证据含义

NTFS 中同一文件有多组时间戳，来源不同、可伪造性不同，证据权重也不同：

| 来源 | 字段 | 含义 | 证据要点 |
| --- | --- | --- | --- |
| `$STANDARD_INFORMATION` | created | 文件创建时间 | 用户态 `SetFileTime` 可任意改写，单独不可信 |
| `$STANDARD_INFORMATION` | modified | 内容最后修改 | 同上；timestomp 工具主要改的就是 SI 四组时间 |
| `$STANDARD_INFORMATION` | mft_changed | MFT 记录本身最后变更 | 用户态无法直接设置；晚于 modified 属正常，**早于** modified 则时间线不自洽 |
| `$STANDARD_INFORMATION` | accessed | 最后访问 | 现代 Windows 默认禁用更新，常停留在旧值，证明力弱 |
| `$FILE_NAME` | created / modified / mft_changed / accessed | 内核在文件名操作时维护 | 无公开用户态 API 可改；**SI 明显早于 FN 是 timestomp 的典型痕迹**（`si_before_fn`） |
| `$INDEX_ROOT`（目录索引） | 同上四组 | 父目录索引项中冗余的 FN 副本 | 文件被改名/删除后索引项可能残留，可恢复已删文件的名字与时间 |

检测规则（`detect_timestamp_anomalies`）：

- `si_before_fn`：SI.created / SI.modified 比对应 FN 时间早超过阈值（默认 1s）——
  改时间工具通常只重写 SI，FN 仍保留真实值。
- `mft_changed_before_modified`：记录变更时间早于内容修改时间，时间线不自洽。

## 实体与链接模型

- **实体键**：`(record_number, sequence)`。记录号被复用时序列号递增，
  旧版本实体不会被错误聚合；父引用中的序列号用于精确匹配，匹配不到时
  降级到同记录号的最新版本并在路径中标注 `<?>`。
- **硬链接**：一个实体的多个 `$FILE_NAME` 各自指向可能不同的父目录，
  时间线为每个名字单独生成事件，避免按文件名聚合把不同实体混在一起。
- **ADS**：`$DATA` 的 `name` 非空即为备用数据流，主 unnamed 流与 ADS 分开列出。
- **多链文件**：属性放不下的文件使用扩展记录，解析时按 base record
  reference 把扩展记录的流/文件名/索引项合并回基本实体。

## 测试

```bash
python -m unittest
```

覆盖：fixup 往返与坏 fixup、多 run + 稀疏 run、删除记录、记录号复用、
ADS、硬链接、扩展记录链、目录索引、截断镜像、属性/runlist 越界、
timestomp 检测与时间线排序。
