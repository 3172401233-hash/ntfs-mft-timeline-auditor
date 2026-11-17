import struct
import unittest
from datetime import datetime, timezone

from mftaudit import (
    BadFixupError,
    MftImage,
    RunlistError,
    TruncatedRecordError,
    apply_fixup,
    build_timeline,
    decode_runlist,
    detect_timestamp_anomalies,
    timeline_to_csv,
)

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt):
    return int((dt - EPOCH).total_seconds() * 10_000_000)


T_BASE = datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def ts(day_offset=0):
    from datetime import timedelta
    return ft(T_BASE + timedelta(days=day_offset))


def si_value(c=0, m=1, mc=2, a=3):
    return struct.pack("<QQQQ", ts(c), ts(m), ts(mc), ts(a)) + b"\x00" * 0x28


def fn_value(parent_ref, name, namespace=1, c=0, m=1, mc=2, a=3,
             real_size=0, flags=0):
    name_b = name.encode("utf-16-le")
    return (
        struct.pack("<Q", parent_ref)
        + struct.pack("<QQQQ", ts(c), ts(m), ts(mc), ts(a))
        + struct.pack("<QQ", real_size, real_size)
        + struct.pack("<II", flags, 0)
        + struct.pack("<BB", len(name), namespace)
        + name_b
    )


def resident_attr(atype, value, name="", attr_id=0):
    name_b = name.encode("utf-16-le")
    name_off = 0x18 if name else 0
    value_off = 0x18 + len(name_b)
    total = value_off + len(value)
    pad = (-total) % 8
    buf = bytearray(total + pad)
    struct.pack_into("<IIBBBHH", buf, 0, atype, total + pad, 0,
                     len(name), name_off, 0, attr_id)
    struct.pack_into("<IH", buf, 0x10, len(value), value_off)
    if name:
        buf[name_off:name_off + len(name_b)] = name_b
    buf[value_off:value_off + len(value)] = value
    return bytes(buf)


def encode_runs(runs):
    """runs: [(length, delta)] 或 (length, None) 表示稀疏 run。"""
    out = bytearray()
    for length, delta in runs:
        len_b = length.to_bytes((length.bit_length() + 7) // 8 or 1, "little")
        if delta is None:
            out.append(len(len_b))
            out += len_b
        else:
            size = max(1, (delta.bit_length() + 8) // 8)
            off_b = delta.to_bytes(size, "little", signed=True)
            out.append((len(off_b) << 4) | len(len_b))
            out += len_b + off_b
    out.append(0)
    return bytes(out)


def nonresident_data(name, runs, real_size, attr_id=2, flags=0):
    runlist = encode_runs(runs)
    run_off = 0x40
    name_b = name.encode("utf-16-le")
    if name:
        run_off = 0x40 + len(name_b)
    total = run_off + len(runlist)
    pad = (-total) % 8
    buf = bytearray(total + pad)
    struct.pack_into("<IIBBBHH", buf, 0, 0x80, total + pad, 1,
                     len(name), 0x40 if name else 0, flags, attr_id)
    last_vcn = sum(l for l, _ in runs) - 1
    struct.pack_into("<QQ", buf, 0x10, 0, last_vcn)
    struct.pack_into("<H", buf, 0x20, run_off)
    struct.pack_into("<QQ", buf, 0x28, (last_vcn + 1) * 4096, real_size)
    if name:
        buf[0x40:0x40 + len(name_b)] = name_b
    buf[run_off:run_off + len(runlist)] = runlist
    return bytes(buf)


def build_record(seq=1, flags=0x01, attrs=b"", link_count=1, base_ref=0,
                 record_size=1024, usn=0xAAAA):
    rec = bytearray(record_size)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 0x30, record_size // 512 + 1)
    struct.pack_into("<HHHHII", rec, 0x10, seq, link_count, 0x38, flags,
                     0, record_size)
    struct.pack_into("<Q", rec, 0x20, base_ref)
    body = attrs + struct.pack("<I", 0xFFFFFFFF)
    rec[0x38:0x38 + len(body)] = body
    struct.pack_into("<I", rec, 0x18, 0x38 + len(body))
    struct.pack_into("<H", rec, 0x30, usn)
    for i in range(record_size // 512):
        tail = (i + 1) * 512 - 2
        rec[0x32 + i * 2:0x34 + i * 2] = rec[tail:tail + 2]
        struct.pack_into("<H", rec, tail, usn)
    return bytes(rec)


def dir_record(seq=1, entries=(), **kw):
    streams = b""
    for child_ref, name in entries:
        stream = fn_value(0, name)
        entry_size = 0x10 + len(stream)
        pad = (-entry_size) % 8
        entry = struct.pack("<QHHI", child_ref, entry_size + pad,
                            len(stream), 0) + stream + b"\x00" * pad
        streams += entry
    streams += struct.pack("<QHHI", 0, 0x10, 0, 0x02)
    total = 0x10 + len(streams)
    value = bytearray(0x10)
    struct.pack_into("<IIB", value, 0, 0x30, 1, 1)
    struct.pack_into("<I", value, 0x08, 4096)
    value += struct.pack("<IIII", 0x10, total, total, 0)
    value += streams
    return build_record(seq=seq, flags=0x03,
                        attrs=resident_attr(0x90, bytes(value), "$I30"),
                        **kw)


def make_image(records):
    return b"".join(records)


class FixupTests(unittest.TestCase):
    def test_fixup_roundtrip(self):
        rec = build_record(attrs=resident_attr(0x10, si_value()))
        fixed = apply_fixup(rec)
        self.assertEqual(fixed[0x30:0x32], b"\xaa\xaa")
        self.assertNotEqual(fixed[510:512], b"\xaa\xaa")

    def test_bad_fixup_detected(self):
        rec = bytearray(build_record())
        rec[510] ^= 0xFF
        with self.assertRaises(BadFixupError):
            apply_fixup(bytes(rec))

    def test_bad_fixup_record_skipped_in_image(self):
        good = build_record(seq=1, attrs=resident_attr(0x10, si_value()))
        bad = bytearray(build_record(seq=1))
        bad[510] ^= 0xFF
        image = MftImage(make_image([good, bytes(bad)]))
        self.assertEqual(len(image.scan_errors), 1)
        self.assertIn("record 1", image.scan_errors[0])
        self.assertIsNotNone(image.get(0))

    def test_truncated_record(self):
        with self.assertRaises(TruncatedRecordError):
            apply_fixup(build_record()[:512])


class RunlistTests(unittest.TestCase):
    def test_multi_run_and_sparse(self):
        runs = decode_runlist(encode_runs([(4, 100), (8, None), (2, -50)]), 0,
                              len(encode_runs([(4, 100), (8, None),
                                               (2, -50)])))
        self.assertEqual(len(runs), 3)
        self.assertEqual(runs[0].lcn, 100)
        self.assertTrue(runs[1].sparse)
        self.assertIsNone(runs[1].lcn)
        self.assertEqual(runs[2].lcn, 50)

    def test_runlist_bounds(self):
        with self.assertRaises(RunlistError):
            decode_runlist(b"\x18\x10", 0, 2)
        with self.assertRaises(RunlistError):
            decode_runlist(b"\x00\x00", 5, 2)

    def test_multi_run_file_entity(self):
        data = nonresident_data("", [(4, 100), (8, None), (2, -50)],
                                real_size=14 * 4096)
        rec = build_record(attrs=resident_attr(0x10, si_value()) + data)
        image = MftImage(make_image([rec]))
        entity = image.get(0)
        stream = entity.streams[0]
        self.assertEqual(len(stream.runs), 3)
        self.assertTrue(stream.sparse)
        self.assertEqual(stream.size, 14 * 4096)


class EntityTests(unittest.TestCase):
    def test_deleted_record(self):
        rec = build_record(flags=0x00,
                           attrs=resident_attr(0x10, si_value())
                           + resident_attr(0x30, fn_value(5 << 0, "gone.txt")))
        image = MftImage(make_image([rec]))
        entity = image.get(0)
        self.assertTrue(entity.deleted)
        self.assertFalse(entity.in_use)
        self.assertEqual(entity.primary_name.name, "gone.txt")

    def test_record_number_reuse_sequence(self):
        old_ref = (3 << 48) | 5
        rec = build_record(seq=7, attrs=resident_attr(0x10, si_value())
                           + resident_attr(0x30, fn_value(old_ref, "x")))
        image = MftImage(make_image([rec]))
        entity = image.get(0)
        self.assertIsNone(image.get(5, 3))
        self.assertIsNone(image.parent_of(entity))

    def test_ads(self):
        attrs = (resident_attr(0x10, si_value())
                 + resident_attr(0x80, b"main", attr_id=1)
                 + resident_attr(0x80, b"hidden", name="secret", attr_id=2))
        image = MftImage(make_image([build_record(attrs=attrs)]))
        entity = image.get(0)
        self.assertEqual(len(entity.streams), 2)
        ads = entity.ads_streams
        self.assertEqual(len(ads), 1)
        self.assertEqual(ads[0].name, "secret")
        self.assertEqual(ads[0].data, b"hidden")

    def test_hard_links(self):
        attrs = (resident_attr(0x10, si_value())
                 + resident_attr(0x30, fn_value(0, "a.txt", namespace=1))
                 + resident_attr(0x30, fn_value(0, "b.txt", namespace=1)))
        rec = build_record(attrs=attrs, link_count=2)
        image = MftImage(make_image([rec]))
        entity = image.get(0)
        self.assertEqual(entity.hard_link_count, 2)
        events = [e for e in build_timeline(image)
                  if e.source == "$FILE_NAME"]
        paths = {e.path for e in events}
        self.assertIn("a.txt", paths)
        self.assertIn("b.txt", paths)

    def test_extension_record_chain(self):
        base_attrs = (resident_attr(0x10, si_value())
                      + resident_attr(0x30, fn_value(0, "big.bin"))
                      + nonresident_data("", [(4, 100)], 4 * 4096, attr_id=1))
        ext_attrs = nonresident_data("", [(4, 200)], 4 * 4096, attr_id=5)
        pad = build_record(seq=1)
        base = build_record(seq=1, attrs=base_attrs)
        ext = build_record(seq=1, attrs=ext_attrs, base_ref=(1 << 48) | 1)
        image = MftImage(make_image([pad, base, ext]))
        base_entity = image.get(1)
        self.assertEqual(base_entity.extensions, [2])
        self.assertEqual(len(base_entity.streams), 2)
        self.assertEqual(base_entity.streams[1].runs[0].lcn, 200)

    def test_directory_index(self):
        child_ref = (1 << 48) | 9
        drec = dir_record(entries=[(child_ref, "kid.txt")])
        image = MftImage(make_image([drec]))
        entity = image.get(0)
        self.assertTrue(entity.is_directory)
        self.assertEqual(len(entity.index_entries), 1)
        entry = entity.index_entries[0]
        self.assertEqual(entry.child_record, 9)
        self.assertEqual(entry.child_sequence, 1)
        self.assertEqual(entry.name, "kid.txt")

    def test_truncated_image(self):
        good = build_record(attrs=resident_attr(0x10, si_value()))
        image = MftImage(good + b"\xde\xad" * 100)
        self.assertTrue(image.truncated)
        self.assertEqual(len(image.scan_errors), 1)
        self.assertIsNotNone(image.get(0))


class BoundsTests(unittest.TestCase):
    def test_attribute_length_overrun(self):
        attr = bytearray(resident_attr(0x10, si_value()))
        struct.pack_into("<I", attr, 4, 0xFFFF)
        rec = build_record(attrs=bytes(attr))
        image = MftImage(make_image([rec]))
        entity = image.get(0)
        self.assertTrue(any("exceeds record bounds" in e
                            for e in entity.errors))

    def test_resident_value_overrun(self):
        attr = bytearray(resident_attr(0x10, si_value()))
        struct.pack_into("<I", attr, 0x10, 0xFFFF)
        rec = build_record(attrs=bytes(attr))
        image = MftImage(make_image([rec]))
        entity = image.get(0)
        self.assertTrue(any("outside attribute length" in e
                            for e in entity.errors))

    def test_runlist_offset_overrun(self):
        attr = bytearray(nonresident_data("", [(4, 100)], 4 * 4096))
        struct.pack_into("<H", attr, 0x20, 0xF000)
        rec = build_record(attrs=bytes(attr))
        image = MftImage(make_image([rec]))
        entity = image.get(0)
        self.assertTrue(any("runlist offset" in e for e in entity.errors))


class TimelineTests(unittest.TestCase):
    def _image(self, si_c=0, si_m=1, fn_c=0, fn_m=1):
        attrs = (resident_attr(0x10, si_value(c=si_c, m=si_m))
                 + resident_attr(0x30, fn_value(0, "f.txt",
                                                c=fn_c, m=fn_m)))
        return MftImage(make_image([build_record(attrs=attrs)]))

    def test_timeline_sorted_and_sourced(self):
        image = self._image()
        events = build_timeline(image)
        self.assertEqual(len(events), 8)
        self.assertEqual(events, sorted(events, key=lambda e: e.timestamp))
        sources = {e.source for e in events}
        self.assertEqual(sources, {"$STANDARD_INFORMATION", "$FILE_NAME"})
        csv_out = timeline_to_csv(events)
        self.assertIn("$FILE_NAME", csv_out)
        self.assertEqual(len(csv_out.strip().splitlines()), 9)

    def test_timestomp_detection(self):
        image = self._image(si_c=-100, si_m=-90, fn_c=0, fn_m=1)
        anomalies = detect_timestamp_anomalies(image)
        kinds = {a.kind for a in anomalies}
        self.assertIn("si_before_fn", kinds)
        self.assertTrue(any("f.txt" in a.path for a in anomalies))

    def test_no_false_positive_when_consistent(self):
        image = self._image()
        self.assertEqual(detect_timestamp_anomalies(image), [])

    def test_deleted_entity_events_flagged(self):
        rec = build_record(flags=0x00,
                           attrs=resident_attr(0x10, si_value()))
        image = MftImage(make_image([rec]))
        events = build_timeline(image)
        self.assertTrue(events)
        self.assertTrue(all(e.deleted for e in events))


if __name__ == "__main__":
    unittest.main()
