#!/usr/bin/env python3
"""Validate the checked-in C3 and provisional S3 partition layouts."""
from pathlib import Path

PAGE = 0x1000
ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "partitions.csv": {"flash_end": 0x400000, "fs_offset": 0x2B0000, "fs_size": 0x150000},
    "partitions_s3_n16r8.csv": {"flash_end": 0x1000000, "fs_offset": 0x610000, "fs_size": 0x9F0000},
}


def parse(path):
    rows = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [field.strip() for field in line.split(",")]
        if len(fields) != 5:
            raise ValueError(f"{path.name}: expected five fields: {line!r}")
        name, kind, subtype, offset, size = fields
        rows.append((name, kind, subtype, int(offset, 0), int(size, 0)))
    return rows


def check(filename, expected):
    path = ROOT / filename
    rows = parse(path)
    names = [row[0] for row in rows]
    if len(names) != len(set(names)):
        raise ValueError(f"{filename}: duplicate partition name")

    previous_end = 0
    for name, kind, subtype, offset, size in sorted(rows, key=lambda row: row[3]):
        if offset % PAGE or size % PAGE:
            raise ValueError(f"{filename}: {name} is not 0x1000 aligned")
        if offset < previous_end:
            raise ValueError(f"{filename}: {name} overlaps the previous partition")
        previous_end = offset + size
    if previous_end != expected["flash_end"]:
        raise ValueError(f"{filename}: end 0x{previous_end:x} != 0x{expected['flash_end']:x}")

    by_name = {row[0]: row for row in rows}
    for name in ("nvs", "otadata", "app0", "app1"):
        if name not in by_name:
            raise ValueError(f"{filename}: missing {name}")
    app0, app1 = by_name["app0"], by_name["app1"]
    if app0[1:3] != ("app", "ota_0") or app1[1:3] != ("app", "ota_1"):
        raise ValueError(f"{filename}: app0/app1 are not OTA slots")
    if app0[4] != app1[4] or app1[3] != app0[3] + app0[4]:
        raise ValueError(f"{filename}: OTA slots are not adjacent and equal-sized")

    fs = by_name.get("spiffs") or by_name.get("littlefs")
    if not fs or fs[1] != "data" or fs[2] != "spiffs":
        raise ValueError(f"{filename}: expected a data/spiffs filesystem partition")
    if (fs[3], fs[4]) != (expected["fs_offset"], expected["fs_size"]):
        raise ValueError(f"{filename}: unexpected filesystem offset/size")
    print(f"{filename}: OK, flash end 0x{previous_end:x}, OTA slot 0x{app0[4]:x}, FS {fs[0]} 0x{fs[4]:x}")


for filename, expected in EXPECTED.items():
    check(filename, expected)
