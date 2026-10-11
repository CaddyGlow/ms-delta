#!/usr/bin/env python3
"""Construct original PE test data with the native legacy five-column GenericParam layout.
Never execute these synthetic DLLs. The modern CLR does not use this table layout.
"""
import hashlib
import json
import struct
from pathlib import Path

SCHEMA = {"0":[[0,0],[3,0],[5,0],[5,0],[5,0]],"1":[[7,11],[3,0],[3,0]],"2":[[1,0],[3,0],[3,0],[7,0],[6,4],[6,6]],"3":[[6,4]],"4":[[0,0],[3,0],[4,3]],"5":[[6,6]],"6":[[2,0],[0,0],[0,0],[3,0],[4,1],[6,8]],"7":[[6,8]],"8":[[0,0],[0,0],[3,0]],"9":[[6,2],[7,0]],"10":[[7,5],[3,0],[4,2]],"11":[[0,0],[7,1],[4,0]],"12":[[7,2],[7,10],[4,6]],"13":[[7,3],[4,7]],"14":[[0,0],[7,4],[4,8]],"15":[[0,0],[1,0],[6,2]],"16":[[1,0],[6,4]],"17":[[4,9]],"18":[[6,2],[6,20]],"19":[[6,20]],"20":[[0,0],[3,0],[7,0]],"21":[[6,2],[6,23]],"22":[[6,23]],"23":[[0,0],[3,0],[4,4]],"24":[[0,0],[6,6],[7,6]],"25":[[6,2],[7,7],[7,7]],"26":[[3,0]],"27":[[4,5]],"28":[[0,0],[7,8],[3,0],[6,26]],"29":[[2,0],[6,4]],"30":[[1,0],[1,0]],"31":[[1,0]],"32":[[1,0],[0,0],[0,0],[0,0],[0,0],[1,0],[4,10],[3,0],[3,0]],"33":[[1,0]],"34":[[1,0],[1,0],[1,0]],"35":[[0,0],[0,0],[0,0],[0,0],[1,0],[4,11],[3,0],[3,0],[4,12]],"36":[[1,0],[6,35]],"37":[[1,0],[1,0],[1,0],[6,35]],"38":[[1,0],[3,0],[4,12]],"39":[[1,0],[1,0],[3,0],[3,0],[7,9]],"40":[[1,0],[1,0],[3,0],[7,9]],"41":[[6,2],[6,2]],"42":[[0,0],[0,0],[7,12],[3,0]],"43":[[7,7],[4,0]],"44":[[6,42],[7,0]]}
CODED = {"0":[2,[2,1,27]],"1":[2,[4,8,23]],"2":[5,[6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43]],"3":[1,[4,8]],"4":[2,[2,6,32]],"5":[3,[2,1,26,6,27]],"6":[1,[20,23]],"7":[1,[6,10]],"8":[1,[4,6]],"9":[2,[38,35,39]],"10":[3,[64,64,6,10,64]],"11":[2,[0,26,35,1]],"12":[1,[2,6]]}

def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]

def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def set32(data, offset, value):
    struct.pack_into("<I", data, offset, value)

def build(original):
    data = bytearray(original)
    nt = u32(data, 60)
    optional = nt + 24
    optional_size = u16(data, nt + 20)
    section_start = optional + optional_size
    section_count = u16(data, nt + 6)
    sections = []
    for index in range(section_count):
        header = section_start + 40 * index
        sections.append((header, u32(data, header + 12), u32(data, header + 16), u32(data, header + 20)))
    def locate(rva):
        for _, va, size, raw in sections:
            if va <= rva < va + size:
                return raw + rva - va
        raise ValueError("RVA is not backed")
    cli = locate(u32(data, optional + 96 + 14 * 8))
    root_rva = u32(data, cli + 8)
    root_size = u32(data, cli + 12)
    root_start = locate(root_rva)
    root = bytearray(data[root_start:root_start + root_size])
    cursor = 16 + ((u32(root, 12) + 3) // 4) * 4
    stream_count = u16(root, cursor + 2)
    cursor += 4
    streams = {}
    for _ in range(stream_count):
        name_end = root.index(0, cursor + 8)
        name = bytes(root[cursor + 8:name_end]).decode("ascii")
        streams[name] = (cursor, u32(root, cursor), u32(root, cursor + 4))
        cursor = ((name_end + 1 + 3) // 4) * 4
    _, tables_start, tables_size = streams["#~"]
    heap_bits = root[tables_start + 6]
    valid = struct.unpack_from("<Q", root, tables_start + 8)[0]
    rows = [0] * 64
    cursor = tables_start + 24
    for index in range(64):
        if valid >> index & 1:
            rows[index] = u32(root, cursor)
            cursor += 4
    widths = {}
    offsets = {}
    for table in range(45):
        if not rows[table]:
            continue
        offsets[table] = cursor
        columns = []
        for kind, argument in SCHEMA[str(table)]:
            if kind == 0:
                long = False
            elif kind in (1, 2):
                long = True
            elif kind in (3, 4, 5):
                long = bool(heap_bits & {3:1, 4:4, 5:2}[kind])
            elif kind == 6:
                long = rows[argument] >= 65536
            else:
                bits, tags = CODED[str(argument)]
                long = any(rows[tag] >= (65536 >> bits) for tag in tags if tag < 64)
            columns.append(4 if long else 2)
        widths[table] = columns
        cursor += rows[table] * sum(columns)
    strings = streams["#Strings"][1]
    item = None
    typedef_width = sum(widths[2])
    for row in range(rows[2]):
        offset = offsets[2] + row * typedef_width + 4
        name_index = u32(root, offset) if widths[2][1] == 4 else u16(root, offset)
        name_start = strings + name_index
        name_end = root.index(0, name_start)
        if root[name_start:name_end] == b"Item":
            item = row + 1
            break
    if item is None:
        raise ValueError("fixture has no Item TypeDef")
    if not rows[42] or any(width != 2 for width in widths[42]):
        raise ValueError("fixture requires narrow nonempty GenericParam")
    first = offsets[42]
    old_size = sum(widths[42])
    old_end = first + rows[42] * old_size
    expanded = bytearray()
    for row in range(rows[42]):
        expanded += root[first + row * old_size:first + (row + 1) * old_size]
        expanded += struct.pack("<H", item << 2)
    root[first:old_end] = expanded
    extra = rows[42] * 2
    padding = (-extra) % 4
    stream_end = tables_start + tables_size + extra
    root[stream_end:stream_end] = bytes(padding)
    inserted = extra + padding
    for name, (header, offset, size) in streams.items():
        if name == "#~":
            set32(root, header + 4, size + inserted)
        elif offset >= tables_start + tables_size:
            set32(root, header, offset + inserted)
    # Make room for a fourth section header without moving any RVA-backed data.
    old_headers = u32(data, optional + 60)
    if old_headers != 512:
        raise ValueError("expected original fixture header size")
    data[old_headers:old_headers] = bytes(512)
    for header, _, _, raw in sections:
        set32(data, header + 20, raw + 512)
    set32(data, optional + 60, old_headers + 512)
    struct.pack_into("<H", data, nt + 6, section_count + 1)
    new_raw = (len(data) + 511) // 512 * 512
    new_rva = (u32(data, optional + 56) + 4095) // 4096 * 4096
    new_raw_size = (len(root) + 511) // 512 * 512
    header = section_start + 40 * section_count
    data[header:header + 40] = bytes(40)
    data[header:header + 8] = b".climeta"
    struct.pack_into("<IIII", data, header + 8, len(root), new_rva, new_raw_size, new_raw)
    set32(data, header + 36, 0x40000040)
    set32(data, optional + 56, new_rva + (len(root) + 4095) // 4096 * 4096)
    set32(data, optional + 8, u32(data, optional + 8) + new_raw_size)
    set32(data, cli + 512 + 8, new_rva)
    set32(data, cli + 512 + 12, len(root))
    data += bytes(new_raw - len(data))
    data += root + bytes(new_raw_size - len(root))
    return bytes(data), {"generic_rows":rows[42], "constraint_typedef_rid":item,
                        "constraint_coded_value":item << 2,
                        "metadata_rva":new_rva, "metadata_size":len(root),
                        "tables_size":tables_size + inserted}

def main():
    destination = Path(__file__).resolve().parent
    source = destination.parent / "signatures" / "x86"
    records = {}
    for name in ("source", "target"):
        original = (source / (name + ".dll")).read_bytes()
        converted, record = build(original)
        (destination / (name + ".dll")).write_bytes(converted)
        record.update(input_sha256=hashlib.sha256(original).hexdigest(),
                      output_sha256=hashlib.sha256(converted).hexdigest(),
                      output_size=len(converted))
        records[name] = record
    (destination / "inputs.json").write_text(json.dumps(records, indent=2) + "\n")

if __name__ == "__main__":
    main()

