"""Report generated PE metadata stream sizes and heap-width flags for research."""
from pathlib import Path
import json
import struct


def inspect(path):
    b = path.read_bytes()
    u16 = lambda n: struct.unpack_from('<H', b, n)[0]
    u32 = lambda n: struct.unpack_from('<I', b, n)[0]
    pe = u32(0x3c)
    assert b[pe:pe+4] == b'PE\0\0'
    coff = pe + 4
    optional = coff + 20
    magic = u16(optional)
    assert magic in (0x10b, 0x20b)
    directory = 96 if magic == 0x10b else 112
    section_start = optional + u16(coff + 16)
    sections = [section_start + 40 * i for i in range(u16(coff + 2))]

    def rva(n):
        for s in sections:
            va, size, raw = u32(s + 12), u32(s + 16), u32(s + 20)
            if va <= n < va + size:
                return raw + n - va
        raise ValueError('unmapped RVA')

    cli = rva(u32(optional + directory + 14 * 8))
    metadata = rva(u32(cli + 8))
    assert b[metadata:metadata+4] == b'BSJB'
    cursor = (metadata + 16 + u32(metadata + 12) + 3) & ~3
    count = u16(cursor + 2)
    cursor += 4
    streams = {}
    for _ in range(count):
        offset, size = u32(cursor), u32(cursor+4)
        end = b.index(0, cursor+8)
        name = b[cursor+8:end].decode('ascii')
        streams[name] = {'offset': offset, 'size': size}
        cursor = (end + 4) & ~3
    table = metadata + streams['#~']['offset']
    flags = b[table + 6]
    valid = struct.unpack_from('<Q', b, table+8)[0]
    cursor = table + 24
    rows = {}
    for t in range(64):
        if valid & (1 << t):
            rows[str(t)] = u32(cursor)
            cursor += 4
    return {'machine': u16(coff), 'optional_header_magic': magic, 'clr_flags': u32(cli + 16), 'streams': streams, 'heap_width_flags': flags, 'string_index_bytes': 4 if flags & 1 else 2, 'blob_index_bytes': 4 if flags & 4 else 2, 'table_rows': rows}


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    report = {str(p.relative_to(root)): inspect(p) for p in sorted(root.rglob('*.dll')) if 'native-i386' not in p.parts and 'legacy-schema' not in p.parts}
    (root / 'metadata-layouts.json').write_text(json.dumps(report, indent=2) + '\n')
