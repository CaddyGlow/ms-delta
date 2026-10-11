"""Copy original PE controls and derive header-only, never-executed variants."""
from pathlib import Path
import hashlib
import json
import struct

root = Path(__file__).resolve().parent
fixtures = root.parent
pairs = [
    ('i386-layout', fixtures / 'pa30-pe32-native/native-i386/source.exe', fixtures / 'pa30-pe32-native/native-i386/target.exe'),
    ('amd64-small', fixtures / 'pa30-pe-native/source.exe', fixtures / 'pa30-pe-native/target.exe'),
    ('amd64-shifted', fixtures / 'pa30-pe-native/source.exe', fixtures / 'pa30-pe-native/shifted.exe'),
]
for name, source, target in pairs:
    folder = root / name
    folder.mkdir(exist_ok=True)
    (folder / 'source.exe').write_bytes(source.read_bytes())
    (folder / 'target.exe').write_bytes(target.read_bytes())

for name, baseline in [('i386-header', pairs[0][1]), ('amd64-header', pairs[1][1])]:
    folder = root / name
    folder.mkdir(exist_ok=True)
    original = baseline.read_bytes()
    source = bytearray(original)
    target = bytearray(original)
    nt = struct.unpack_from('<I', original, 0x3c)[0]
    optional = nt + 24
    is_pe32 = struct.unpack_from('<H', original, optional)[0] == 0x10b
    directories = optional + (96 if is_pe32 else 112)
    struct.pack_into('<I', source, nt + 8, 0x12345678)
    struct.pack_into('<I', target, nt + 8, 0xfedcba98)
    struct.pack_into('<I', source, optional + 64, 0x89abcdef)
    struct.pack_into('<I', target, optional + 64, 0)
    struct.pack_into('<I', source, directories + 8 * 8, 0x1010)
    struct.pack_into('<I', target, directories + 8 * 8, 0x1020)
    if is_pe32:
        struct.pack_into('<I', source, optional + 28, 0x410000)
        struct.pack_into('<I', target, optional + 28, 0x520000)
    else:
        struct.pack_into('<Q', source, optional + 24, 0x1234567890000)
        struct.pack_into('<Q', target, optional + 24, 0xabcdef0120000)
    (folder / 'source.exe').write_bytes(source)
    (folder / 'target.exe').write_bytes(target)

rows = []
for folder in sorted(root.iterdir()):
    if not folder.is_dir() or not (folder / 'source.exe').exists():
        continue
    rows.append({'pair': folder.name, 'files': {n: {'size': (folder / n).stat().st_size, 'sha256': hashlib.sha256((folder / n).read_bytes()).hexdigest()} for n in ['source.exe', 'target.exe']}})
(root / 'inputs.json').write_text(json.dumps(rows, indent=2) + '\n')
