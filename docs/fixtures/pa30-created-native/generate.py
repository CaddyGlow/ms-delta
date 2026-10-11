"""Create original known-answer inputs and invoke the standalone Rust encoder."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

root = Path(__file__).resolve().parent
cache = Path('/data/cache/pa30-created-native')
cache.mkdir(exist_ok=True)
cli = Path(os.environ.get('WINDOWS_DELTA_CLI', 'ms-delta'))


def random_bytes(size):
    value = 5071
    result = bytearray()
    for _ in range(size):
        value ^= (value << 13) & 0xffffffff
        value ^= value >> 17
        value ^= (value << 5) & 0xffffffff
        result.append(value & 255)
    return bytes(result)


random = random_bytes(4096)
changed = bytearray(random)
changed[100:148] = bytes(range(48))
created = root.parent / 'pa30-pe32-native/basic/anycpu'
cases = [
    ('empty', b'', b''), ('abc', b'', b'abc'),
    ('all-256', b'', bytes(range(256))),
    ('random-literals', b'', random_bytes(8192)),
    ('short-repetition', b'', b'ABCD' * 100),
    ('long-repetition', b'', b'ABCD' * 20000),
    ('identical-source', random, random),
    ('changed-source', random, bytes(changed)),
    ('reversed-source', random, random[::-1]),
    ('source-prefix', random, random[:512]),
    ('source-suffix', random, random[-512:]),
    ('source-reordered', random, random[2048:2560] + random[64:512]),
    ('tiny-source', b'abc', b'abcabcabcabc'),
    ('binary-source', bytes(range(256)) * 4, bytes(range(256)) * 6),
    ('length-8', b'', b'A' * 8), ('length-9', b'', b'A' * 9),
    ('length-255', b'', b'A' * 255),
    ('length-65536', b'', b'A' * 65536),
    ('raw-managed-pe32', (created / 'source.dll').read_bytes(), (created / 'target.dll').read_bytes()),
]
for size in [600000, 2000000, 20000000]:
    cases.append(('offset-' + str(size), b'DISTANCE' + bytes(size - 8), b'DISTANCE' * 512))
rows = []
for name, source, target in cases:
    source_path = (cache if len(source) > 1000000 else root) / (name + '.source')
    target_path = root / (name + '.target')
    delta_path = root / (name + '.delta')
    source_path.write_bytes(source)
    target_path.write_bytes(target)
    # Intentionally do not overwrite existing patches; invocation should fail if reused.
    result = subprocess.run([str(cli), 'create', '--format', 'pa30', '--source', str(source_path), '--target', str(target_path), '--output', str(delta_path)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stderr)
    info = json.loads(subprocess.check_output([str(cli), 'inspect', '--delta', str(delta_path)]))
    row = {'name': name, 'source_path': source_path.name if source_path.parent == root else str(source_path), 'source_size': len(source), 'target_size': len(target), 'delta_size': delta_path.stat().st_size,
           'source_sha256': hashlib.sha256(source).hexdigest(), 'target_sha256': hashlib.sha256(target).hexdigest(), 'delta_sha256': hashlib.sha256(delta_path.read_bytes()).hexdigest(), 'header': info,
           'rust_create_exit': result.returncode, 'rust_create_stdout': result.stdout}
    if len(source) > 1000000:
        row['source_generator'] = 'ASCII DISTANCE followed by source_size - 8 zero bytes; large source cache only'
    rows.append(row)
(root / 'manifest.json').write_text(json.dumps(rows, indent=2) + '\n')
print('Created', len(rows), 'Rust PA30 patches')
