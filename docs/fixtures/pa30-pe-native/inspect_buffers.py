"""Extract bounded PA30 outer buffers for research; not a patch decoder/oracle."""
from pathlib import Path
import hashlib
import json


def inspect(path):
    data = path.read_bytes()
    assert len(data) < 4_000_000 and data[:4] == b'PA30'
    stream = data[12:]
    position = 3

    def read(count):
        nonlocal position
        assert position + count <= len(stream) * 8 - (stream[0] & 7)
        value = sum(((stream[(position + i) // 8] >> ((position + i) % 8)) & 1) << i for i in range(count))
        position += count
        return value

    def number():
        nibbles = 1
        while read(1) == 0:
            nibbles += 1
            assert nibbles <= 16
        return read(4 * nibbles)

    def buffer():
        nonlocal position
        size = number()
        position = (position + 7) & ~7
        start = position // 8
        assert start + size <= len(stream)
        position += size * 8
        return stream[start:start + size]

    fields = dict(zip(['type_set', 'type', 'flags', 'target_size', 'hash_alg'], [number() for _ in range(5)]))
    fields['target_hash'] = buffer().hex()
    for name in ['preprocessing', 'patch']:
        b = buffer()
        path.with_suffix('.' + name).write_bytes(b)
        fields[name + '_size'] = len(b)
        fields[name + '_sha256'] = hashlib.sha256(b).hexdigest()
    fields['delta_sha256'] = hashlib.sha256(data).hexdigest()
    return fields


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    rows = {p.name: inspect(p) for p in sorted(root.glob('*.delta'))}
    (root / 'outer-buffers.json').write_text(json.dumps(rows, indent=2) + '\n')
