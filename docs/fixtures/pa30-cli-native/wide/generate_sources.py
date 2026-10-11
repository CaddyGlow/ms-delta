from pathlib import Path
root = Path(__file__).resolve().parent
for name, count, reverse in [('source', 150, False), ('target', 250, True)]:
    indices = list(range(count))
    if reverse:
        indices.reverse()
    classes = ['public class N_%03d_%s { public int Value() { return %d; } }' % (i, 'x' * 300, i) for i in indices]
    (root / (name + '.cs')).write_text('namespace WideStringFixture {\n' + '\n'.join(classes) + '\n}\n')
