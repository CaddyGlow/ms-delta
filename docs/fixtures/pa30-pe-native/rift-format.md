# PA30 rift research evidence

The Rust implementation in `crates/windows-delta/src/pa30/rift.rs` was written
independently from observed Microsoft `msdelta.dll` 19041 behavior and public
symbol names. No native implementation source was copied. The associated PDB
identifier is `7B8B6A22A43F1187433E929B2C5944921`; the PDB was obtained from the
[Microsoft symbol server](https://msdl.microsoft.com/download/symbols/msdelta.pdb/7B8B6A22A43F1187433E929B2C5944921/msdelta.pdb).
This is implementation research, not a Microsoft PA30 format specification.

The inspected native functions were `RiftTable::InternalFromBitReader`
(RVA `0x5120`), `RiftTable::FromBitReaderWithFormat` (`0x11ab0`),
`IntFormat::ReadNumber` (`0x11c10`), `RiftTable::GetRift` (`0x4cd0`),
`RiftTable::Map` (`0x15e80`), `RiftTable::Multiply` (`0x4620`),
`RiftTable::Reverse` (`0x4060`), and `RiftTable::Sum` (`0x24970`).

A `(left, right)` entry changes the address translation to `right - left`
starting at `left`. Before the first entry, the final entry's translation
applies. Empty tables are identity. Duplicate breakpoints resolve to their
last entry. Address mapping wraps over the signed 64-bit domain. Multiplication
composes maps; summation merges breakpoints with explicit collision priority.

The wire representation starts with one nonempty bit, followed by two signed
integer Huffman formats and a nibble-encoded entry count. Each entry encodes a
delta in the left coordinate and a delta in the translation. The integer
formats have 126 positive and 126 negative symbols. Negative values complement
their corresponding positive magnitude. Two explicit-length counts, a trailing
length partition count, and 4-bit lengths define the left-leaning Huffman tree.
The parser bounds table storage and rejects truncated or unsorted entries.

The retained `rift-reverse.ps1` and `rift-reverse.execution.json` exercise the
native private reversal function in an isolated disposable Windows process.
Four cases cover a positive step, negative step, constant translation, and
reordered overlapping ranges. Rust tests compare both exact inverse entries and
mapping against these native results at breakpoints and interval interiors.
Same-translation segment boundaries remain present: they can reset a different
translation when another table is subsequently overlaid. Extra experiments with
other start addresses are retained in `rift-reverse-starts.*`; production Rust
currently uses only start zero. Native reversal of a single constant translation
preserves that translation, a compatibility quirk retained in Rust.

The native generated shifted PE fixtures additionally validate nonempty wire
tables through full reconstruction and target hashes. A separately constructed
wire fixture tests signed cumulative coordinates and all truncation positions.
Composition tests compare results with direct nested mapping, including signed
wrap boundaries. These tests do not establish compatibility with every possible
native rift table or unsupported PE transform.

`max_parameter_bytes` bounds parameter trees and individual rift tables or
workspaces separately. Composition also has a bounded pairwise work budget.
This is not an aggregate resident-memory ceiling: the decoder can retain several
maps alongside parameter trees, normalized source bytes, hints, and output.
