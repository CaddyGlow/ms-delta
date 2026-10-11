# Native delta reconstruction and creation

`windows-delta` creates patches and reconstructs file bytes with portable Rust. This is separate
from Windows servicing: decoding a patch does not establish package
applicability, catalog trust, component-store consistency, or bootability.

## File patch formats

| Format | Header and bitstream | Implemented scope |
| --- | --- | --- |
| PA30 | `PA30`, FILETIME, an LSB-first outer stream, and independent PLZX patch stream | RAW, I386/AMD64, Thumb ARM, ARM64 and IA64 PE, AnyCPU, legacy and CLI4 managed files; source preprocessing/nonempty rifts, target E8 restoration, default/composite Huffman parameters, source/output/repeat matches and extended offsets |
| PA31 | `PA31`, FILETIME, a nested source/target integrity header, and PLZX or framed LZMS/BSDiff | Forward reconstruction and reverse playback; RAW, PE and managed dictionaries shared with PA30 |
| MS-PATCH LZX Delta | Little-endian two-byte chunk-size prefixes, LZX bitstream, externally supplied target size/window | Reference history, verbatim/aligned/uncompressed blocks, extended match lengths and Intel E8 translation |

PA30 inspects file types, transform flags, target size/hash, and nested-buffer
sizes. Application supports RAW type 1, I386 PE selected types 2/16 and AMD64
types 8/32. IA64 selects type 4, Thumb ARM type 64 and ARM64 type 128.
Types 2/4/8 select legacy managed graphs; 16/32/64/128 select CLI4 metadata.
The source machine and optional-header width must match the selected graph.
The file-type *set* can contain other candidate types. Generation-limit
flags `0x20000` and `0x40000` do not change reconstruction.

PE preprocessing parses checked PE32/PE32+ headers and applies source marking,
imports, exports, resources, relocations, instruction operands, pdata/unwind
handlers, and import unbinding. Source image base, global pointer, timestamp,
and checksum are normalized using target preprocessing metadata. Nonempty rifts
map source RVAs into target geometry and compose the compression dictionary
mapping. Target E8 restoration follows the native graph. The native HEADERS flag
has no additional effect in these graphs. PE32 uses four-byte import thunks,
HIGHLOW relocations, load-config lock-prefix normalization, and native byte scans for
relative calls, long jumps and conditional jumps. Relocation-table rewriting uses
the native fixed source-buffer capacity, including omission of entries that no
longer fit after mapped pages split. This alters only the decoding dictionary;
the final target must still pass its declared hash.

An executable graph does not imply the source is managed.
Managed preprocessing reads the private target-metadata and shared-format CLI
maps, normalizes metadata heap/table/coded indices and signature type references,
and remaps IL field/method/type/string tokens. Compression maps preserve row and
heap geometry, including two/four-byte index transitions. The pinned native graph
uses bit 21 for IL and bit 22 for metadata; fixture names retain numeric flags
because the SDK macro names do not describe that observed transform order.
Legacy graphs use bits 14/15 for IL/metadata and a five-column GenericParam
schema. When modern GenericParam rows exhaust that older schema's table buffer,
the native source parser resets metadata to empty; the Rust parser mirrors that
bounded fallback. Both graphs share the private map wire format and compression
rules, while retaining their distinct metadata geometry.
Native quirks include skipping the final MethodDef during IL/marking, leaving
`calli` tokens unchanged, and preserving stale signature bytes when an encoded
index shrinks. The native signature walker also stops at generic base types and
leaves parameters of void/typed-reference-returning MethodDef/MemberRef
signatures untouched. Identity rift boundaries must survive reversal until maps merge.

Validation covers original pure-IL AnyCPU, x86 and x64 assemblies and synthetic
unmanaged I386/AMD64 files, original mixed-mode and ReadyToRun images, and
ARM32/ARM64 and IA64 native flag matrices. A fresh host replay confirms that
`ia64-forward-2048` now reconstructs exactly. Unsupported relocation
kinds and unknown transform flags are outside the validated scope. Unsupported
formats fail explicitly; no complete PA30 coverage is claimed.

PA30 application validates its declared target size and MD5, SHA-1, or SHA-256
hash. MD5/SHA-1 are compatibility checks, not independent authenticity claims.
The earlier 19041 msdelta oracle generated MD5 and SHA-1 patches; its SHA-256
generation attempt returned Windows error 13. The newer UpdateCompression oracle
accepts SHA-256 creation. Rust SHA-256 parsing/verifying support does
not establish native SHA-256 generation interoperability.

LZX Delta has no PA30 header or intrinsic target hash. Callers provide its exact
target length and a window order from 17 through 25 (128 KiB–32 MiB). Reference
data must fit inside the window minus three bytes. The full-stream decoder
checks framing, chunk sizes, padding, output bounds and trailing data.

Direct MSU processing, general PSF/CIX dependency-chain orchestration, legacy
PA19, and CBS installation are outside this API.

## API, commands, and bounds

The APIs are `pa30::inspect_pa30`, `pa30::apply_pa30`, `pa30::create_pa30`, `pa30::create_pa30_pe`,
`apply_lzxd`, and `create_lzxd` in
[windows-delta](../README.md). The optional `cli` feature
builds `windows-delta inspect`, `create` and `apply`.
The main `windows-uup` CLI also exposes `delta-inspect`, `delta-create` and `delta-apply` with
the same arguments. Select `--format pa30`
or `--format lzxd` explicitly; omit `--source` for an empty basis. LZX Delta
requires `--target-size` and accepts `--window-order` (default 17).
`--expected-sha256` supplies an additional independently expected target hash.

Creation accepts `--source`, `--target`, `--output` and `--format`. LZXD also
accepts `--window-order`; applying its output still requires the exact target
size and window order. Creation checks the resulting patch against the target
before publishing. PA30 creation emits RAW type 1 with flags zero, SHA-1 target
hash and zero FILETIME. Its bounded four-candidate dictionary finds source and
overlapping output matches, with native default Huffman parameters and extended
offset/length encodings. Arbitrary PE/managed bytes are accepted as RAW input;
optimized pure IL managed creation emits CLI4 graphs.

Optional `--pe` (or `create_pa30_pe`) creates unmanaged legacy PE graphs with
file-type set 15 and selected I386 type 2 or AMD64 type 8. Both inputs must be
checked PEs of the same architecture. Target
image base, timestamp and global pointer drive source header normalization.
Target RVA-to-file maps and matching-section-name source/target RVA maps are
serialized through the private signed Rift wire format. The encoder compares
three candidates: header normalization (flags zero), relocation normalization
(`0x20`), and combined transforms (`0x21fe` for I386 / `0x263e` for AMD64).
Each candidate uses generic source/output offset matches and is checked against
the original source and exact target before selection. Unsupported optional
normalizations may be skipped when another PE candidate succeeds.

The smallest successful PE patch wins. It is not automatically compared with
RAW output; preprocessing overhead makes some small/header-only patches larger.
Pointer-heavy rebased fixtures demonstrate 112-byte AMD64 and 111-byte I386
patches, compared with 5,770 and 7,659–7,666 RAW bytes respectively. These are
original controlled fixtures, not a claim about compression ratios on Windows
update payloads. Adaptive encoding and fine-grained symbol/function correspondence remain future work.

MS-PATCH creation emits chunk-prefixed verbatim blocks with fixed complete
Huffman trees, source/output matches and recent offsets. It uses windows
17 through 25, matches up to 256 bytes and disables Intel preprocessing.
Creation does not emit adaptive trees or aligned blocks. Both encoders are
deterministic; their patches can be larger than Microsoft's adaptive output,
and incompressible data can expand. PA19 patch-file envelopes are not emitted.

`Limits` defaults are 64 MiB for each patch/source/output, 32 MiB for history
distance/window, and 8 MiB for each retained PA30 parameter/table/workspace
budget. These independent budgets are not an aggregate process-memory ceiling:
multiple maps, normalized source bytes and hints can coexist. Allocation arithmetic and declared
sizes are checked before reserving output or attacker-sized parameter arrays.
Disassembly, import traversal and unbinding also cap cumulative repeated
traversal work at four source lengths per transform.

Unsupported features, malformed data, integrity failures and resource limits
have distinct errors. File commands preserve inputs and refuse existing output
files/symlinks; they publish patches or decoded bytes only after checks succeed.

## Evidence

- [PE32 and encoder validation snapshot](fixtures/pa30-pe32-native/rust-validation.json)
  pins the tested Rust source and oracle manifests. Host suites, strict workspace
  Clippy, formatting, SSU5071 reconstruction, independent MS-PATCH decoding and
  the Windows x64 cross-build pass. This gate does not execute the Rust Windows
  binary; native MSDelta oracle execution is a separate recorded check.
- [Native PA30 fixtures](fixtures/pa30-native/README.md): thirteen generated
  patches round-tripped with Windows `CreateDeltaB`/`ApplyDeltaB`, with platform,
  DLL, input and target hashes retained. Rust reproduces every target, including
  dynamic Huffman coding and all three extended-offset prefixes at 600,000,
  2,000,000 and 20,000,000-byte source distances. The two largest source buffers
  are regenerated deterministically in tests rather than checked in.
- [Real SSU oracle metadata](fixtures/pa30-native/ssu-oracle.json) and
  [Rust comparison](fixtures/pa30-native/rust-ssu-oracle.json): Rust decoded
  SSU5071 RAW member 0 from an empty basis into 1,326,048 bytes. Its SHA-256
  `884b19a15a672842b1d6a9abece35fdfb01989122cc7ec2f709d5df964b48f5e`
  matches native `ApplyDeltaB` and the independent CIX target record. Other
  sampled SSU members are covered by the PE chain gate below. Microsoft
  patch/output bytes stay in the local cache.
- [AMD64 PE native research](fixtures/pa30-pe-native/README.md): 44 original
  synthetic known-answer cases cover RAW empty bases, legacy AMD64 type 8,
  CLI4-capable type 32, isolated flags, and shifted section/RVA geometry.
  Eleven cache-only Microsoft PE flag-isolated cases exercise actual imports,
  resources and other transforms; Rust reproduces every native target exactly.
  Eight additional RAW E8 vectors and a native-applied LRU golden distinguish
  boundary behavior and offset deduplication. Private native rift-reversal
  experiments pin mapping semantics independently of the Rust implementation.
- [Rust SSU PE chain comparison](fixtures/pa30-native/rust-ssu-pe-oracle.json):
  Rust reconstructs SSU5071 members 0, 1, 2 and 10, using its own previously
  reconstructed bytes as dependency bases. Every target matches native
  `ApplyDeltaB` and the independent CIX length/SHA-256 record. This sampled
  dependency chain establishes file reconstruction, not general PSFX support.
- [LZX Delta fixtures](https://github.com/CaddyGlow/ms-compress/blob/main/tests/fixtures/lzxd/README.md):
  the specification's `abc` example and six independently constructed vectors
  decoded identically with unmodified libmspack, pinned at
  `55d501976171397ccd5d5a7a1ca7da065b1d9a06`.
- [Managed CLI4 fixtures](fixtures/pa30-cli-native/README.md): original x64 C#
  assemblies exercise reordered definitions, IL tokens, tiny/fat bodies and
  switches, generic signatures, arrays, modifiers, properties, events,
  attributes, and string-heap index widening/narrowing. Native-generated deltas
  cover isolated/combined flags, empty bases, reverse deltas and default flags.
  All 70 targets match native output byte for byte in the portable Rust tests.
- [PE32 and legacy managed fixtures](fixtures/pa30-pe32-native/README.md):
  250 native-generated cases cover the same five original assembly families
  compiled for AnyCPU/x86 with legacy type 2 and CLI4 type 16, and x64 with
  legacy type 8. Forward/reverse deltas cover isolated IL/metadata, combined
  and default flags, including both string-index width transitions. Every
  declared native graph is checked; no RAW fallback is counted as coverage.
  An additional 28 unmanaged I386 cases exercise imports, HIGHLOW relocations,
  restored lock prefixes, x86 calls/jumps and shifted/rebased geometry. Ten
  native cases exercise the actual five-column legacy GenericParam schema with
  a nonzero coded constraint whose TypeDef row changes.
- [Rust-created PA30 native oracle](fixtures/pa30-created-native/README.md):
  native Windows `ApplyDeltaB` accepts all 22 Rust-created RAW patches and
  reproduces exact targets, including empty output, arbitrary managed PE32
  bytes, source/output matches, long lengths and 600,000/2,000,000/20,000,000-byte
  reference distances. Native header inspection confirms RAW type 1, zero
  flags/FILETIME and SHA-1 hashes. Regression tests regenerate every golden
  patch exactly; the two largest source buffers are regenerated from their
  documented original pattern rather than stored in the repository.
- [Rust-created MS-PATCH oracle](fixtures/lzxd-created-libmspack/README.md):
  independent pinned libmspack decodes 36 original vectors across all window
  orders 17 through 25, covering random odd-length literals, reference/output
  matches and frame boundaries. An additional cache-only 20 MB distant-reference
  case passes the independent decoder. These are LZX Delta streams, with no
  PA19/PA30 envelope or Windows patch-file packaging claim.
- [Rust-created PE oracle](fixtures/pa30-created-pe-native/README.md): 14
  patches from seven original/control I386/AMD64 pairs pass native `ApplyDeltaB`
  in both directions. Header-only, shifted sections, rebased images and
  2,048 varied absolute pointers with HIGHLOW/DIR64 relocations exercise flags
  zero, `0x20`, and I386 `0x21fe`. Native type/flags/hash/FILETIME and unchanged
  source hashes are retained, alongside RAW size comparisons. Regressions
  regenerate all 14 deltas exactly from their pinned inputs.

Regression tests also exercise every truncation of a native PA30 fixture,
wrong source/hash, forged sizes, parameter-memory limits, malformed Huffman
trees, unsupported transforms, padding/trailing input, truncated PE sources,
resource cycles/bounds, cross-section lookups, and bounded
malformed-input loops. Codec tests and file reconstruction do not replace the
separate Windows servicing and boot gates.

Run portable regression tests with `cargo test -p windows-delta --all-features
--locked`. The cache-dependent real SSU gate was also run successfully:

```sh
WINDOWS_DELTA_SSU5071_PATCH=/data/cache/pa30-ssu5071-inputs/0 \
  cargo test -p windows-delta --locked --test ssu real_ssu5071_raw_patch -- --ignored
WINDOWS_DELTA_SSU5071_DIR=/data/cache/pa30-ssu5071-inputs \
  cargo test -p windows-delta --locked --test ssu real_ssu5071_pe_chain -- --ignored
```

Validation also passed package tests for `windows-uup` and `caby`, the nested
`ms-compress` test suite, and Clippy with all targets/features and warnings denied.
The standalone command cross-compiled successfully with
`cargo xwin build --locked -p windows-delta --features cli --target
x86_64-pc-windows-msvc`; executing that Rust binary on Windows was not tested.

## Research and provenance

The PA30 format research is
[smilingthax/msdelta-pa30-format](https://github.com/smilingthax/msdelta-pa30-format/tree/cc0eb6fe9ea070f0425e2e9449e3fd4c9b2c2ca8),
pinned at `cc0eb6fe9ea070f0425e2e9449e3fd4c9b2c2ca8`. Its notes leave PE
transforms and rifts incomplete. Native fixtures resolved discrepancies between
the prose and its C experiments concerning short-match lengths, extended-slot
prefixes, and unused all-zero Huffman trees. The Rust implementation was written
independently; the research repository has no root license file and its C code
was not copied.

PE preprocessing and rifts were implemented independently from the Microsoft
PE specification and processing graphs/disassembly in the pinned native
MSDelta DLL. [PE research provenance](fixtures/pa30-pe-native/README.md)
records original inputs, isolated flag matrices and native experiment scripts;
the DLL and Microsoft update payloads remain cache-only. AMD64 instruction
decoding uses `iced-x86` 1.21 under its MIT license.

Managed parsing and transforms were independently implemented using
[ECMA-335](https://ecma-international.org/publications-and-standards/standards/ecma-335/)
and the pinned native CLI4 processing graph. `clrmeta` 0.1 was evaluated:
its raw-metadata API fits the existing PE parser, but its owned heaps/row vectors
and lack of configurable allocation budgets do not fit this decoder's input
limits. The runtime therefore uses checked byte slices and bounded layouts;
no CLR runtime or additional metadata dependency is required. The MSDelta
mapping rules remain custom code, independently tested against native output.

Microsoft primary references are
[MS-PATCH LZX Delta](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf)
(revision 14.1, 2025-08-19),
[CreateDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-createdeltab),
[ApplyDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab),
and [the SDK header](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/msdelta.h).
The [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
defines the executable structures used by preprocessing.
MSDelta API documentation is not a complete PA30 binary-format specification.

`windows-delta` inherits the workspace MIT license. Its `ms-compress` dependency
retains that crate's `LGPL-2.1-only AND LGPL-2.1-or-later` license declaration.
The independent libmspack oracle is LGPL-2.1; its source is not redistributed in
the new fixtures. Preserve dependency license obligations when distributing
combined artifacts.

### Managed PA30 creation (2026-10-04)

`create_pa30_pe` and `--pe` also create pure IL managed CLI4 graphs (I386 16,
AMD64 32; file-type set 245). The encoder serializes target metadata geometry,
three heap maps, GUID maps and named metadata row maps. Ambiguous names retain
identity mappings. IL, metadata and combined normalization join the PE
candidates; each generated patch must reconstruct the exact target. Mixed-mode
and ReadyToRun creation are covered by eight native-verified PA30/PA31 fixtures
that regenerate byte-for-byte in the host regression tests. Small assemblies can produce larger
patches than RAW because of preprocessing overhead.

All 36 original managed forward/reverse patches pass native Windows application
across AnyCPU, x86 and x64, including signatures, attributes, heap-width changes
and header controls. The native dictionary oracle also establishes a private
rule: StandAloneSig local signatures normalize only the first local variable.
See [managed creation evidence](fixtures/pa30-created-cli-native/README.md).

### PA31 and current Windows payload modes (2026-10-04)

`inspect_pa31`, `apply_pa31`, `create_pa31` and `create_pa31_pe` are available
in `windows_delta::pa30`. CLI creation/application accept `--format pa31`;
inspection and PSF reconstruction select PA30/PA31 from each stream signature.
PA31 nests the common header in a bounded buffer and adds three fields and an
optional source digest. The first two fields are opaque; the third accepts
native values 0/1. Unknown flags and invalid field values fail explicitly.
Creation uses SHA-256 for both source and target, zero FILETIME, and the same
bounded PLZX encoder and PE/managed candidates as PA30.

Modern PA30/PA31 decoding also handles bit-25 binary differences compressed
with Windows Compression API LZMS framing. Empty-source streams contain target
bytes; source-dependent streams use interleaved signed controls, byte additions
and literal runs. Every chunk, decoded size and workspace is bounded. Reverse
playback handles source copies, deleted literals and byte restoration records,
including XPRESS-Huffman compressed deletes and Windows' extended 32-bit lengths.

The supplied `Windows11.0-KB5043080-x64.psf` reconstructs all 26,357 outputs
(414,035,568 bytes) in Rust with CIX source/output SHA-256 checks: 25,735 RAW
ranges, 247 PA30 streams and 375 PA31 streams. File 739's modern flags and
file 13469's incomplete Huffman table are covered. Incomplete prefix-free
tables are supported; oversubscribed or overlapping codes are rejected.
Four original native adaptive vectors independently exercise incomplete tables.

Native creation accepts all 18 retained Rust PA31 patches, including RAW,
unmanaged and managed inputs. Fourteen native reverse blobs reconstruct old
sources exactly, including a 70,000-byte compressed deleted tail. Original
ReadyToRun assemblies built with .NET 8 crossgen2 and original mixed IL/native
assemblies pass 80 native flag-isolated decoder cases and eight Rust-created
patches. This validates byte reconstruction; these fixtures were not installed
or executed as applications. See [PA31 native vectors](fixtures/pa31-native/README.md),
[creation vectors](fixtures/pa31-created-native/README.md) and
[mixed/ReadyToRun images](fixtures/pa30-managed-native-images/README.md).

### Architecture transforms and producer compatibility

Thumb ARM normalization handles wide branches, paired MOV/MOVT addresses and
pdata. ARM64 handles PC-relative branches, ADRP/address instruction state and
pdata. IA64 handles GP-relative and bundle branch operands plus all three
pdata words. Fixed-width operands, function ranges and repeated traversal work
are bounded. Native ARM MOV32T and IA64 IMM64 relocation entries become inactive
(type zero); their operands are left for the instruction pass rather than
inventing a relocation transform absent from the native implementation.

IA64 headers have no producer version, but the older 19041 MSDelta normalizes
instruction/pdata dictionaries while current UpdateCompression ignores those
flags. Decoding tries at most two dictionaries and returns bytes only when the
declared target hash matches. IA64 creation uses header/relocation candidates
that interoperate with both producers. Native decoding covers 24 ARM/ARM64
PA30 cases, 36 ARM/ARM64/IA64 PA31 cases, and 32 IA64 producer/relocation cases.
All 12 Rust-created architecture patches pass native application. The retained
ARM source-copy probe also verifies the entire normalized dictionary byte for
byte. See [architecture evidence](fixtures/pa30-arm-native/README.md).

The native DLL accepts empty uncompressed BSDiff streams and rejects nonempty
ones, even though header inspection accepts their flags. Rust follows that
behavior with an invalid-input error. Similarly, third extended-header values
above 1 are rejected by the native parser; they are not guessed as new formats.
Unknown flag bits return an unsupported-feature error before reconstruction.
