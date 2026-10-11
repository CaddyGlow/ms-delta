# ms-delta

Standalone Rust library and optional `ms-delta` CLI. All dependencies resolve
from crates.io; no sibling checkout or Windows DLL is required for host tests.

Native Rust creation and reconstruction of individual file patches using
**PA30**, **PA31** and **MS-PATCH LZX Delta** streams, and reconstruction of legacy **PA19**. These work on Linux and Windows without `msdelta.dll`,
DISM, Wine, or an external decompressor. This library does not install Windows
packages or maintain the CBS component store.

PA30 supports RAW type 1, I386 PE types 2/16, AMD64 types 8/32, IA64 type 4,
Thumb ARM type 64 and ARM64 type 128, nonempty rift
tables, PE source preprocessing, target E8 restoration, default/composite
Huffman parameters, source/output/repeat matches, extended offsets, and target
MD5/SHA-1/SHA-256 verification. PE preprocessing covers marking, imports,
exports, resources, relocations, x86 calls/jumps/lock prefixes, AMD64 instruction
operands/pdata, unbinding, and source header normalization. Legacy and CLI4
preprocessing handles metadata columns,
heap/row maps, signatures, IL tokens, and compression geometry across index-width
changes, including PE32 AnyCPU assemblies. Unsupported machine variants fail explicitly; header inspection exposes metadata.

Legacy **PA19** (the `mspatcha.dll` PatchAPI format, e.g. Defender `mpengine.dll._p`
engine patches) is decoded by `ms_delta::pa19::{inspect_pa19, apply_pa19}` and created
by `create_pa19`/`create_pa19_with`; the container, normalization, transform passes,
interleave tables and LZX stream are described in the `pa19` module docs. The decoder covers
header parsing with the patch CRC trailer, old-file alternatives selected by size and CRC,
ignore and retain ranges, PE32 source normalization (rebase, unbind, lock prefixes,
checksum), both rift transform pass orders (legacy, and the current order selected by header
options 0x100/0x200 including the absolute-pointer scan for images without a usable
relocation directory), the pass-disabling option bits, explicit window shifts, interleaved
LZX groups (header flag 0x40000000), and the chunked MS-PATCH LZX stream with Intel E8
translation, verifying the new-file CRC-32. Creation writes single-source patches with
verbatim fixed-tree LZX (2.2 to 4.4 times larger than `mspatchc.dll` output), optional window
order and interleave groups (`--window-order`, `--interleave-bytes`), Intel `E8` translation
(`--e8 off|on|auto`) and, for PE32 pairs, the PE-aware path (`--pe`: header COFF fields,
normalization, a generated rift table and the transform passes; the smallest of the PE and raw
candidates is kept). PE32+ and non-PE files are written as raw data because `mspatcha.dll`
transforms PE32 only. There is no encoder for ignore or retain ranges or several old files.

Evidence: READ from the Windows Server 2025 26100.32230 `mspatcha.dll` and `mspatchc.dll`
decompilation. OBSERVED on real data: 32 real `mpengine.dll._p` patches (1.1.26060.3008 to
1.1.26100.3, x86, x64 and arm64) parse with matching CRCs and 6 whose source engine was held
reconstruct the shipped target byte for byte; 514 patches created by the real `mspatchc.dll`
(`CreatePatchFileExW`) on a Windows 11 guest decode byte-identical (356 from synthetic data, x86
DLL pairs and 16 MB x86 engines: pass orders and every option bit, zeroed and unmapped
relocation directories, window shifts, ignore, retain and multiple old files, interleave maps
with up to 63 groups; 158 from 70 x86 and 70 x64 DLL pairs between two Windows builds and
18 engine pairs of x86, x64 and arm64); and 635 patches created by this crate (raw data, PE32
pairs with the generated rift, `E8` translation including `E8` bytes at every offset around
chunk boundaries, PE32+ pairs, interleaved groups, 16 to 19 MB engines of all three
architectures) were applied by the real `mspatcha.dll` to the exact target. For 70 x86 DLL
pairs the automatic creation totals 0.64 of the raw size (64 of 70 strictly smaller) and
2.9 times the size of `mspatchc.dll` output. `tests/pa19_fixtures.rs` runs 9 of the
`mspatchc.dll` patches on synthetic files committed in `tests/fixtures/pa19/`;
`tests/pa19_create_pe.rs` covers `E8` and PE creation on synthetic images; the gated tests
`WINDOWS_DELTA_PA19_DIR` (real engine patches) and `WINDOWS_DELTA_PA19_ORACLE` (the oracle
directory of guest-created patches and real file pairs) need Microsoft files that are not
committed. Not validated: other `mspatchc.dll` versions, a nonzero target time in a created
header, rift quality beyond the pairs above (any rift is valid, a poor one only costs size).

Creation uses a RAW PA30 graph with a SHA-1 target hash, source/output matches,
default Huffman parameters and a zero FILETIME. PE and managed input bytes are
accepted as RAW data. Optional `--pe` creation handles matching unmanaged or pure IL managed
supported PE pairs, generating source/target RVA maps and comparing header,
relocation and combined normalization candidates. It chooses the smallest PE
patch; it can still be larger than RAW for small files because of preprocessing
overhead. Managed creation emits CLI4 graphs, heap maps and unambiguous named
row maps, and compares IL, metadata and combined normalization candidates.
Matching mixed-mode and ReadyToRun I386/AMD64 pairs are also covered by native
fixtures; eight Rust-created PA30/PA31 patches passed retained Windows application checks.
MS-PATCH creation uses verbatim
blocks with fixed complete Huffman trees, source/output matches and disabled
Intel preprocessing. These deterministic encoders can produce larger patches
than Microsoft's adaptive encoders, and random data can expand.

MS-PATCH support decodes chunk-prefixed LZX Delta with reference data,
verbatim/aligned/uncompressed blocks, extended lengths, and optional Intel E8
translation. Its target size and window order come from the caller. LZX Delta
and PA30 have different framing and bitstreams; they are not interchangeable.

## Cargo features

Defaults enable `all-formats` and `serde`, preserving the full library API.
Use `default-features = false` to select only the formats you need:

```toml
ms-delta = { version = "0.1", default-features = false, features = ["pa30"] }
```

| Feature | Enables |
| --- | --- |
| `lzxd` | MS-PATCH LZX Delta creation and reconstruction |
| `pa19` | PA19 inspection, creation and reconstruction; includes `lzxd` |
| `pa30` | PA30 inspection, creation and reconstruction, including PE and managed transforms |
| `pa31` | PA31 envelopes and reverse playback; includes the shared `pa30` engine |
| `all-formats` | All four format features |
| `serde` | Serialization of enabled formats' inspection metadata |
| `cli` | Complete command-line tool; includes `all-formats` and `serde` |

With no features, only `Limits`, `Error`, and `Result` remain, with no normal
third-party dependencies. Every configuration requires `std`. Formats include
both creation and reconstruction; transform and hash support stays together
with the format so selecting it preserves its complete validated behavior.
PA31 APIs remain under `ms_delta::pa30` for compatibility.

Compression algorithms live in `ms-compress`; patch containers, integrity checks,
and executable transforms live here. The `ms-compress` dependency disables defaults:
`lzxd` (and therefore `pa19`) enables only LZX, while `pa30` (and therefore `pa31`)
enables LZMS and XPRESS. Enabling every patch format still excludes unrelated codecs.

## Releases

Install the CLI from crates.io with `cargo install ms-delta --features cli --locked`.
Tags matching the Cargo version run Linux/Windows tests and the feature matrix,
verify the crate package, publish it to crates.io, and attach the `.crate` archive
and SHA-256 checksum to the GitHub release. The release environment supplies
`CARGO_REGISTRY_TOKEN` through a GitHub Actions secret.

## Library

```rust
use ms_delta::{Limits, pa30::{apply_pa30, inspect_pa30}};

# fn example(delta: &[u8], source: &[u8]) -> ms_delta::Result<()> {
let limits = Limits::default();
let metadata = inspect_pa30(delta, &limits)?;
let target = apply_pa30(source, delta, &limits)?;
assert_eq!(target.len(), metadata.target_size);
# Ok(())
# }
```

`ms_delta::apply_lzxd(source, delta, target_size, window_order, limits)`
reconstructs MS-PATCH data. `window_order` must be 17 through 25; reference data
must fit within the corresponding window minus three bytes. Supply an
independently expected hash when the containing format provides one.

`ms_delta::pa30::create_pa30(source, target, limits)` and
`ms_delta::create_lzxd(source, target, window_order, limits)` return new
encoded patches. LZXD callers retain the target size and window order separately.
`ms_delta::pa30::create_pa30_pe(source, target, limits)` creates an
PE graph (I386 type 2 or AMD64 type 8), or pure IL CLI4 graph (types 16/32),
rejecting mixed managed/unmanaged pairs and architecture mismatches.

## Commands

```sh
cargo run -p ms-delta --features cli -- inspect --delta patch.pa30
cargo run -p ms-delta --features cli -- apply \
  --format pa19 --source mpengine.dll --delta old_to_new.dll._p --output new.dll
cargo run -p ms-delta --features cli -- create \
  --format pa19 --pe --e8 auto --source old.dll --target new.dll --output new.dll._p
cargo run -p ms-delta --features cli -- create \
  --format pa30 --source original.bin --target target.bin --output patch.pa30
cargo run -p ms-delta --features cli -- create \
  --format pa30 --pe --source original.exe --target target.exe --output patch.pa30
cargo run -p ms-delta --features cli -- create \
  --format lzxd --source original.bin --target target.bin --output patch.lzxd \
  --window-order 17
cargo run -p ms-delta --features cli -- apply \
  --format pa30 --source original.bin --delta patch.pa30 --output target.bin
cargo run -p ms-delta --features cli -- apply \
  --format lzxd --delta patch.lzxd --output target.bin \
  --target-size 4096 --window-order 17
```

The main `windows-uup` CLI exposes the same arguments as `delta-inspect`,
`delta-create` and `delta-apply`.

Omitting `--source` supplies an empty source. `--expected-sha256` checks an
additional target hash. Commands preserve inputs and publish a new output only
after reconstruction and checks; existing output files and symlinks are refused.
Creation verifies the patch against the target before publishing it.

Defaults bound each input and the output to 64 MiB, history distance/window to
32 MiB, and each retained PA30 parameter/table/workspace budget to 8 MiB. These
independent budgets are not an aggregate process-memory ceiling. Library callers can set separate
patch/source limits. CLI flags are `--max-input-bytes`, `--max-output-bytes`,
`--max-window-bytes`, and `--max-parameter-bytes`.

See [format research and validation](docs/windows-delta.md) for native
oracle evidence, current limitations, and source/license provenance.

PA31 APIs live beside PA30 in `ms_delta::pa30`: `inspect_pa31`, `apply_pa31`,
`create_pa31` and `create_pa31_pe`. Use `--format pa31` with create/apply;
inspect recognizes either signature. Creation includes SHA-256 source and target
hashes. Modern PA30/PA31 LZMS/BSDiff reconstruction and PA31 reverse playback are
supported, including Windows XPRESS-Huffman compressed reverse literals.

## Build and test

```sh
cargo test --all-features --locked
cargo test --no-default-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
cargo build --features cli --release --locked
```

The `cli` feature enables the command-line tool and reusable CLI argument types.
The library uses `std`. The pinned Nix development shell is available through
`nix develop`; Rust 1.99 is also specified in `rust-toolchain.toml`.

Checked-in fixtures support portable regression tests. Native Windows oracle
replay and cache-dependent SSU/PA19 tests remain separate gates; the existing
`WINDOWS_DELTA_*` environment variables retain their names.
