//! Legacy PA19 patches, the format read by `mspatcha.dll` `ApplyPatchToFileByHandles`.
//!
//! PA19 is the PatchAPI format that predates MSDelta (PA30). It is used for
//! the `mpengine.dll._p` patches inside Microsoft Defender engine update
//! packages, which `MpSigStub.exe` hands to `mspatcha.dll` when a patch file
//! does not start with `MPSP`. PA30/PA31 are unrelated formats.
//!
//! # Format description
//!
//! Evidence labels: READ means read from the decompilation of Windows Server
//! 2025 build 26100.32230 `mspatcha.dll` (`DecodePatchHeader`,
//! `ApplyPatchToFileByBuffers`, `CreateNewFileBufferFromPatchData`,
//! `ApplyRawLzxPatchToBuffer`, `LZX_Decode*`, `NormalizeCoffImage`,
//! `TransformCoffImage` and the `TransformOldFile_PE_*` helpers). OBSERVED
//! means measured on the 32 real `mpengine.dll._p` patches (see the crate
//! README for which were applied). INFERRED is stated explicitly.
//!
//! ## Container
//!
//! All integers are little endian. `uvar` and `svar` are the PatchAPI
//! variable-length integers (READ): bytes are taken low group first and the
//! LAST byte of a number has bit 7 SET (the opposite of LEB128). `uvar`
//! carries 7 bits per byte and `svar` carries a sign in bit 6 and 6 data bits
//! in its first byte (sign-magnitude, bit 6 set means negative), then 7 bits
//! per following byte. Both read at most 5 bytes; bits above 32 are lost.
//!
//! ```text
//! +0   "PA19"                         (any other "PAnn" with nn <= 19 is
//!                                       "bad format", others "unsupported")
//! +4   u32 stored_flags               f = stored_flags XOR 0x00800000
//!      f must satisfy f & 0x3F00FFF8 == 0; low bits 0x3 must not both be 0
//!      to apply (bit 0x4 raises the maximum default LZX window from 8 MiB
//!      to 32 MiB); the remaining bits, as decoded in order below:
//!        0x80000000  an options u32 follows
//!        0x00800000  CLEAR: a u32 target time follows (seconds since 1970)
//!        0x00040000  CLEAR: COFF fields follow
//!        0x00400000  CLEAR: resource time follows
//!        0x40000000  per-source interleave tables follow (see below)
//!        0x00010000  do not unbind the source image
//!        0x00020000  do not smash lock prefixes in the source image
//!        0x00200000  zero (rather than recompute) the PE checksum
//!      options (only present if f bit 31): mask 0xFFFEFCC0 must be 0, so
//!      only 0x3F (disable relocation/import/export/jump/call/resource
//!      transform passes), 0x100/0x200 (newer pass order) and 0x10000
//!      (explicit window) are legal.
//! if f & 0x80000000: u32 options
//! if !(f & 0x00800000): u32 time
//! if !(f & 0x00040000): u16 coff_base_high   (coff_base = value << 16)
//!                       time != 0 ? svar d : u32 raw ; coff_time = time - d
//! if !(f & 0x00400000): coff_time != 0 ? svar d : u32 raw ;
//!                       resource_time = coff_time - d
//! uvar new_size
//! u32  new_crc32                       zlib CRC-32 of the reconstructed file
//!                                      before any retain ranges are pasted
//! if options & 0x10000: u8 window_shift   (<= 31; window = 1 << shift)
//! u8   source_count                    one "old file" alternative each
//! source_count times:
//!     svar  old_size - new_size
//!     u32   old_crc32                  CRC-32 of the old file after the
//!                                      normalization described below
//!     u8    ignore_count               (svar delta, uvar length) pairs;
//!                                      offset = previous end + delta
//!     u8    retain_count               (svar old_delta, svar new_minus_old,
//!                                      uvar length) triples
//!     uvar  rift_count                 (uvar old_delta, svar new_delta) pairs
//!                                      accumulating to (old_rva, new_rva)
//!     if f & 0x40000000: uvar group_count and 2/3 svar per group
//!     uvar  patch_size                 bytes of LZX data for this source
//! source LZX streams follow back to back (patch_size each), then
//! u32  trailer = !crc32(everything before the trailer)  (READ: the register
//!      value of the PatchAPI CRC, which is non-complemented)
//! ```
//!
//! Header sizes are bounds-checked by `mspatcha.dll` (ranges inside the old and
//! new file). The patch is applied only if one `source` matches the supplied
//! old file: `old_size` equal, and the CRC of the normalized old file equal.
//!
//! ## Old-file normalization (READ)
//!
//! Before the CRC test the old file is modified exactly as the producer
//! modified it (retain-range bytes are saved first): PE32 images (magic
//! 0x10B only; PE32+ and non-PE data are untouched) get the COFF TimeDateStamp
//! and ImageBase replaced by `coff_time`/`coff_base` and are rebased through
//! the relocation table; bound imports are removed (bound import directory
//! zeroed, thunk table copied over the IAT, `.idata` made writable); lock
//! prefix table targets are rewritten to `F0`; the PE checksum is recomputed
//! (or zeroed). Ignore and retain ranges are then zeroed. If the source count
//! and `new_size` equal the old size and the normalized old file already has
//! the `new_crc32`, the normalized old file is the result (no stream).
//!
//! ## Rift transform (READ, OBSERVED)
//!
//! A non-empty `rift` table makes `mspatcha.dll` transform the normalized old
//! PE32 image into the layout the new image will have: relocations, imports,
//! exports, near jumps and calls and resource directories are rewritten
//! through the rift (a piecewise-constant RVA delta), with a byte map that
//! keeps data and header bytes untouched. A source file that is not PE32 is
//! used unchanged. Header `options` bits `0x1`, `0x2`, `0x4`, `0x8`, `0x10`
//! and `0x20` disable the relocation, import, export, relative-jump,
//! relative-call and resource passes; the legal option bits are those six,
//! `0x100`, `0x200` and `0x10000` (explicit window shift). Two pass orders
//! exist, selected by options `0x100` or `0x200` (either one selects the
//! current order; `TransformCoffImage`):
//!
//! - legacy (neither bit): mark non-executable bytes (a directory is marked
//!   even when its RVA maps to file offset 0), relocations (rebuilt, sorted by
//!   new RVA), imports, exports, `E8`/`0F 8x` jumps (narrowed to `EB`/`7x` when
//!   the displacement now fits), `E8` calls, resources through the
//!   "old compatible" walker (leaf data entries add their size to the byte
//!   budget);
//! - current (`0x100` and/or `0x200`): mark (a directory whose RVA maps to
//!   offset 0 is not marked), imports, exports, resources through the current
//!   walker (leaf entries add nothing to the budget, a bad leaf or subdirectory
//!   offset only sets an error flag, a child that exhausts the budget ends every
//!   enclosing directory), relocations, jumps, calls. With `0x200` the
//!   relocation pass runs only if the base relocation directory maps wholly
//!   inside the file; otherwise, for an x86 image, every dword at or after
//!   `SizeOfHeaders` whose value lies in `(ImageBase, ImageBase + SizeOfImage)`
//!   and whose mark bits do not contain `0x02` is marked `0x01` and moved
//!   through the rift (a scan for absolute pointers), advancing four bytes after
//!   a hit and one otherwise.
//!
//! ## LZX stream (READ, OBSERVED)
//!
//! Each source's stream is the MS-PATCH "LZX Delta" format: consecutive
//! chunks, each a u16 byte count and that many bytes, each decoding to exactly
//! 32768 bytes (the last may be shorter). The old file (after the transforms)
//! is the pre-loaded history before output position 0 and a match can reach
//! back into it. The window is 1 << window_shift if given, else the smallest
//! power of two from 128 KiB up that is at least
//! `new_size + round_up(old_size, 32768)`, capped at 8 MiB (32 MiB when flag
//! 0x4 is set). The first chunk begins with a 1-bit Intel `E8` translation
//! flag followed, if set, by a 32-bit translation size. `E8` translation
//! applies to the first 0x8000 chunks only. Without interleave tables the
//! first `min(old size, window)` bytes of the old file are preloaded; a match
//! distance is at most `window - 3`, so only the last `window - 3` of those
//! bytes can be referenced.
//!
//! ## Interleave tables (flag 0x40000000; READ, OBSERVED)
//!
//! A source with interleave tables splits its stream into groups. Each group
//! is an independent LZX decode: the tree, repeated-offset and `E8` state is
//! reset (`LZX_DecodeNewGroup`; the first chunk of the group carries the `E8`
//! header again), and the history is a slice of the transformed old file. The
//! group outputs follow each other and the chunk stream is continuous. The
//! table is `uvar` group count, then per group `svar d1`, `svar d2` and, for
//! every group but the last, `svar d3`:
//! `A += d1; B += d2; old_offset += A; old_length += B` (running sums of
//! running sums, from zero) and `new_length += d3 << 15` (non-last groups; the
//! last group produces what remains of the new file). Each slice must lie
//! inside the old file. `mspatchc.dll` writes a default map (about `window - 3`
//! bytes of old file per group, 32768-aligned new lengths) when
//! `PATCH_OPTION_INTERLEAVE_FILES` is set and the files do not fit the window
//! (`MaxLzxWindowSize` of `PATCH_OPTION_DATA` lowers the window), or the caller
//! supplies `InterleaveMapArray`.
//!
//! ## Differences from `mspatcha.dll` in this implementation
//!
//! Where `mspatcha.dll` reads outside its buffers or raises its PE format
//! exception, this module returns [`Error::Invalid`]. It additionally requires
//! patch sizes to add up exactly, checks the new-file CRC when a source has no
//! stream, and rejects trailing bytes after a stream. The LZX history of a
//! group is limited to `window - 3` bytes (see above).
//!
//! ## Creation
//!
//! [`create_pa19`] and [`create_pa19_with`] write single-source patches without ignore or retain
//! ranges. The LZX stream comes from the crate's fixed-tree encoder (`create_lzxd`), so patches
//! are about 2.2 to 4.4 times larger than `mspatchc.dll` output on the same pairs (OBSERVED
//! below); they are valid for the real `mspatcha.dll`. Every candidate is applied with
//! [`apply_pa19`] before it is returned. Options ([`Pa19CreateOptions`]):
//!
//! - **Window and interleave**: explicit window shift (option bit 0x10000) and interleave groups
//!   ([`plan_interleave`]).
//! - **Intel `E8` translation** ([`Pa19E8`]): the first LZX chunk carries the flag and the
//!   translation size (the new file size, as in `mspatchc.dll` output). The target is translated
//!   chunk by chunk before it is encoded, so matches see the translated bytes just as the decoder's
//!   history does; the translation is the exact inverse of the decoder's: positions up to the last
//!   ten bytes of each 32768-byte chunk are scanned, an `E8` operand `rel` with
//!   `-pos <= rel < size` becomes `rel + pos` (or `rel - size` when it is at least `size - pos`),
//!   five bytes are skipped after every `E8`, and only the first 0x8000 chunks of a group are
//!   translated. `Auto` builds both and keeps the smaller patch (skipped for targets with fewer
//!   than 32 `E8` bytes).
//! - **PE32 awareness** ([`Pa19Pe`]), only when both files are PE32 images with a 64 KiB-aligned
//!   target `ImageBase`: the header carries a time field (zero), `coff_base` and `coff_time` of the
//!   new image, no resource time (flags as `mspatchc.dll` writes them: decoded `0x400001`, unbind
//!   and lock-prefix smashing on), and a rift table; the old image is normalized and transformed
//!   with the same code the decoder runs, and the stream is encoded against that history. The rift
//!   generator is this crate's own (INFERRED to differ from `mspatchc.dll`'s): per pair of
//!   same-named sections it finds unique 8-byte anchors, keeps the heaviest chain increasing in
//!   both files and emits a step wherever the new-minus-old shift changes for a run of at least 16
//!   matching bytes. Candidates with several run thresholds (one for images over 4 MiB) are built
//!   and the smallest patch wins, next to the raw path.
//! - **PE32+ and other files** take the raw path: `mspatcha.dll` normalizes and transforms PE32
//!   only (READ), and `mspatchc.dll` writes PE32+ patches with decoded flags `0x440001` (no COFF
//!   fields), options 0 and an empty rift (OBSERVED on 70 x64 DLL pairs and 12 x64 and arm64
//!   engine pairs). No other PE32+ treatment (timestamp, checksum) exists in the format.
//!
//! The transform options are 0 (legacy order) without `E8` and 0x10 (call pass disabled, the
//! `E8` translation handles calls) with it, as `mspatchc.dll` pairs them (OBSERVED: its patches
//! with the `E8` flag on small x86 DLLs always carry option 0x10, and x86 engines too). The
//! `E8` choice in `mspatchc.dll` looks like a trial by size (INFERRED: on 70 small x86 pairs 4
//! chose it, on the 16 MB x86 and 18 MB x64 engines all 12 did, on arm64 none of 6 did).
//!
//! ## Validation (OBSERVED, Windows 11 10.0.26100.7920 guest, 2026-10-05)
//!
//! - 32 real `mpengine.dll._p` engine patches parse; six applied byte-identical
//!   to the shipped engines (x86 with rift tables, x64, arm64).
//! - 356 patches created by the real `mspatchc.dll` (`CreatePatchFileExW`) from
//!   synthetic data and from x86 system DLL pairs (two builds) and the x86
//!   Defender engines (16 MB) decode byte-identical, with: legacy and current
//!   pass orders (options `0x100`, `0x200`, `0x300`, every pass-disabling
//!   bit, combinations), a missing, zeroed or unmapped relocation directory
//!   under `0x200` (the pointer scan), `LZX_A`/`LZX_B`/`LARGE`, no-timestamp,
//!   no-rebase, no-bindfix, no-lockfix, no-checksum and no-resource-time
//!   flags, explicit window shifts (`MaxLzxWindowSize`), ignore ranges, retain
//!   ranges, three old-file alternatives, an old file equal to the new file,
//!   and interleave maps (default maps with 4 to 63 groups on 16 MB engines,
//!   explicit maps, windows from 128 KiB to 8 MiB).
//! - 158 more `mspatchc.dll` patches decode byte-identical: 70 x86 (PE32) and 70 x64 (PE32+)
//!   system DLL pairs between two builds (Windows 11 26100.7920 on the guest, Server 2025
//!   26100.32230 from the install image) and 6 engine pairs each of x86, x64 and arm64 (all
//!   ordered pairs of three engine versions, 16 to 19 MB).
//! - Patches made by this crate and applied by the real `mspatcha.dll`
//!   (`ApplyPatchToFileW`), each reproducing the target byte for byte: 30 raw, PE and interleaved
//!   patches (first round), then 605 with `E8` and PE awareness: 70 (14 x86 DLL pairs in the
//!   modes PE, PE with `E8` on, PE with `E8` auto, raw, raw with `E8`), 79 `E8` patches on code-like
//!   data (25 sizes from 1 byte to 300 KB around the 32768-byte chunk boundaries, `E8` bytes with
//!   in-range operands at every offset from 14 bytes before to 2 after each boundary, policies on,
//!   auto and off, three interleaved groupings, an empty old file), 420 (70 x86 and 70 x64 DLL
//!   pairs in the modes PE, PE with `E8` auto and raw; on x64 the PE modes take the raw path) and
//!   36 on the 18 engine pairs. Sizes: for the 70 x86 pairs the automatic patches total 7,054,054
//!   bytes against 11,027,211 raw (0.64) and 2,427,204 from `mspatchc.dll`, and 64 of 70 are
//!   strictly smaller than raw; for the x64 pairs 14,076,276 against 14,465,298 raw (0.97; `E8`
//!   helps there) and 3,181,001; on the engines 2.2 to 2.4 times `mspatchc.dll`.
//! - Mutation check (OBSERVED): writing the `E8` flag but skipping the translation in the encoder
//!   makes every created `E8` patch fail this crate's own round-trip verification, so the
//!   translation is exercised, not vacuous (`tests/pa19_create_pe.rs` covers the policies and the
//!   chunk-boundary cases without Microsoft files).
//! - Not validated: patches from other `mspatchc.dll` versions; the rift generator beyond the
//!   pairs above (any rift is valid because the transform is deterministic, so a poor table
//!   only costs size); PE32 pairs larger than 16 MB with a useful rift (on the engines the PE path
//!   gains nothing over raw with `E8`); a nonzero target time in the header (the creator writes 0,
//!   accepted by `mspatcha.dll` in all PE patches above).

use crate::{Error, Limits, Result};

mod pe;
mod rift;

const MAGIC: &[u8; 4] = b"PA19";
const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

/// Standard (zlib) CRC-32.
fn crc32(data: &[u8]) -> u32 {
    let mut register = 0xffff_ffffu32;
    for byte in data {
        register = CRC_TABLE[usize::from((register as u8) ^ byte)] ^ (register >> 8);
    }
    !register
}

/// A byte range of the old file that is zeroed before the old-file CRC test.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Pa19IgnoreRange {
    /// Offset in the old file.
    pub offset: u32,
    /// Length in bytes.
    pub length: u32,
}

/// A range preserved across patching: copied out of the old file and pasted into the new file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Pa19RetainRange {
    /// Offset in the old file.
    pub old_offset: u32,
    /// Length in bytes.
    pub length: u32,
    /// Offset in the new file.
    pub new_offset: u32,
}

/// One interleave group of a source: an independent LZX decode whose history is a slice of the
/// old file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Pa19InterleaveGroup {
    /// Offset of the old-file slice.
    pub old_offset: u32,
    /// Length of the old-file slice.
    pub old_length: u32,
    /// Output bytes produced by the group.
    pub new_length: u32,
}

/// One old-file alternative carried by a PA19 patch.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Pa19Source {
    /// Required old file size.
    pub old_size: usize,
    /// CRC-32 of the normalized old file.
    pub old_crc32: u32,
    /// Ranges zeroed before the CRC test.
    pub ignore_ranges: Vec<Pa19IgnoreRange>,
    /// Ranges preserved from the old file.
    pub retain_ranges: Vec<Pa19RetainRange>,
    /// Number of rift entries.
    pub rift_entries: usize,
    /// Number of interleave groups (zero when the header has no interleave tables).
    pub interleave_groups: usize,
    /// Interleave groups: the old-file slice each independent LZX group sees and how many
    /// output bytes the group produces. Empty without interleave tables.
    pub interleave: Vec<Pa19InterleaveGroup>,
    /// Size of the LZX stream for this alternative.
    pub patch_size: usize,
}

/// Metadata carried by a PA19 header. Inspection does not apply a patch.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Pa19Info {
    /// Decoded header flags (stored flags XOR 0x800000).
    pub flags: u32,
    /// Option bits; zero when the header carries none.
    pub options: u32,
    /// Target time in seconds since 1970, if present.
    pub target_time: Option<u32>,
    /// COFF ImageBase imposed on the old image, or zero.
    pub coff_base: u32,
    /// COFF TimeDateStamp imposed on the old image, or zero.
    pub coff_time: u32,
    /// Resource directory timestamp imposed on the old image, or zero.
    pub resource_time: u32,
    /// Declared reconstructed size.
    pub target_size: usize,
    /// CRC-32 of the reconstructed file.
    pub target_crc32: u32,
    /// Explicit LZX window size, if the header carries one.
    pub window_size: Option<usize>,
    /// Old-file alternatives.
    pub sources: Vec<Pa19Source>,
    /// Size of the header in bytes.
    pub header_size: usize,
}

struct Parsed {
    info: Pa19Info,
    rifts: Vec<Vec<(u32, u32)>>,
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn bytes(&mut self, count: usize) -> Result<&[u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error::Invalid("PA19 header is truncated"))?;
        let slice = self
            .data
            .get(self.position..end)
            .ok_or(Error::Invalid("PA19 header is truncated"))?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn uvar(&mut self) -> Result<u32> {
        let (mut value, mut shift) = (0u32, 0u32);
        loop {
            let byte = self.u8()?;
            value |= u32::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 != 0 || shift >= 32 {
                return Ok(value);
            }
        }
    }

    fn svar(&mut self) -> Result<i32> {
        let first = self.u8()?;
        let mut value = u32::from(first & 0x3f);
        let mut shift = 6u32;
        if first & 0x80 == 0 {
            loop {
                let byte = self.u8()?;
                value |= u32::from(byte & 0x7f) << shift;
                shift += 7;
                if byte & 0x80 != 0 || shift >= 32 {
                    break;
                }
            }
        }
        let value = value as i32;
        Ok(if first & 0x40 != 0 {
            value.wrapping_neg()
        } else {
            value
        })
    }

    /// A count of items that each need at least `minimum` further header bytes.
    fn count(&mut self, minimum: usize, limits: &Limits) -> Result<usize> {
        let count = self.uvar()? as usize;
        let remaining = self.data.len() - self.position;
        if count > remaining / minimum || count.saturating_mul(8) > limits.max_parameter_bytes {
            return Err(Error::Limit("PA19 table size"));
        }
        Ok(count)
    }
}

fn parse(delta: &[u8], limits: &Limits) -> Result<Parsed> {
    if delta.len() > limits.max_patch_bytes {
        return Err(Error::Limit("PA19 patch size"));
    }
    if delta.len() < 12 || &delta[..4] != MAGIC {
        return Err(Error::Invalid("not a PA19 patch"));
    }
    let mut reader = Reader {
        data: &delta[..delta.len() - 4],
        position: 4,
    };
    let flags = reader.u32()? ^ 0x0080_0000;
    if flags & 0x3f00_fff8 != 0 {
        return Err(Error::Invalid("PA19 header flags are invalid"));
    }
    let options = if flags & 0x8000_0000 != 0 {
        let options = reader.u32()?;
        if options & 0xfffe_fcc0 != 0 {
            return Err(Error::Invalid("PA19 header options are invalid"));
        }
        options
    } else {
        0
    };
    let target_time = if flags & 0x80_0000 == 0 {
        Some(reader.u32()?)
    } else {
        None
    };
    let time = target_time.unwrap_or(0);
    let (mut coff_base, mut coff_time, mut resource_time) = (0u32, 0u32, 0u32);
    if flags & 0x4_0000 == 0 {
        coff_base = u32::from(reader.u16()?) << 16;
        coff_time = if time != 0 {
            time.wrapping_sub(reader.svar()? as u32)
        } else {
            reader.u32()?
        };
    }
    if flags & 0x40_0000 == 0 {
        resource_time = if coff_time != 0 {
            coff_time.wrapping_sub(reader.svar()? as u32)
        } else {
            reader.u32()?
        };
    }
    let target_size = reader.uvar()?;
    let target_crc32 = reader.u32()?;
    if target_size as usize > limits.max_output_bytes {
        return Err(Error::Limit("PA19 target size"));
    }
    let window_size = if options & 0x1_0000 != 0 {
        let shift = reader.u8()?;
        if shift > 0x1f {
            return Err(Error::Invalid("PA19 window shift is invalid"));
        }
        Some(1usize << shift)
    } else {
        None
    };
    let source_count = usize::from(reader.u8()?);
    let mut sources = Vec::with_capacity(source_count);
    let mut rifts = Vec::with_capacity(source_count);
    for _ in 0..source_count {
        let delta_size = reader.svar()?;
        let old_size_signed = (target_size as i32).wrapping_add(delta_size);
        if old_size_signed < 0 {
            return Err(Error::Invalid("PA19 old file size is negative"));
        }
        let old_size = old_size_signed as u32;
        let old_crc32 = reader.u32()?;
        let ignore_count = usize::from(reader.u8()?);
        let mut ignore_ranges = Vec::with_capacity(ignore_count);
        let mut previous = 0u32;
        for _ in 0..ignore_count {
            let offset = previous.wrapping_add(reader.svar()? as u32);
            let length = reader.uvar()?;
            if offset > old_size || length > old_size - offset {
                return Err(Error::Invalid("PA19 ignore range exceeds the old file"));
            }
            ignore_ranges.push(Pa19IgnoreRange { offset, length });
            previous = offset.wrapping_add(length);
        }
        let retain_count = usize::from(reader.u8()?);
        let mut retain_ranges = Vec::with_capacity(retain_count);
        let mut previous = 0u32;
        for _ in 0..retain_count {
            let old_offset = previous.wrapping_add(reader.svar()? as u32);
            let new_offset = old_offset.wrapping_add(reader.svar()? as u32);
            let length = reader.uvar()?;
            if old_offset > old_size
                || length > old_size - old_offset
                || new_offset > target_size
                || length > target_size - new_offset
            {
                return Err(Error::Invalid("PA19 retain range exceeds a file"));
            }
            retain_ranges.push(Pa19RetainRange {
                old_offset,
                length,
                new_offset,
            });
            previous = old_offset.wrapping_add(length);
        }
        let rift_count = reader.count(2, limits)?;
        let mut rift = Vec::new();
        rift.try_reserve_exact(rift_count)
            .map_err(|_| Error::Allocation)?;
        let (mut old, mut new) = (0u32, 0u32);
        for _ in 0..rift_count {
            old = old.wrapping_add(reader.uvar()?);
            new = new.wrapping_add(reader.svar()? as u32);
            rift.push((old, new));
        }
        let mut interleave = Vec::new();
        if flags & 0x4000_0000 != 0 {
            let groups = reader.count(2, limits)?;
            interleave
                .try_reserve_exact(groups)
                .map_err(|_| Error::Allocation)?;
            let (mut a, mut b) = (0i32, 0i32);
            let (mut length, mut offset) = (0u32, 0u32);
            let (mut new_length, mut remaining) = (0u32, target_size);
            for index in 0..groups {
                a = a.wrapping_add(reader.svar()?);
                b = b.wrapping_add(reader.svar()?);
                length = length.wrapping_add(b as u32);
                offset = offset.wrapping_add(a as u32);
                if offset > old_size || length > old_size - offset {
                    return Err(Error::Invalid("PA19 interleave group exceeds the old file"));
                }
                if index + 1 < groups {
                    let step = (reader.svar()? as u32) << 15;
                    new_length = new_length.wrapping_add(step);
                    if new_length > remaining {
                        return Err(Error::Invalid("PA19 interleave groups exceed the new file"));
                    }
                    remaining -= new_length;
                } else {
                    new_length = remaining;
                }
                interleave.push(Pa19InterleaveGroup {
                    old_offset: offset,
                    old_length: length,
                    new_length,
                });
            }
        }
        let interleave_groups = interleave.len();
        let patch_size = reader.uvar()? as usize;
        sources.push(Pa19Source {
            old_size: old_size as usize,
            old_crc32,
            ignore_ranges,
            retain_ranges,
            rift_entries: rift_count,
            interleave_groups,
            interleave,
            patch_size,
        });
        rifts.push(rift);
    }
    Ok(Parsed {
        info: Pa19Info {
            flags,
            options,
            target_time,
            coff_base,
            coff_time,
            resource_time,
            target_size: target_size as usize,
            target_crc32,
            window_size,
            sources,
            header_size: reader.position,
        },
        rifts,
    })
}

/// Reads PA19 metadata and verifies the patch CRC trailer. Does not apply a patch.
pub fn inspect_pa19(delta: &[u8], limits: &Limits) -> Result<Pa19Info> {
    let parsed = parse(delta, limits)?;
    verify_trailer(delta)?;
    Ok(parsed.info)
}

fn verify_trailer(delta: &[u8]) -> Result<()> {
    let split = delta.len() - 4;
    let trailer = u32::from_le_bytes([
        delta[split],
        delta[split + 1],
        delta[split + 2],
        delta[split + 3],
    ]);
    if !crc32(&delta[..split]) != trailer {
        return Err(Error::Integrity("PA19 patch CRC"));
    }
    Ok(())
}

fn zeroed(size: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    buffer.resize(size, 0);
    Ok(buffer)
}

fn copied(data: &[u8]) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(data.len())
        .map_err(|_| Error::Allocation)?;
    buffer.extend_from_slice(data);
    Ok(buffer)
}

/// `SaveRetainRanges`: the bytes of each range, concatenated; out-of-range ranges give zeros.
fn save_retain(
    image: &[u8],
    ranges: &[Pa19RetainRange],
    by_new_offset: bool,
    limits: &Limits,
) -> Result<Vec<u8>> {
    let mut total = 0usize;
    for range in ranges {
        total = total
            .checked_add(range.length as usize)
            .filter(|total| *total <= limits.max_source_bytes)
            .ok_or(Error::Limit("PA19 retain ranges"))?;
    }
    let mut saved = zeroed(total)?;
    let mut cursor = 0usize;
    for range in ranges {
        let offset = if by_new_offset {
            range.new_offset
        } else {
            range.old_offset
        } as usize;
        let length = range.length as usize;
        if offset <= image.len() && length <= image.len() - offset {
            saved[cursor..cursor + length].copy_from_slice(&image[offset..offset + length]);
        }
        cursor += length;
    }
    Ok(saved)
}

fn paste_retain(image: &mut [u8], ranges: &[Pa19RetainRange], saved: &[u8]) {
    let mut cursor = 0usize;
    for range in ranges {
        let offset = range.new_offset as usize;
        let length = range.length as usize;
        if offset <= image.len() && length <= image.len() - offset {
            image[offset..offset + length].copy_from_slice(&saved[cursor..cursor + length]);
        }
        cursor += length;
    }
}

fn zero_ranges(image: &mut [u8], ranges: impl Iterator<Item = (u32, u32)>) {
    for (offset, length) in ranges {
        let (offset, length) = (offset as usize, length as usize);
        if offset <= image.len() && length <= image.len() - offset {
            image[offset..offset + length].fill(0);
        }
    }
}

fn default_window(flags: u32, old_size: usize, new_size: usize) -> usize {
    let wanted = new_size as u64 + ((old_size as u64 + 0x7fff) & !0x7fff);
    let maximum: u64 = if flags & 4 != 0 {
        0x200_0000
    } else {
        0x80_0000
    };
    let mut window: u64 = 0x2_0000;
    if wanted > window {
        window = maximum;
        while window >> 1 >= wanted {
            window >>= 1;
        }
    }
    window as usize
}

/// Applies a PA19 patch to the old file, verifying the patch CRC and the new file CRC.
///
/// The old file must match one of the patch's old-file alternatives (size and CRC
/// after normalization).
pub fn apply_pa19(source: &[u8], delta: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA19 source size"));
    }
    let parsed = parse(delta, limits)?;
    verify_trailer(delta)?;
    let info = &parsed.info;

    // Identity shortcut: the old file already is the new file after normalization.
    if source.len() == info.target_size
        && let Some(first) = info.sources.first()
    {
        let mut work = copied(source)?;
        let saved = save_retain(&work, &first.retain_ranges, true, limits)?;
        zero_ranges(
            &mut work,
            first
                .retain_ranges
                .iter()
                .map(|range| (range.new_offset, range.length)),
        );
        if crc32(&work) != info.target_crc32 {
            pe::normalize(&mut work, info.flags, info.coff_base, info.coff_time)?;
        }
        if crc32(&work) == info.target_crc32 {
            paste_retain(&mut work, &first.retain_ranges, &saved);
            return Ok(work);
        }
    }

    let mut stream_start = info.header_size;
    for (index, entry) in info.sources.iter().enumerate() {
        let stream_end = stream_start
            .checked_add(entry.patch_size)
            .filter(|end| *end <= delta.len() - 4)
            .ok_or(Error::Invalid("PA19 patch stream is truncated"))?;
        if entry.old_size == source.len() {
            let mut work = copied(source)?;
            let saved = save_retain(&work, &entry.retain_ranges, false, limits)?;
            pe::normalize(&mut work, info.flags, info.coff_base, info.coff_time)?;
            zero_ranges(
                &mut work,
                entry
                    .ignore_ranges
                    .iter()
                    .map(|range| (range.offset, range.length))
                    .chain(
                        entry
                            .retain_ranges
                            .iter()
                            .map(|range| (range.old_offset, range.length)),
                    ),
            );
            if crc32(&work) == entry.old_crc32 {
                return reconstruct(
                    info,
                    entry,
                    &parsed.rifts[index],
                    work,
                    &saved,
                    &delta[stream_start..stream_end],
                    limits,
                );
            }
        }
        stream_start = stream_end;
    }
    if stream_start + 4 != delta.len() {
        return Err(Error::Invalid("PA19 patch has trailing bytes"));
    }
    Err(Error::Integrity(
        "source file matches no old file in the PA19 patch",
    ))
}

fn reconstruct(
    info: &Pa19Info,
    entry: &Pa19Source,
    rift: &[(u32, u32)],
    mut work: Vec<u8>,
    saved: &[u8],
    stream: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>> {
    let target_size = info.target_size;
    let mut output;
    if target_size == 0 {
        return Ok(Vec::new());
    }
    if entry.patch_size == 0 {
        if work.len() != target_size {
            return Err(Error::Invalid(
                "PA19 source without a stream must match the target size",
            ));
        }
        if crc32(&work) != info.target_crc32 {
            return Err(Error::Integrity("PA19 target CRC"));
        }
        output = work;
    } else {
        if !rift.is_empty() {
            pe::transform(&mut work, info.options, info.resource_time, rift)?;
        }
        let window = match info.window_size {
            Some(window) => window,
            None => default_window(info.flags, work.len(), target_size),
        };
        if !window.is_power_of_two() || !(0x2_0000..=0x200_0000).contains(&window) {
            return Err(Error::Invalid("PA19 LZX window must be 128 KiB to 32 MiB"));
        }
        if window > limits.max_window_bytes {
            return Err(Error::Limit("window size"));
        }
        if info.flags & 3 == 0 {
            return Err(Error::Invalid("PA19 header selects no LZX mode"));
        }
        output = zeroed(target_size)?;
        let order = window.trailing_zeros() as u8;
        if entry.interleave.is_empty() {
            // mspatcha preloads the first min(old size, window) bytes as the history; only the
            // last window - 3 of them can be reached by a match.
            let history = history_slice(&work[..work.len().min(window)], window);
            ms_compress::lzx::decompress_lzxd(stream, history, &mut output, order)
                .map_err(|error| Error::Codec(error.to_string()))?;
        } else {
            decode_interleaved(stream, &work, &entry.interleave, &mut output, order)?;
        }
        if crc32(&output) != info.target_crc32 {
            return Err(Error::Integrity("PA19 target CRC"));
        }
    }
    paste_retain(&mut output, &entry.retain_ranges, saved);
    Ok(output)
}

/// The part of a preloaded history that a match can reach: a match distance is at most
/// `window - 3`, so the first bytes of a history that fills the window are unreachable.
fn history_slice(history: &[u8], window: usize) -> &[u8] {
    &history[history.len().saturating_sub(window - 3)..]
}

/// Decodes an interleaved stream: each group is an independent LZX decode (fresh state and
/// trees, E8 header again in its first chunk) whose history is its slice of the transformed old
/// file; the groups' outputs follow each other and the chunk stream is continuous.
fn decode_interleaved(
    stream: &[u8],
    old: &[u8],
    groups: &[Pa19InterleaveGroup],
    output: &mut [u8],
    order: u8,
) -> Result<()> {
    let codec = |error: ms_compress::lzx::LzxDeltaError| Error::Codec(error.to_string());
    let (mut input, mut position) = (stream, 0usize);
    for group in groups {
        let (offset, length) = (group.old_offset as usize, group.old_length as usize);
        let reference = old
            .get(
                offset
                    ..offset
                        .checked_add(length)
                        .ok_or(Error::Invalid("PA19 interleave range"))?,
            )
            .ok_or(Error::Invalid("PA19 interleave group exceeds the old file"))?;
        let mut decoder =
            ms_compress::lzx::LzxDeltaDecoder::new(order, reference).map_err(codec)?;
        let end = position
            .checked_add(group.new_length as usize)
            .filter(|end| *end <= output.len())
            .ok_or(Error::Invalid("PA19 interleave groups exceed the new file"))?;
        for chunk in output[position..end].chunks_mut(32768) {
            let prefix = input
                .get(..2)
                .ok_or(Error::Invalid("PA19 patch stream is truncated"))?;
            let size = usize::from(u16::from_le_bytes([prefix[0], prefix[1]]));
            let payload = input
                .get(2..2 + size)
                .ok_or(Error::Invalid("PA19 patch stream is truncated"))?;
            if size == 0 {
                return Err(Error::Invalid("PA19 empty LZX chunk"));
            }
            decoder.decompress_chunk(payload, chunk).map_err(codec)?;
            input = &input[2 + size..];
        }
        decoder.finish().map_err(codec)?;
        position = end;
    }
    if position != output.len() || !input.is_empty() {
        return Err(Error::Invalid(
            "PA19 interleave groups do not cover the stream",
        ));
    }
    Ok(())
}

fn put_uvar(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte | 0x80);
            return;
        }
        out.push(byte);
    }
}

fn put_svar(out: &mut Vec<u8>, value: i32) {
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let first = (magnitude & 0x3f) as u8 | if negative { 0x40 } else { 0 };
    magnitude >>= 6;
    if magnitude == 0 {
        out.push(first | 0x80);
        return;
    }
    out.push(first);
    put_uvar(out, magnitude);
}

/// Policy for the Intel `E8` call translation of the LZX stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Pa19E8 {
    /// No translation (the stream's first chunk carries a zero flag).
    #[default]
    Off,
    /// Translate with the new file size as translation size (what `mspatchc.dll` writes).
    On,
    /// Try both and keep the smaller patch (skipped when the target has almost no `E8` bytes).
    Auto,
}

/// Policy for PE-aware creation (PE32 images only: `mspatcha.dll` transforms nothing else).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Pa19Pe {
    /// Raw data: no normalization, no rift.
    #[default]
    Off,
    /// Use the PE32 path when both files are PE32 images (otherwise raw), without trying raw.
    On,
    /// Try the PE32 path, when applicable, next to the raw path and keep the smaller patch.
    Auto,
}

/// Options for [`create_pa19_with`].
#[derive(Clone, Debug, Default)]
pub struct Pa19CreateOptions {
    /// Explicit LZX window size as a power of two from 17 to 25 (carried in the header with
    /// option bit 0x10000); the default is the one `mspatcha.dll` derives from the file sizes.
    pub window_order: Option<u8>,
    /// Interleave groups. Every group except the last must produce a multiple of 32768 bytes; the
    /// last one's length is taken from the target size. Without groups the whole old file is the
    /// history of one LZX stream, which must fit the window.
    pub interleave: Vec<Pa19InterleaveGroup>,
    /// Intel `E8` translation policy.
    pub e8: Pa19E8,
    /// PE-aware creation policy.
    pub pe: Pa19Pe,
}

/// Plans interleave groups of `group_bytes` output bytes (rounded up to a multiple of 32768) for
/// files that do not fit one LZX window: each group sees the window - 3 bytes of the old file
/// centred on the position corresponding to the group's start. A heuristic, not what
/// `mspatchc.dll` chooses; the result is valid for any file sizes.
pub fn plan_interleave(
    old_size: usize,
    new_size: usize,
    window_order: u8,
    group_bytes: usize,
) -> Vec<Pa19InterleaveGroup> {
    let group = group_bytes.max(1).div_ceil(32768) * 32768;
    let history = old_size.min((1usize << window_order.clamp(17, 25)) - 3);
    let count = new_size.div_ceil(group).max(1);
    (0..count)
        .map(|index| {
            let start = index * group;
            let proportional = if new_size == 0 {
                0
            } else {
                (start as u128 * old_size as u128 / new_size as u128) as usize
            };
            let offset = proportional
                .saturating_sub(history / 2)
                .min(old_size - history);
            Pa19InterleaveGroup {
                old_offset: offset as u32,
                old_length: history as u32,
                new_length: group.min(new_size.saturating_sub(start)) as u32,
            }
        })
        .collect()
}

/// Creates a PA19 patch from `source` to `target` with default options: one old-file
/// alternative, no ranges, no PE normalization or rift transform, LZX stream from
/// [`crate::create_lzxd`] (verbatim blocks with fixed trees, Intel `E8` preprocessing off).
pub fn create_pa19(source: &[u8], target: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    create_pa19_with(source, target, &Pa19CreateOptions::default(), limits)
}

/// PE32 treatment chosen by the creator: what the header tells `mspatcha.dll` to do to the old
/// image before the LZX stream sees it.
struct PePlan {
    /// ImageBase (high word shifted) the old image is rebased to.
    coff_base: u32,
    /// TimeDateStamp the old image is stamped with.
    coff_time: u32,
    /// Transform option bits (the pass-disabling bits and pass order selectors).
    options: u32,
    rift: Vec<(u32, u32)>,
}

fn pe32_pair(source: &[u8], target: &[u8]) -> Option<(u32, u32)> {
    pe::nt_header(source)?;
    let new_nt = pe::nt_header(target)?;
    let word = |buf: &[u8], at: usize| {
        buf.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let base = word(target, new_nt + 52)?;
    // The header stores only the high word of the ImageBase.
    (base & 0xffff == 0).then_some((base, word(target, new_nt + 8)?))
}

/// Creates a PA19 patch; see [`Pa19CreateOptions`]. Every candidate patch is applied with
/// [`apply_pa19`] before it is returned, so a result always round-trips through this crate.
pub fn create_pa19_with(
    source: &[u8],
    target: &[u8],
    options: &Pa19CreateOptions,
    limits: &Limits,
) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA19 source size"));
    }
    if target.len() > limits.max_output_bytes {
        return Err(Error::Limit("PA19 target size"));
    }
    if source.len() > u32::MAX as usize >> 1 || target.len() > u32::MAX as usize >> 1 {
        return Err(Error::Limit("PA19 file size"));
    }
    let e8_found = target.iter().filter(|byte| **byte == 0xe8).count();
    let e8_choices: &[bool] = match options.e8 {
        Pa19E8::Off => &[false],
        Pa19E8::On => &[true],
        Pa19E8::Auto if e8_found >= 32 => &[false, true],
        Pa19E8::Auto => &[false],
    };
    let pair = match options.pe {
        Pa19Pe::Off => None,
        Pa19Pe::On | Pa19Pe::Auto => pe32_pair(source, target),
    };
    let mut candidates: Vec<(Option<PePlan>, Option<u32>)> = Vec::new();
    let intel = |on: bool| on.then_some(target.len() as u32).filter(|size| *size != 0);
    if let Some((coff_base, coff_time)) = pair {
        // Rift candidates: coarse tables (few, well supported steps) up to fine ones; identical
        // tables are tried once. Large images get one candidate to bound the work.
        let divisors: &[usize] = if source.len().max(target.len()) > 4 << 20 {
            &[512]
        } else {
            &[16, 128, 1024, 0]
        };
        let mut rifts: Vec<Vec<(u32, u32)>> = Vec::new();
        for &divisor in divisors {
            let table = rift::generate(source, target, divisor);
            if !rifts.contains(&table) {
                rifts.push(table);
            }
        }
        for rift in rifts {
            for &on in e8_choices {
                // With the call pass disabled (option 0x10) the LZX `E8` translation handles calls
                // instead; `mspatchc.dll` pairs the two the same way (OBSERVED).
                let transform_options = if on { 0x10 } else { 0 };
                candidates.push((
                    Some(PePlan {
                        coff_base,
                        coff_time,
                        options: transform_options,
                        rift: rift.clone(),
                    }),
                    intel(on),
                ));
            }
        }
    }
    if options.pe != Pa19Pe::On || pair.is_none() {
        for &on in e8_choices {
            candidates.push((None, intel(on)));
        }
    }
    let mut best: Option<Vec<u8>> = None;
    let mut first_error = None;
    for (plan, intel_size) in &candidates {
        let result =
            build(source, target, options, plan.as_ref(), *intel_size, limits).and_then(|patch| {
                if apply_pa19(source, &patch, limits)? != target {
                    return Err(Error::Integrity("created PA19 patch does not round-trip"));
                }
                Ok(patch)
            });
        match result {
            Ok(patch)
                if best
                    .as_ref()
                    .is_none_or(|previous| patch.len() < previous.len()) =>
            {
                best = Some(patch);
            }
            Ok(_) => {}
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    best.ok_or_else(|| first_error.unwrap_or(Error::Invalid("PA19 creation candidates")))
}

/// Builds one patch for a fixed choice of PE treatment and `E8` translation size.
fn build(
    source: &[u8],
    target: &[u8],
    options: &Pa19CreateOptions,
    pe_plan: Option<&PePlan>,
    intel_size: Option<u32>,
    limits: &Limits,
) -> Result<Vec<u8>> {
    // Decoded flags. Raw mode: no target time, no COFF or resource times, do not unbind or smash
    // lock prefixes (the old file is used unmodified). PE mode (as `mspatchc.dll` writes it): a
    // time and the COFF fields follow, no resource time, unbind and lock smashing on.
    let mut flags = 0x0001u32;
    let mut header_options = 0u32;
    let mut work = std::borrow::Cow::Borrowed(source);
    let mut old_crc = None;
    if let Some(plan) = pe_plan {
        flags |= 0x0040_0000;
        header_options |= plan.options;
        let mut image = source.to_vec();
        pe::normalize(&mut image, flags, plan.coff_base, plan.coff_time)?;
        old_crc = Some(crc32(&image));
        if !plan.rift.is_empty() {
            pe::transform(&mut image, header_options, 0, &plan.rift)?;
        }
        work = std::borrow::Cow::Owned(image);
    } else {
        flags |= 0x0080_0000 | 0x0004_0000 | 0x0040_0000 | 0x0001_0000 | 0x0002_0000;
    }
    let interleaved = !options.interleave.is_empty();
    if interleaved {
        flags |= 0x4000_0000;
    }
    if options.window_order.is_some() {
        header_options |= 0x1_0000;
    }
    if header_options != 0 {
        flags |= 0x8000_0000;
    }
    let history_source: &[u8] = &work;
    let window = match options.window_order {
        Some(order) if (17..=25).contains(&order) => 1usize << order,
        Some(_) => return Err(Error::Invalid("PA19 window order must be 17 to 25")),
        None => {
            let small = default_window(flags, source.len(), target.len());
            let wanted = target.len() as u64 + ((source.len() as u64 + 0x7fff) & !0x7fff);
            if small as u64 >= wanted || interleaved {
                small
            } else {
                flags |= 4;
                default_window(flags, source.len(), target.len())
            }
        }
    };
    if window > limits.max_window_bytes {
        return Err(Error::Limit("window size"));
    }
    let order = window.trailing_zeros() as u8;
    let mut streams: Vec<Vec<u8>> = Vec::new();
    let mut table = Vec::new();
    if interleaved {
        let (mut previous_offset, mut previous_length, mut previous_new) = (0i64, 0i64, 0i64);
        let (mut previous_a, mut previous_b) = (0i64, 0i64);
        let mut position = 0usize;
        put_uvar(&mut table, options.interleave.len() as u32);
        for (index, group) in options.interleave.iter().enumerate() {
            let (offset, length) = (group.old_offset as usize, group.old_length as usize);
            let reference = history_source
                .get(
                    offset
                        ..offset
                            .checked_add(length)
                            .ok_or(Error::Invalid("PA19 interleave"))?,
                )
                .ok_or(Error::Invalid("PA19 interleave group exceeds the old file"))?;
            let last = index + 1 == options.interleave.len();
            let new_length = if last {
                target.len() - position
            } else {
                if group.new_length % 32768 != 0
                    || position + group.new_length as usize > target.len()
                {
                    return Err(Error::Invalid("PA19 interleave group length"));
                }
                group.new_length as usize
            };
            let a = i64::from(group.old_offset) - previous_offset;
            let b = i64::from(group.old_length) - previous_length;
            put_svar(&mut table, (a - previous_a) as i32);
            put_svar(&mut table, (b - previous_b) as i32);
            if !last {
                let step = new_length as i64 - previous_new;
                if step % 32768 != 0 {
                    return Err(Error::Invalid("PA19 interleave group length"));
                }
                put_svar(&mut table, (step >> 15) as i32);
            }
            (previous_offset, previous_length) =
                (i64::from(group.old_offset), i64::from(group.old_length));
            (previous_a, previous_b, previous_new) = (a, b, new_length as i64);
            streams.push(crate::lzxd_encode::create_lzxd_intel(
                reference,
                &target[position..position + new_length],
                order,
                intel_size,
                limits,
            )?);
            position += new_length;
        }
        if position != target.len() {
            return Err(Error::Invalid(
                "PA19 interleave groups do not cover the target",
            ));
        }
    } else {
        let history = history_slice(&history_source[..history_source.len().min(window)], window);
        streams.push(crate::lzxd_encode::create_lzxd_intel(
            history, target, order, intel_size, limits,
        )?);
    }
    let stream_size: usize = streams.iter().map(Vec::len).sum();
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(flags ^ 0x0080_0000).to_le_bytes());
    if flags & 0x8000_0000 != 0 {
        out.extend_from_slice(&header_options.to_le_bytes());
    }
    if let Some(plan) = pe_plan {
        out.extend_from_slice(&0u32.to_le_bytes()); // target time: unknown to a byte-level creator
        out.extend_from_slice(&((plan.coff_base >> 16) as u16).to_le_bytes());
        out.extend_from_slice(&plan.coff_time.to_le_bytes()); // raw, because the time is zero
    }
    put_uvar(&mut out, target.len() as u32);
    out.extend_from_slice(&crc32(target).to_le_bytes());
    if let Some(order) = options.window_order {
        out.push(order);
    }
    out.push(1);
    put_svar(&mut out, source.len() as i32 - target.len() as i32);
    out.extend_from_slice(&old_crc.unwrap_or_else(|| crc32(source)).to_le_bytes());
    out.push(0); // ignore ranges
    out.push(0); // retain ranges
    match pe_plan {
        Some(plan) => {
            put_uvar(&mut out, plan.rift.len() as u32);
            let (mut old_rva, mut new_rva) = (0u32, 0u32);
            for &(old, new) in &plan.rift {
                put_uvar(&mut out, old - old_rva);
                put_svar(&mut out, new.wrapping_sub(new_rva) as i32);
                (old_rva, new_rva) = (old, new);
            }
        }
        None => put_uvar(&mut out, 0),
    }
    out.extend_from_slice(&table);
    put_uvar(&mut out, stream_size as u32);
    for stream in &streams {
        out.extend_from_slice(stream);
    }
    let trailer = !crc32(&out);
    out.extend_from_slice(&trailer.to_le_bytes());
    if out.len() > limits.max_patch_bytes {
        return Err(Error::Limit("PA19 patch size"));
    }
    Ok(out)
}
