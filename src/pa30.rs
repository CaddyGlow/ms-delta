//! Bounded PA30/PA31 creation and decoding for RAW, PE and managed files.
//!
//! PA30 uses its own LSB-first PLZX stream; it is not an MS-PATCH LZX stream.
//! Includes PE source normalization, piecewise rifts, and target E8 restoration.
//! Includes legacy/CLI4 metadata, signature, and IL token normalization.

use crate::{Error, Limits, Result};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::borrow::Cow;

mod arm;
mod arm64;
mod bsdiff;
mod cli;
mod cli_encode;
mod cli_il;
mod cli_rift;
mod e8;
mod encode;
mod ia64;
mod lzms_frame;
mod pa31;
mod pe;
mod pe_encode;
mod reverse;
mod rift;
mod rift_encode;

pub use encode::create_pa30;
pub use pa31::{Pa31Info, apply_pa31, create_pa31, create_pa31_pe, inspect_pa31};
pub use pe_encode::create_pa30_pe;

/// Metadata carried by a PA30 outer header. Inspection does not apply a patch.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Pa30Info {
    /// Windows FILETIME timestamp of the target.
    pub target_file_time: u64,
    /// File types considered when the delta was generated.
    pub file_type_set: u64,
    /// Selected file type; RAW is 1.
    pub file_type: u64,
    /// Transform and generation flags from the delta header.
    pub flags: u64,
    /// Declared reconstructed size.
    pub target_size: usize,
    /// CryptoAPI target-hash algorithm identifier.
    pub target_hash_algorithm: u32,
    /// Target hash bytes, validated after reconstruction.
    pub target_hash: Vec<u8>,
    /// Number of bytes in the preprocessing buffer.
    pub preprocessing_size: usize,
    /// Number of bytes in the PLZX patch buffer.
    pub patch_size: usize,
}

struct Parsed<'a> {
    info: Pa30Info,
    preprocessing: &'a [u8],
    patch: &'a [u8],
}

/// Reads PA30 metadata with bounded sizes. Unsupported transforms remain visible.
pub fn inspect_pa30(delta: &[u8], limits: &Limits) -> Result<Pa30Info> {
    Ok(parse(delta, limits)?.info)
}

/// Applies PA30 deltas with RAW, PE and managed source dictionaries.
///
/// The reconstructed target hash must match. Unsupported architectures or
/// unknown graphs return [`Error::Unsupported`] without an external fallback.
pub fn apply_pa30(source: &[u8], delta: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA30 source size"));
    }
    let parsed = parse(delta, limits)?;
    apply_parsed(source, &parsed, limits)
}

/// Apply a bounded PA30 delta with mandatory external target authentication.
///
/// Unlike [`apply_pa30`], this explicit path accepts CALG_NONE only when its
/// intrinsic hash is empty. Every decoded target must pass `verifier` before
/// any bytes are returned. Other hash algorithms and lengths remain strict.
/// This supports DCM1 manifests whose expanded bytes are authenticated by a
/// signed catalog, without weakening ordinary delta integrity verification.
pub fn apply_pa30_with_verifier(
    source: &[u8],
    delta: &[u8],
    limits: &Limits,
    verifier: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA30 source size"));
    }
    let parsed = parse(delta, limits)?;
    let output = apply_parsed_with_hash_policy(source, &parsed, limits, true)?;
    verifier(&output)?;
    Ok(output)
}
fn apply_parsed(source: &[u8], parsed: &Parsed<'_>, limits: &Limits) -> Result<Vec<u8>> {
    apply_parsed_with_hash_policy(source, parsed, limits, false)
}
fn apply_parsed_with_hash_policy(
    source: &[u8],
    parsed: &Parsed<'_>,
    limits: &Limits,
    allow_absent_hash: bool,
) -> Result<Vec<u8>> {
    let result = apply_once(source, parsed, limits, allow_absent_hash);
    if matches!(result, Err(Error::Integrity(_)))
        && parsed.info.file_type == 4
        && parsed.info.flags & 0x1800 != 0
    {
        // PA30 carries no producer version. Older MSDelta normalizes IA64
        // instructions/pdata; current UpdateCompression leaves them unchanged.
        // The declared target digest selects between these two bounded paths.
        let alternate = Parsed {
            info: Pa30Info {
                flags: parsed.info.flags & !0x1800,
                ..parsed.info.clone()
            },
            preprocessing: parsed.preprocessing,
            patch: parsed.patch,
        };
        return apply_once(source, &alternate, limits, allow_absent_hash);
    }
    result
}

fn apply_once(
    source: &[u8],
    parsed: &Parsed<'_>,
    limits: &Limits,
    allow_absent_hash: bool,
) -> Result<Vec<u8>> {
    let info = &parsed.info;
    let absent_hash =
        allow_absent_hash && info.target_hash_algorithm == 0 && info.target_hash.is_empty();
    if !absent_hash {
        validate_hash(info)?;
    }
    if info.flags & !0x1bff_ffff != 0 {
        return Err(Error::Unsupported("PA30 unknown transform flag"));
    }
    let normalized_parameters = Parsed {
        info: Pa30Info {
            flags: info.flags & 0x01ff_ffff,
            ..info.clone()
        },
        preprocessing: parsed.preprocessing,
        patch: parsed.patch,
    };
    let (source, source_rift) = prepare_source(source, &normalized_parameters, limits)?;
    if info.flags & 0x0200_0000 != 0 {
        if info.flags & 0x0800_0000 == 0 && !parsed.patch.is_empty() {
            return Err(Error::Invalid(
                "delta nonempty BSDiff payload requires compression",
            ));
        }
        let maximum = if source.is_empty() {
            info.target_size
        } else {
            info.target_size
                .checked_add(limits.max_parameter_bytes)
                .ok_or(Error::Limit("delta BSDiff workspace"))?
        };
        let decoded = if parsed.patch.is_empty() && info.target_size == 0 {
            Vec::new()
        } else {
            lzms_frame::decompress(parsed.patch, maximum)?
        };
        let mut output = if source.is_empty() {
            decoded
        } else {
            bsdiff::apply(&source, &decoded, info.target_size, limits)?
        };
        if output.len() != info.target_size {
            return Err(Error::Invalid("delta BSDiff target size"));
        }
        if info.flags & 1 != 0 {
            e8::restore(&mut output);
        }
        if !absent_hash {
            verify_hash(info, &output)?;
        }
        return Ok(output);
    }
    let mut bits = Bits::new(parsed.patch)?;
    let base_rift = rift::RiftTable::read(&mut bits, limits)?;
    let shift = rift::RiftTable::source_shift(source.len(), limits)?;
    let shifted = rift::RiftTable::compose(&shift, &source_rift, limits)?;
    let compression_rift = rift::RiftTable::sum(&base_rift, &shifted, false, limits)?;
    let blocks = parameters(&mut bits, source.len(), info.target_size, limits)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(info.target_size)
        .map_err(|_| Error::Allocation)?;
    let mut lru = [0usize; 3];
    let mut active = 0;
    while output.len() < info.target_size {
        // Compression parameter positions include the prepended source.
        let position = source
            .len()
            .checked_add(output.len())
            .ok_or(Error::Invalid("PA30 position overflow"))?;
        while active + 1 < blocks.len() && blocks[active + 1].start <= position {
            active += 1;
        }
        let trees = &blocks[active];
        let symbol = trees.main.decode(&mut bits)?;
        if symbol < 256 {
            output.push(symbol as u8);
            continue;
        }
        let slot = (symbol - 256) >> 3;
        let short = (symbol - 256) & 7;
        let kind = match slot {
            0 => Match::Source(bits.read(14)? as i64 - 0x2000),
            1 => {
                let raw = bits.read(16)? as i64 - 0x8000;
                Match::Source(raw + if raw < 0 { -0x2000 } else { 0x2000 })
            }
            2 => {
                let raw = bits.read(18)? as i64 - 0x20000;
                Match::Source(raw + if raw < 0 { -0xa000 } else { 0xa000 })
            }
            3 => Match::MappedSource,
            4..=6 => Match::Repeat(slot - 4),
            8..=10 => Match::Offset(slot - 7),
            _ => Match::Offset(read_offset(slot, &mut bits, &trees.aligned)?),
        };
        let length = if short != 0 {
            short + 1
        } else {
            let symbol = trees.length.decode(&mut bits)?;
            if symbol != 0 {
                symbol + 8
            } else {
                long_length(&mut bits)?
                    .checked_add(8)
                    .ok_or(Error::Invalid("PA30 length overflow"))?
            }
        };
        if length > info.target_size - output.len() {
            return Err(Error::Invalid("PA30 match exceeds target"));
        }
        if matches!(kind, Match::MappedSource) {
            let first_offset = mapped_offset(&compression_rift, position, 0)?;
            for _ in 0..length {
                let position = source.len() + output.len();
                let offset = mapped_offset(&compression_rift, position, 0)?;
                copy_match(&source, &mut output, offset, 1, limits)?;
            }
            remember_offset(&mut lru, first_offset);
            continue;
        }
        let offset = match kind {
            Match::Source(delta) => mapped_offset(&compression_rift, position, delta)?,
            Match::MappedSource => return Err(Error::Invalid("PA30 mapped match state")),
            Match::Repeat(index) => lru[index],
            Match::Offset(offset) => offset,
        };
        copy_match(&source, &mut output, offset, length, limits)?;
        remember_offset(&mut lru, offset);
    }
    bits.finish()?;
    if info.flags & 1 != 0 {
        e8::restore(&mut output);
    }
    if !absent_hash {
        verify_hash(info, &output)?;
    }
    Ok(output)
}

fn remember_offset(lru: &mut [usize; 3], offset: usize) {
    if lru[0] != offset {
        if lru[1] != offset {
            lru[2] = lru[1];
        }
        lru[1] = lru[0];
        lru[0] = offset;
    }
}

enum Match {
    Source(i64),
    MappedSource,
    Repeat(usize),
    Offset(usize),
}

fn mapped_offset(table: &rift::RiftTable, position: usize, delta: i64) -> Result<usize> {
    let position = i64::try_from(position).map_err(|_| Error::Limit("PA30 source position"))?;
    let translation = table.compression_rift(position).0;
    if translation == 0 {
        return Err(Error::Invalid("PA30 inactive source rift"));
    }
    let index = i128::from(position) + i128::from(translation) - i128::from(delta);
    let distance = i128::from(position) - index;
    usize::try_from(distance).map_err(|_| Error::Invalid("PA30 mapped match offset"))
}

fn copy_match(
    source: &[u8],
    output: &mut Vec<u8>,
    offset: usize,
    length: usize,
    limits: &Limits,
) -> Result<()> {
    let position = source.len() + output.len();
    if offset == 0 || offset > position {
        return Err(Error::Invalid("PA30 match precedes source"));
    }
    if offset > limits.max_window_bytes {
        return Err(Error::Limit("PA30 match window"));
    }
    for _ in 0..length {
        let from = source.len() + output.len() - offset;
        let byte = if from < source.len() {
            source[from]
        } else {
            output[from - source.len()]
        };
        output.push(byte);
    }
    Ok(())
}

fn prepare_source<'a>(
    source: &'a [u8],
    parsed: &Parsed<'_>,
    limits: &Limits,
) -> Result<(Cow<'a, [u8]>, rift::RiftTable)> {
    let info = &parsed.info;
    if info.flags & !0x01ff_ffff != 0 {
        return Err(Error::Unsupported("PA30 unknown transform flag"));
    }
    if info.file_type == 1 && info.file_type_set & 1 != 0 {
        if !parsed.preprocessing.is_empty() {
            return Err(Error::Unsupported("PA30 RAW preprocessing buffer"));
        }
        return Ok((Cow::Borrowed(source), rift::RiftTable::default()));
    }
    if !matches!(info.file_type, 2 | 4 | 8 | 16 | 32 | 64 | 128)
        || info.file_type_set & info.file_type == 0
    {
        return Err(Error::Unsupported("PA30 executable file type"));
    }
    let graph = if matches!(info.file_type, 2 | 4 | 8) {
        cli::Graph::Legacy
    } else {
        cli::Graph::Cli4
    };
    let mut bits = Bits::new(parsed.preprocessing)?;
    let target = pe::TargetInfo {
        image_base: bits.read(64)?,
        global_pointer: bits.read(32)? as u32,
        time_stamp: bits.read(32)? as u32,
        rva_to_offset: rift::RiftTable::read(&mut bits, limits)?,
    };
    let target_cli = cli::MetadataInfo::read_for_graph(&mut bits, limits, graph)?;
    let used = rift::RiftTable::read(&mut bits, limits)?;
    let cli_maps = graph.read_maps(&mut bits, limits)?;
    bits.finish()?;
    let layout = pe::PeLayout::parse(source)?;
    let matches_architecture = match info.file_type {
        2 | 16 => layout.machine() == 0x14c,
        8 | 32 => layout.machine() == 0x8664,
        4 => layout.machine() == 0x200,
        128 => layout.machine() == 0xaa64,
        64 => layout.machine() == 0x1c4,
        _ => false,
    };
    if !matches_architecture {
        return Err(Error::Invalid(
            "PA30 source architecture differs from graph",
        ));
    }
    let source_cli = cli::MetadataInfo::parse_for_graph(source, &layout, limits, graph)?;
    let source_rva = layout.file_offset_to_rva(limits)?;
    let mapped = rift::RiftTable::compose(&source_rva, &used, limits)?;
    let mapped = rift::RiftTable::compose(&mapped, &target.rva_to_offset, limits)?;
    let compression = mapped.reverse(limits)?;
    let flags = if graph == cli::Graph::Legacy {
        (info.flags & !0x60_0000) | ((info.flags & 0xc000) << 7)
    } else {
        info.flags
    };
    let normalized = pe::preprocess_cli(
        source,
        flags,
        &target,
        &used,
        &source_cli,
        &target_cli,
        &cli_maps,
        limits,
    )?;
    let cli_compression =
        cli_rift::compression(&source_cli, &target_cli, &cli_maps, &normalized, limits)?;
    let compression = rift::RiftTable::sum(&compression, &cli_compression, true, limits)?;
    Ok((Cow::Owned(normalized), compression))
}

fn parse<'a>(delta: &'a [u8], limits: &Limits) -> Result<Parsed<'a>> {
    if delta.len() > limits.max_patch_bytes {
        return Err(Error::Limit("PA30 delta size"));
    }
    if delta.get(..4) != Some(b"PA30") {
        return Err(Error::Invalid("PA30 signature"));
    }
    let time: [u8; 8] = delta
        .get(4..12)
        .ok_or(Error::Invalid("PA30 truncated header"))?
        .try_into()
        .map_err(|_| Error::Invalid("PA30 timestamp"))?;
    let mut bits = Bits::new(&delta[12..])?;
    let file_type_set = bits.number(16)?;
    let file_type = bits.number(16)?;
    let flags = bits.number(16)?;
    let target_size =
        usize::try_from(bits.number(16)?).map_err(|_| Error::Limit("PA30 target size"))?;
    if target_size > limits.max_output_bytes {
        return Err(Error::Limit("PA30 target size"));
    }
    let target_hash_algorithm =
        u32::try_from(bits.number(8)?).map_err(|_| Error::Invalid("PA30 hash algorithm"))?;
    let target_hash = bits.buffer()?;
    if target_hash.len() > 32 {
        return Err(Error::Invalid("PA30 oversized target hash"));
    }
    let preprocessing = bits.buffer()?;
    let patch = bits.buffer()?;
    bits.finish()?;
    Ok(Parsed {
        info: Pa30Info {
            target_file_time: u64::from_le_bytes(time),
            file_type_set,
            file_type,
            flags,
            target_size,
            target_hash_algorithm,
            target_hash: target_hash.to_vec(),
            preprocessing_size: preprocessing.len(),
            patch_size: patch.len(),
        },
        preprocessing,
        patch,
    })
}

fn verify_hash(info: &Pa30Info, target: &[u8]) -> Result<()> {
    let matches = match info.target_hash_algorithm {
        0x8003 if info.target_hash.len() == 16 => {
            Md5::digest(target).as_slice() == info.target_hash
        }
        0x800c if info.target_hash.len() == 32 => {
            Sha256::digest(target).as_slice() == info.target_hash
        }
        0x8004 if info.target_hash.len() == 20 => {
            Sha1::digest(target).as_slice() == info.target_hash
        }
        0x8003 | 0x8004 | 0x800c => return Err(Error::Invalid("PA30 hash length")),
        _ => return Err(Error::Unsupported("PA30 target hash algorithm")),
    };
    if matches {
        Ok(())
    } else {
        Err(Error::Integrity("PA30 target hash mismatch"))
    }
}

fn validate_hash(info: &Pa30Info) -> Result<()> {
    let expected = match info.target_hash_algorithm {
        0x8003 => 16,
        0x8004 => 20,
        0x800c => 32,
        _ => return Err(Error::Unsupported("PA30 target hash algorithm")),
    };
    if info.target_hash.len() != expected {
        return Err(Error::Invalid("PA30 hash length"));
    }
    Ok(())
}

struct Bits<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl<'a> Bits<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        let first = *bytes
            .first()
            .ok_or(Error::Invalid("PA30 empty bitstream"))?;
        let padding = usize::from(first & 7);
        let end = bytes
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_sub(padding))
            .ok_or(Error::Invalid("PA30 bitstream overflow"))?;
        if end < 3 {
            return Err(Error::Invalid("PA30 invalid bitstream padding"));
        }
        if padding != 0 && bytes[bytes.len() - 1] >> (8 - padding) != 0 {
            return Err(Error::Invalid("PA30 nonzero tail padding"));
        }
        Ok(Self {
            bytes,
            position: 3,
            end,
        })
    }

    fn read(&mut self, count: usize) -> Result<u64> {
        if count > 64 || count > self.end - self.position {
            return Err(Error::Invalid("PA30 truncated bitstream"));
        }
        let mut value = 0;
        for shift in 0..count {
            value |= u64::from((self.bytes[self.position / 8] >> (self.position % 8)) & 1) << shift;
            self.position += 1;
        }
        Ok(value)
    }

    fn number(&mut self, max_nibbles: usize) -> Result<u64> {
        let mut nibbles = 1;
        while self.read(1)? == 0 {
            nibbles += 1;
            if nibbles > max_nibbles {
                return Err(Error::Invalid("PA30 integer width"));
            }
        }
        self.read(nibbles * 4)
    }

    fn buffer(&mut self) -> Result<&'a [u8]> {
        let length =
            usize::try_from(self.number(16)?).map_err(|_| Error::Invalid("PA30 buffer length"))?;
        let aligned = self
            .position
            .checked_add(7)
            .ok_or(Error::Invalid("PA30 buffer offset"))?
            & !7;
        if aligned > self.end {
            return Err(Error::Invalid("PA30 buffer alignment"));
        }
        // Buffer byte alignment is independent of stream tail padding.
        self.position = aligned;
        let start = aligned / 8;
        let end = start
            .checked_add(length)
            .ok_or(Error::Invalid("PA30 buffer size overflow"))?;
        if end > self.end / 8 {
            return Err(Error::Invalid("PA30 truncated buffer"));
        }
        self.position = end * 8;
        Ok(&self.bytes[start..end])
    }

    fn finish(&self) -> Result<()> {
        if self.position == self.end {
            Ok(())
        } else {
            Err(Error::Invalid("PA30 trailing bits"))
        }
    }
}

struct Huffman {
    first: [usize; 17],
    counts: [usize; 17],
    offsets: [usize; 17],
    symbols: Vec<usize>,
    max: usize,
}

impl Huffman {
    fn new(lengths: &[u8], max: usize) -> Result<Self> {
        let mut counts = [0usize; 17];
        for &length in lengths {
            if usize::from(length) > max {
                return Err(Error::Invalid("PA30 Huffman code length"));
            }
            counts[usize::from(length)] += 1;
        }
        if counts[0] == lengths.len() {
            return Ok(Self {
                first: [0; 17],
                counts,
                offsets: [0; 17],
                symbols: Vec::new(),
                max: 0,
            });
        }
        let mut available = 1isize;
        for &count in counts.iter().take(max + 1).skip(1) {
            available = available * 2 - count as isize;
            if available < 0 {
                return Err(Error::Invalid("PA30 oversubscribed Huffman tree"));
            }
        }
        let mut first = [0; 17];
        let mut sum = 0;
        for length in (1..=max).rev() {
            first[length] = sum;
            sum = (sum + counts[length]) / 2;
        }
        for short in 1..=max {
            if counts[short] == 0 {
                continue;
            }
            for long in short + 1..=max {
                if counts[long] == 0 {
                    continue;
                }
                let start = first[long] >> (long - short);
                let end = (first[long] + counts[long] - 1) >> (long - short);
                if start < first[short] + counts[short] && end >= first[short] {
                    return Err(Error::Invalid("PA30 overlapping Huffman codes"));
                }
            }
        }
        let mut offsets = [0; 17];
        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(lengths.len())
            .map_err(|_| Error::Allocation)?;
        for length in (1..=max).rev() {
            offsets[length] = symbols.len();
            for (symbol, &len) in lengths.iter().enumerate() {
                if usize::from(len) == length {
                    symbols.push(symbol);
                }
            }
        }
        Ok(Self {
            first,
            counts,
            offsets,
            symbols,
            max,
        })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<usize> {
        let mut value = 0;
        for length in 1..=self.max {
            value = (value << 1) | bits.read(1)? as usize;
            if value >= self.first[length] && value - self.first[length] < self.counts[length] {
                let index = self.offsets[length] + value - self.first[length];
                return self
                    .symbols
                    .get(index)
                    .copied()
                    .ok_or(Error::Invalid("PA30 Huffman symbol"));
            }
        }
        Err(Error::Invalid("PA30 Huffman code"))
    }
}

struct Parameters {
    start: usize,
    main: Huffman,
    length: Huffman,
    aligned: Huffman,
}

fn default_lengths(size: usize) -> Vec<u8> {
    let bits = usize::BITS - (size - 1).leading_zeros();
    let shorter = (1usize << bits) - size;
    (0..size)
        .map(|i| (bits - u32::from(i < shorter)) as u8)
        .collect()
}

fn parameters(
    bits: &mut Bits<'_>,
    source_size: usize,
    target_size: usize,
    limits: &Limits,
) -> Result<Vec<Parameters>> {
    if bits.read(1)? != 0 {
        check_parameter_budget(1, limits)?;
        return Ok(vec![make_parameters(
            0,
            &[
                default_lengths(600),
                default_lengths(256),
                default_lengths(16),
            ]
            .concat(),
        )?]);
    }
    let count =
        usize::try_from(bits.number(8)?).map_err(|_| Error::Limit("PA30 parameter blocks"))?;
    // Every parameter block is represented by at least one bit and substantial
    // tree state. Bound CPU and memory independently of the output allocation.
    if count == 0 {
        return Err(Error::Invalid("PA30 no parameter blocks"));
    }
    if count > (bits.end - bits.position) / 5 {
        return Err(Error::Limit("PA30 parameter blocks"));
    }
    check_parameter_budget(count, limits)?;
    let mut starts = Vec::new();
    starts
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    let mut start = 0usize;
    for i in 0..count {
        let delta = usize::try_from(bits.number(16)?)
            .map_err(|_| Error::Invalid("PA30 parameter offset"))?;
        if i != 0 && delta == 0 {
            return Err(Error::Invalid("PA30 duplicate parameter offset"));
        }
        start = start
            .checked_add(delta)
            .ok_or(Error::Invalid("PA30 parameter offset overflow"))?;
        if start > source_size.saturating_add(target_size) {
            return Err(Error::Invalid("PA30 parameter offset beyond target"));
        }
        starts.push(start);
    }
    // Native selection uses the first tree even before its declared start;
    // subsequent starts switch trees in the concatenated source/target space.
    let mut pretree_lengths = [0; 39];
    for length in &mut pretree_lengths {
        *length = bits.read(4)? as u8;
    }
    let pretree = Huffman::new(&pretree_lengths, 15)?;
    let mut previous = [0u8; 872];
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for start in starts {
        let mut lengths = [0u8; 872];
        let mut i = 0;
        while i < lengths.len() {
            let symbol = pretree.decode(bits)?;
            match symbol {
                0..=16 => {
                    lengths[i] = symbol as u8;
                    i += 1;
                }
                17..=22 => {
                    let delta = if symbol < 20 {
                        symbol as i16 - 16
                    } else {
                        19 - symbol as i16
                    };
                    let value = i16::from(previous[i]) + delta;
                    if !(0..=16).contains(&value) {
                        return Err(Error::Invalid("PA30 Huffman length delta"));
                    }
                    lengths[i] = value as u8;
                    i += 1;
                }
                23..=38 => {
                    let code = (symbol - 23) & 7;
                    let count = if code < 3 {
                        code + 1
                    } else {
                        (1 << (code - 1)) | bits.read(code - 1)? as usize
                    };
                    if count > lengths.len() - i {
                        return Err(Error::Invalid("PA30 Huffman length run"));
                    }
                    if symbol < 31 {
                        if i == 0 {
                            return Err(Error::Invalid("PA30 Huffman run without prior length"));
                        }
                        let last = lengths[i - 1];
                        lengths[i..i + count].fill(last);
                    } else {
                        lengths[i..i + count].copy_from_slice(&previous[i..i + count]);
                    }
                    i += count;
                }
                _ => return Err(Error::Invalid("PA30 pretree symbol")),
            }
        }
        blocks.push(make_parameters(start, &lengths)?);
        previous = lengths;
    }
    Ok(blocks)
}

fn check_parameter_budget(count: usize, limits: &Limits) -> Result<()> {
    // Each retained block owns exactly 872 machine-word Huffman symbols, three
    // decoder structures and one offset. Fixed overhead covers the pretree,
    // previous/current length arrays, and temporary default length buffers.
    let per_block = std::mem::size_of::<Parameters>() + 873 * std::mem::size_of::<usize>();
    let required = count
        .checked_mul(per_block)
        .and_then(|bytes| bytes.checked_add(4096))
        .ok_or(Error::Limit("PA30 parameter memory"))?;
    if required > limits.max_parameter_bytes {
        return Err(Error::Limit("PA30 parameter memory"));
    }
    Ok(())
}

fn make_parameters(start: usize, lengths: &[u8]) -> Result<Parameters> {
    Ok(Parameters {
        start,
        main: Huffman::new(&lengths[..600], 16)?,
        length: Huffman::new(&lengths[600..856], 16)?,
        aligned: Huffman::new(&lengths[856..], 16)?,
    })
}

fn read_offset(mut slot: usize, bits: &mut Bits<'_>, aligned: &Huffman) -> Result<usize> {
    if slot == 7 {
        slot = if bits.read(1)? == 0 {
            43 + bits.read(2)? as usize
        } else if bits.read(1)? == 0 {
            47 + bits.read(3)? as usize
        } else {
            55 + bits.read(4)? as usize
        };
    }
    if !(11..=70).contains(&slot) {
        return Err(Error::Invalid("PA30 offset slot"));
    }
    slot -= 11;
    let raw_bits = slot / 2 + 1;
    let top = 2 | (slot & 1);
    let offset = if raw_bits < 4 {
        (top << raw_bits) | bits.read(raw_bits)? as usize
    } else {
        (top << raw_bits) | ((bits.read(raw_bits - 4)? as usize) << 4) | aligned.decode(bits)?
    };
    Ok(offset)
}

fn long_length(bits: &mut Bits<'_>) -> Result<usize> {
    let mut width = 8;
    while bits.read(1)? == 0 {
        width += 1;
        if width > 31 {
            return Err(Error::Invalid("PA30 match length width"));
        }
    }
    Ok((1usize << width) | bits.read(width)? as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn native_raw_fixtures_reconstruct_exact_targets() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-native");
        for name in [
            "empty-literal",
            "empty-repeated",
            "source-copy",
            "md5-literal",
            "random-mutated",
            "empty-random",
            "source-offset",
            "source-reordered",
            "long-repeated",
            "extended-offset",
            "sha1-literal",
        ] {
            let read =
                |suffix| std::fs::read(fixture_root.join(format!("{name}.{suffix}"))).unwrap();
            let source = read("source");
            let delta = read("delta");
            let target = read("target");
            let result = apply_pa30(&source, &delta, &Limits::default());
            assert_eq!(
                result.unwrap_or_else(|e| panic!("{name}: {e:?}")),
                target,
                "{name}"
            );
        }
    }

    fn fixture(name: &str, suffix: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("docs/fixtures/pa30-native/{name}.{suffix}")),
        )
        .unwrap()
    }

    #[test]
    fn every_truncated_native_delta_is_rejected() {
        let delta = fixture("empty-random", "delta");
        for length in 0..delta.len() {
            assert!(
                apply_pa30(&[], &delta[..length], &Limits::default()).is_err(),
                "length {length}"
            );
        }
    }

    #[test]
    fn native_extended_offset_prefixes_reconstruct_large_sources() {
        for (name, size) in [
            ("extended-offset-2m", 2_000_000),
            ("extended-offset-20m", 20_000_000),
        ] {
            let mut state = 5071u32;
            let source: Vec<u8> = (0..size)
                .map(|_| {
                    state ^= state.wrapping_shl(13);
                    state ^= state.wrapping_shr(17);
                    state ^= state.wrapping_shl(5);
                    state as u8
                })
                .collect();
            assert_eq!(
                apply_pa30(&source, &fixture(name, "delta"), &Limits::default())
                    .unwrap_or_else(|e| panic!("{name}: {e:?}")),
                fixture(name, "target"),
                "{name}"
            );
        }
    }

    #[test]
    fn source_hash_mismatch_never_returns_reconstructed_data() {
        let mut source = fixture("source-copy", "source");
        source[100] ^= 1;
        assert!(matches!(
            apply_pa30(
                &source,
                &fixture("source-copy", "delta"),
                &Limits::default()
            ),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn target_hash_mismatch_is_reported() {
        let mut delta = fixture("empty-literal", "delta");
        let info = inspect_pa30(&delta, &Limits::default()).unwrap();
        let position = delta
            .windows(info.target_hash.len())
            .position(|bytes| bytes == info.target_hash)
            .unwrap();
        delta[position] ^= 1;
        assert!(matches!(
            apply_pa30(&[], &delta, &Limits::default()),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn limits_are_checked_before_allocating_output() {
        let limits = Limits {
            max_output_bytes: 2,
            ..Limits::default()
        };
        assert!(matches!(
            apply_pa30(&[], &fixture("empty-literal", "delta"), &limits),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        let mut state = 0x0507_1504_5594_u64;
        let limits = Limits {
            max_output_bytes: 256,
            max_source_bytes: 256,
            max_patch_bytes: 256,
            max_window_bytes: 256,
            ..Limits::default()
        };
        for length in 12..128 {
            for _ in 0..32 {
                let mut delta = vec![0; length];
                for byte in &mut delta {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                delta[..4].copy_from_slice(b"PA30");
                let _ = apply_pa30(&[], &delta, &limits);
            }
        }
    }

    #[derive(Default)]
    struct Writer {
        bytes: Vec<u8>,
        position: usize,
    }

    impl Writer {
        fn bits(&mut self, value: u64, count: usize) {
            for shift in 0..count {
                if self.position / 8 == self.bytes.len() {
                    self.bytes.push(0);
                }
                self.bytes[self.position / 8] |=
                    (((value >> shift) & 1) as u8) << (self.position % 8);
                self.position += 1;
            }
        }
        fn number(&mut self, value: u64) {
            let nibbles = ((64 - value.max(1).leading_zeros()) as usize).div_ceil(4);
            self.bits(1 << (nibbles - 1), nibbles);
            self.bits(value, nibbles * 4);
        }
        fn buffer(&mut self, buffer: &[u8]) {
            self.number(buffer.len() as u64);
            while !self.position.is_multiple_of(8) {
                self.bits(0, 1);
            }
            for &byte in buffer {
                self.bits(u64::from(byte), 8);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            let padding = (8 - self.position % 8) % 8;
            self.bytes[0] |= padding as u8;
            self.bytes
        }
    }

    fn outer(info: &Pa30Info, preprocessing: &[u8], patch: &[u8]) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.bits(0, 3);
        for number in [
            info.file_type_set,
            info.file_type,
            info.flags,
            info.target_size as u64,
            u64::from(info.target_hash_algorithm),
        ] {
            writer.number(number);
        }
        writer.buffer(&info.target_hash);
        writer.buffer(preprocessing);
        writer.buffer(patch);
        let mut result = b"PA30".to_vec();
        result.extend_from_slice(&info.target_file_time.to_le_bytes());
        result.extend_from_slice(&writer.finish());
        result
    }

    #[test]
    fn absent_target_hash_requires_successful_external_verifier() {
        let original = fixture("empty-literal", "delta");
        let parsed = parse(&original, &Limits::default()).unwrap();
        let mut info = parsed.info.clone();
        info.target_hash_algorithm = 0;
        info.target_hash.clear();
        let delta = outer(&info, parsed.preprocessing, parsed.patch);
        assert!(apply_pa30(&[], &delta, &Limits::default()).is_err());
        assert!(
            apply_pa30_with_verifier(&[], &delta, &Limits::default(), |_| {
                Err(Error::Integrity("external verifier refused"))
            })
            .is_err()
        );
        let expected = fixture("empty-literal", "target");
        assert_eq!(
            apply_pa30_with_verifier(&[], &delta, &Limits::default(), |output| {
                if output == expected {
                    Ok(())
                } else {
                    Err(Error::Integrity("unexpected output"))
                }
            })
            .unwrap(),
            expected
        );
        info.target_hash.push(0);
        assert!(
            apply_pa30_with_verifier(
                &[],
                &outer(&info, parsed.preprocessing, parsed.patch),
                &Limits::default(),
                |_| Ok(())
            )
            .is_err()
        );
    }

    #[test]
    fn external_verifier_is_required_even_with_intrinsic_hash() {
        let delta = fixture("empty-literal", "delta");
        assert!(
            apply_pa30_with_verifier(&[], &delta, &Limits::default(), |_| {
                Err(Error::Integrity("external verifier refused"))
            })
            .is_err()
        );
    }

    #[test]
    fn executable_graph_must_match_source_architecture() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa30-pe32-native/basic");
        for (platform, graph_type) in [("anycpu", 32), ("x64", 16)] {
            let directory = root.join(platform);
            let source = std::fs::read(directory.join("source.dll")).unwrap();
            let delta = std::fs::read(directory.join("legacy/forward-0.delta")).unwrap();
            let parsed = parse(&delta, &Limits::default()).unwrap();
            let mut info = parsed.info.clone();
            info.file_type = graph_type;
            info.file_type_set = 245;
            let delta = outer(&info, parsed.preprocessing, parsed.patch);
            assert!(matches!(
                apply_pa30(&source, &delta, &Limits::default()),
                Err(Error::Invalid(
                    "PA30 source architecture differs from graph"
                ))
            ));
        }
    }

    #[test]
    fn unsupported_transforms_remain_inspectable_and_cannot_be_applied() {
        let delta = fixture("empty-literal", "delta");
        let parsed = parse(&delta, &Limits::default()).unwrap();
        let mut info = parsed.info.clone();
        for flags in [1 << 29, 1 << 32, 1 << 63] {
            info.flags = flags;
            let encoded = outer(&info, &[], parsed.patch);
            assert_eq!(
                inspect_pa30(&encoded, &Limits::default()).unwrap().flags,
                flags
            );
            assert!(matches!(
                apply_pa30(&[], &encoded, &Limits::default()),
                Err(Error::Unsupported(_))
            ));
        }
        info.flags = 0;
        info.file_type = 32;
        assert!(matches!(
            apply_pa30(&[], &outer(&info, &[], parsed.patch), &Limits::default()),
            Err(Error::Unsupported(_))
        ));
        info.file_type = 1;
        assert!(matches!(
            apply_pa30(&[], &outer(&info, &[0], parsed.patch), &Limits::default()),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_nonempty_rift_table_is_rejected() {
        let delta = fixture("empty-literal", "delta");
        let parsed = parse(&delta, &Limits::default()).unwrap();
        let mut patch = parsed.patch.to_vec();
        patch[0] |= 1 << 3;
        assert!(matches!(
            apply_pa30(&[], &outer(&parsed.info, &[], &patch), &Limits::default()),
            Err(Error::Invalid(_) | Error::Limit(_))
        ));
    }

    #[test]
    fn incorrect_short_source_cannot_establish_target_hash() {
        assert!(matches!(
            apply_pa30(b"abc", &fixture("source-copy", "delta"), &Limits::default()),
            Err(Error::Integrity(_))
        ));
    }

    #[test]
    fn declared_huge_target_is_rejected_before_decoding() {
        let delta = fixture("empty-literal", "delta");
        let parsed = parse(&delta, &Limits::default()).unwrap();
        let mut info = parsed.info;
        info.target_size = usize::MAX;
        assert!(matches!(
            apply_pa30(&[], &outer(&info, &[], parsed.patch), &Limits::default()),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn invalid_padding_and_trailing_bytes_are_rejected() {
        let mut delta = fixture("empty-literal", "delta");
        delta.push(0);
        assert!(matches!(
            inspect_pa30(&delta, &Limits::default()),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(Bits::new(&[7]), Err(Error::Invalid(_))));
        assert!(matches!(Bits::new(&[0xf3]), Err(Error::Invalid(_))));
    }

    #[test]
    fn malformed_varints_and_huffman_trees_are_rejected() {
        assert!(Bits::new(&[0; 10]).unwrap().number(16).is_err());
        assert!(Huffman::new(&[1, 1, 1], 16).is_err());
        assert!(Huffman::new(&[2, 2], 16).is_ok());
        assert!(Huffman::new(&[2, 3], 16).is_err());
        assert!(Huffman::new(&[17], 16).is_err());
        let mut bits = Bits::new(&[0]).unwrap();
        assert!(
            Huffman::new(&[0; 16], 16)
                .unwrap()
                .decode(&mut bits)
                .is_err()
        );
    }

    #[test]
    fn incomplete_huffman_tables_decode_assigned_codes_and_reject_holes() {
        let table = Huffman::new(&[0, 2, 2, 0], 16).unwrap();
        for (code, expected) in [(0, 1), (2, 2)] {
            let mut writer = encode::Writer::new(16).unwrap();
            writer.bits(code, 2).unwrap();
            let encoded = writer.finish();
            assert_eq!(
                table.decode(&mut Bits::new(&encoded).unwrap()).unwrap(),
                expected
            );
        }
        let mut writer = encode::Writer::new(16).unwrap();
        writer.bits(1, 2).unwrap();
        let encoded = writer.finish();
        assert!(table.decode(&mut Bits::new(&encoded).unwrap()).is_err());
    }

    #[test]
    fn arm_normalized_dictionary_matches_independent_native_source_copy_probe() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa30-arm-native/normalization");
        let source = std::fs::read(root.join("source.exe")).unwrap();
        let delta = std::fs::read(root.join("probe.delta")).unwrap();
        let expected = std::fs::read(root.join("native.bin")).unwrap();
        let parsed = parse(&delta, &Limits::default()).unwrap();
        let (actual, _) = prepare_source(&source, &parsed, &Limits::default()).unwrap();
        assert_eq!(actual.as_ref(), expected);
        // Research probes may inspect normalization; production reconstruction
        // continues to require a supported declared target digest.
        assert!(apply_pa30(&source, &delta, &Limits::default()).is_err());
    }

    #[test]
    fn native_adaptive_streams_reconstruct_with_incomplete_huffman_tables() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa30-adaptive-native");
        let cases: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let mut incomplete = 0;
        for case in cases.as_array().unwrap() {
            let delta = std::fs::read(root.join(case["delta"].as_str().unwrap())).unwrap();
            let target = std::fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
            let patch = if delta.starts_with(b"PA31") {
                let mut outer = Bits::new(&delta[12..]).unwrap();
                outer.buffer().unwrap();
                outer.buffer().unwrap();
                outer.buffer().unwrap()
            } else {
                parse(&delta, &Limits::default()).unwrap().patch
            };
            let mut bits = Bits::new(patch).unwrap();
            rift::RiftTable::read(&mut bits, &Limits::default()).unwrap();
            for block in parameters(&mut bits, 0, target.len(), &Limits::default()).unwrap() {
                for tree in [&block.main, &block.length, &block.aligned] {
                    let kraft: usize = tree
                        .counts
                        .iter()
                        .enumerate()
                        .skip(1)
                        .map(|(length, &count)| count << (16 - length))
                        .sum();
                    if kraft != 0 && kraft < 1 << 16 {
                        incomplete += 1;
                    }
                }
            }
            let output = if delta.starts_with(b"PA31") {
                apply_pa31(&[], &delta, &Limits::default()).unwrap()
            } else {
                apply_pa30(&[], &delta, &Limits::default()).unwrap()
            };
            assert_eq!(output, target);
        }
        assert!(incomplete > 0);
    }

    #[test]
    fn generation_limit_flags_do_not_enable_transforms() {
        let delta = fixture("empty-literal", "delta");
        let parsed = parse(&delta, &Limits::default()).unwrap();
        let mut info = parsed.info;
        info.flags = 0x60000;
        info.file_type_set = 245;
        assert_eq!(
            apply_pa30(&[], &outer(&info, &[], parsed.patch), &Limits::default()).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn empty_target_still_requires_valid_target_hash() {
        let delta = fixture("empty-literal", "delta");
        let mut info = inspect_pa30(&delta, &Limits::default()).unwrap();
        info.target_size = 0;
        info.target_hash = Md5::digest([]).to_vec();
        assert_eq!(
            apply_pa30(&[], &outer(&info, &[], &[0x13]), &Limits::default()).unwrap(),
            Vec::<u8>::new()
        );
        info.target_hash_algorithm = 0;
        info.target_hash.clear();
        assert!(matches!(
            apply_pa30(&[], &outer(&info, &[], &[0x13]), &Limits::default()),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn parameter_memory_limit_covers_default_and_composite_trees() {
        let limits = Limits {
            max_parameter_bytes: 4096,
            ..Limits::default()
        };
        for name in ["empty-literal", "empty-random"] {
            assert!(matches!(
                apply_pa30(&[], &fixture(name, "delta"), &limits),
                Err(Error::Limit("PA30 parameter memory"))
            ));
        }
    }

    #[test]
    fn invalid_hash_metadata_is_rejected_before_decoding_patch() {
        let mut info =
            inspect_pa30(&fixture("empty-literal", "delta"), &Limits::default()).unwrap();
        info.target_hash.clear();
        assert!(matches!(
            apply_pa30(&[], &outer(&info, &[], &[]), &Limits::default()),
            Err(Error::Invalid("PA30 hash length"))
        ));
        info.target_hash_algorithm = 0;
        assert!(matches!(
            apply_pa30(&[], &outer(&info, &[], &[]), &Limits::default()),
            Err(Error::Unsupported("PA30 target hash algorithm"))
        ));
    }

    #[test]
    fn input_limits_are_checked_before_parsing() {
        let limits = Limits {
            max_source_bytes: 0,
            max_patch_bytes: 0,
            ..Limits::default()
        };
        assert!(matches!(
            apply_pa30(b"x", &[], &limits),
            Err(Error::Limit("PA30 source size"))
        ));
        assert!(matches!(
            apply_pa30(&[], b"x", &limits),
            Err(Error::Limit("PA30 delta size"))
        ));
    }
}
