//! Deterministic RAW PA30 creation using native default Huffman parameters.
use super::{Huffman, check_parameter_budget, default_lengths, remember_offset};
use crate::{Error, Limits, Result};
use sha1::{Digest, Sha1};

/// Creates a RAW PA30 delta with a SHA-1 target digest and zero target FILETIME.
///
/// Source and prior output matches use a bounded four-candidate hash dictionary.
/// PE preprocessing, timestamp preservation, and adaptive Huffman parameters are
/// not used. A valid source is required when applying a source-dependent delta.
pub fn create_pa30(source: &[u8], target: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    create_with_dictionary(source, target, 1, 0, &[], limits)
}

pub(super) fn create_with_dictionary(
    source: &[u8],
    target: &[u8],
    file_type: u64,
    flags: u64,
    preprocessing: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA30 source size"));
    }
    if target.len() > limits.max_output_bytes {
        return Err(Error::Limit("PA30 target size"));
    }
    source
        .len()
        .checked_add(target.len())
        .ok_or(Error::Limit("PA30 dictionary position"))?;
    check_parameter_budget(1, limits)?;
    let main = Codes::new(600)?;
    let length = Codes::new(256)?;
    let aligned = Codes::new(16)?;
    let mut patch = Writer::new(limits.max_patch_bytes)?;
    patch.bits(0, 1)?; // empty base rift
    patch.bits(1, 1)?; // native default Huffman trees
    if !target.is_empty() {
        encode_matches(source, target, limits, &main, &length, &aligned, &mut patch)?;
    }
    let patch = patch.finish();
    let outer_limit = limits
        .max_patch_bytes
        .checked_sub(12)
        .ok_or(Error::Limit("PA30 patch size"))?;
    let mut outer = Writer::new(outer_limit)?;
    let file_type_set = match file_type {
        1 => 1,
        16 | 32 | 64 | 128 => 245,
        _ => 15,
    };
    for value in [file_type_set, file_type, flags, target.len() as u64, 0x8004] {
        outer.number(value)?;
    }
    outer.buffer(&Sha1::digest(target))?;
    outer.buffer(preprocessing)?;
    outer.buffer(&patch)?;
    let outer = outer.finish();
    let mut result = Vec::new();
    result
        .try_reserve_exact(12 + outer.len())
        .map_err(|_| Error::Allocation)?;
    result.extend_from_slice(b"PA30");
    result.extend_from_slice(&0u64.to_le_bytes());
    result.extend_from_slice(&outer);
    Ok(result)
}

struct Codes {
    entries: Vec<(u64, u8)>,
}
impl Codes {
    fn new(size: usize) -> Result<Self> {
        let lengths = default_lengths(size);
        let tree = Huffman::new(&lengths, 16)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(size)
            .map_err(|_| Error::Allocation)?;
        entries.resize(size, (0, 0));
        for (index, &symbol) in tree.symbols.iter().enumerate() {
            let length = usize::from(lengths[symbol]);
            entries[symbol] = (
                (tree.first[length] + index - tree.offsets[length]) as u64,
                length as u8,
            );
        }
        Ok(Self { entries })
    }
    fn write(&self, writer: &mut Writer, symbol: usize) -> Result<()> {
        let &(code, length) = self
            .entries
            .get(symbol)
            .ok_or(Error::Invalid("PA30 encoder symbol"))?;
        for bit in (0..length).rev() {
            writer.bits((code >> bit) & 1, 1)?;
        }
        Ok(())
    }
}

pub(super) struct Writer {
    bytes: Vec<u8>,
    position: usize,
    limit: usize,
}
impl Writer {
    pub(super) fn new(limit: usize) -> Result<Self> {
        let mut writer = Self {
            bytes: Vec::new(),
            position: 0,
            limit,
        };
        writer.bits(0, 3)?;
        Ok(writer)
    }
    pub(super) fn bits(&mut self, value: u64, count: usize) -> Result<()> {
        self.position
            .checked_add(count)
            .ok_or(Error::Limit("PA30 writer size"))?;
        for shift in 0..count {
            if self.position / 8 == self.bytes.len() {
                if self.bytes.len() >= self.limit {
                    return Err(Error::Limit("PA30 patch size"));
                }
                self.bytes.try_reserve(1).map_err(|_| Error::Allocation)?;
                self.bytes.push(0);
            }
            self.bytes[self.position / 8] |= (((value >> shift) & 1) as u8) << (self.position % 8);
            self.position += 1;
        }
        Ok(())
    }
    pub(super) fn number(&mut self, value: u64) -> Result<()> {
        let width = (64 - value.max(1).leading_zeros()) as usize;
        let nibbles = width.div_ceil(4);
        self.bits(1 << (nibbles - 1), nibbles)?;
        self.bits(value, nibbles * 4)
    }
    pub(super) fn buffer(&mut self, bytes: &[u8]) -> Result<()> {
        self.number(bytes.len() as u64)?;
        if !self.position.is_multiple_of(8) {
            self.bits(0, 8 - self.position % 8)?;
        }
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(Error::Limit("PA30 patch size"));
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Allocation)?;
        self.bytes.extend_from_slice(bytes);
        self.position = self
            .position
            .checked_add(
                bytes
                    .len()
                    .checked_mul(8)
                    .ok_or(Error::Limit("PA30 writer size"))?,
            )
            .ok_or(Error::Limit("PA30 writer size"))?;
        Ok(())
    }
    pub(super) fn finish(mut self) -> Vec<u8> {
        self.bytes[0] |= ((8 - self.position % 8) % 8) as u8;
        self.bytes
    }
}

fn encode_matches(
    source: &[u8],
    target: &[u8],
    limits: &Limits,
    main: &Codes,
    length_tree: &Codes,
    aligned: &Codes,
    writer: &mut Writer,
) -> Result<()> {
    let capacity = (limits.max_parameter_bytes / std::mem::size_of::<[usize; 4]>()).min(65536);
    if capacity == 0 {
        return Err(Error::Limit("PA30 encoder dictionary"));
    }
    let buckets = 1usize << (usize::BITS - capacity.leading_zeros() - 1);
    let mut history = Vec::new();
    history
        .try_reserve_exact(buckets)
        .map_err(|_| Error::Allocation)?;
    history.resize(buckets, [usize::MAX; 4]);
    let hash = |bytes: &[u8]| {
        let key = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        (key.wrapping_mul(0x9e37_79b1) as usize >> 8) & (buckets - 1)
    };
    for position in
        source.len().saturating_sub(limits.max_window_bytes)..source.len().saturating_sub(3)
    {
        let candidates = &mut history[hash(&source[position..position + 4])];
        candidates.rotate_right(1);
        candidates[0] = position;
    }
    let byte_at = |index: usize| {
        if index < source.len() {
            source[index]
        } else {
            target[index - source.len()]
        }
    };
    let mut lru = [0usize; 3];
    let mut position = 0;
    while position < target.len() {
        let absolute = source.len() + position;
        let mut best = (0usize, 0usize);
        if target.len() - position >= 4 {
            for &candidate in &history[hash(&target[position..position + 4])] {
                if candidate == usize::MAX || candidate >= absolute {
                    continue;
                }
                let offset = absolute - candidate;
                if offset > limits.max_window_bytes {
                    continue;
                }
                let mut length = 0;
                let maximum = (target.len() - position).min(1 << 20);
                while length < maximum && byte_at(candidate + length) == target[position + length] {
                    length += 1;
                }
                if length > best.0 {
                    best = (length, offset);
                }
            }
        }
        let advance = if best.0 >= 4 {
            write_match(writer, main, length_tree, aligned, &mut lru, best.1, best.0)?;
            best.0
        } else {
            main.write(writer, usize::from(target[position]))?;
            1
        };
        for inserted in position..position + advance {
            if target.len() - inserted < 4 {
                break;
            }
            let candidates = &mut history[hash(&target[inserted..inserted + 4])];
            candidates.rotate_right(1);
            candidates[0] = source.len() + inserted;
        }
        position += advance;
    }
    Ok(())
}

fn write_match(
    writer: &mut Writer,
    main: &Codes,
    length_tree: &Codes,
    aligned: &Codes,
    lru: &mut [usize; 3],
    offset: usize,
    length: usize,
) -> Result<()> {
    let repeat = lru.iter().position(|&previous| previous == offset);
    let (slot, raw_width) = if let Some(index) = repeat {
        (4 + index, 0)
    } else if offset <= 3 {
        (7 + offset, 0)
    } else {
        let width = (usize::BITS - offset.leading_zeros() - 2) as usize;
        (11 + (width - 1) * 2 + ((offset >> width) & 1), width)
    };
    if slot > 70 {
        return Err(Error::Limit("PA30 encoder match distance"));
    }
    let short = if length <= 8 { length - 1 } else { 0 };
    main.write(writer, 256 + (if slot > 42 { 7 } else { slot }) * 8 + short)?;
    if slot > 42 {
        if slot <= 46 {
            writer.bits(0, 1)?;
            writer.bits((slot - 43) as u64, 2)?;
        } else if slot <= 54 {
            writer.bits(1, 1)?;
            writer.bits(0, 1)?;
            writer.bits((slot - 47) as u64, 3)?;
        } else {
            writer.bits(3, 2)?;
            writer.bits((slot - 55) as u64, 4)?;
        }
    }
    if raw_width != 0 {
        let raw = offset & ((1usize << raw_width) - 1);
        if raw_width < 4 {
            writer.bits(raw as u64, raw_width)?;
        } else {
            writer.bits((raw >> 4) as u64, raw_width - 4)?;
            aligned.write(writer, raw & 15)?;
        }
    }
    if short == 0 {
        let extra = length - 8;
        if extra < 256 {
            length_tree.write(writer, extra)?;
        } else {
            length_tree.write(writer, 0)?;
            let width = (usize::BITS - extra.leading_zeros() - 1) as usize;
            writer.bits(1 << (width - 8), width - 7)?;
            writer.bits((extra - (1usize << width)) as u64, width)?;
        }
    }
    remember_offset(lru, offset);
    Ok(())
}
