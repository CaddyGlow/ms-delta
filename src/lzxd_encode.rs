//! Independently implemented MS-PATCH verbatim-block encoder.
use crate::{Error, Limits, Result};

const FRAME: usize = 32768;
const SYMBOLS: usize = 2576;

struct Bits {
    bytes: Vec<u8>,
    word: u16,
    used: u8,
}
impl Bits {
    fn new() -> Result<Self> {
        // At most 2825 tree lengths at five bits each, 240 pretree bits,
        // 28 header bits and 32768 literals at twelve bits each: < 65535
        // bytes including word padding. Matches cost fewer bits per byte.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(65535)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            bytes,
            word: 0,
            used: 0,
        })
    }
    fn put(&mut self, value: usize, count: usize) {
        for shift in (0..count).rev() {
            self.word |= (((value >> shift) & 1) as u16) << (15 - self.used);
            self.used += 1;
            if self.used == 16 {
                self.flush();
            }
        }
    }
    fn flush(&mut self) {
        self.bytes.extend_from_slice(&self.word.to_le_bytes());
        self.word = 0;
        self.used = 0;
    }
    fn finish(mut self) -> Vec<u8> {
        if self.used != 0 {
            self.flush();
        }
        self.bytes
    }
}

struct Tree {
    lengths: [u8; SYMBOLS],
    codes: [u16; SYMBOLS],
    count: usize,
}
impl Tree {
    fn new(count: usize) -> Self {
        let depth = count.ilog2() as usize;
        let shallow = (1 << (depth + 1)) - count;
        let mut result = Self {
            lengths: [0; SYMBOLS],
            codes: [0; SYMBOLS],
            count,
        };
        for symbol in 0..count {
            result.lengths[symbol] = (depth + usize::from(symbol >= shallow)) as u8;
            result.codes[symbol] = if symbol < shallow {
                symbol
            } else {
                shallow * 2 + symbol - shallow
            } as u16;
        }
        result
    }
    fn emit(&self, bits: &mut Bits, symbol: usize) {
        bits.put(self.codes[symbol] as usize, self.lengths[symbol] as usize);
    }
    fn describe(&self, bits: &mut Bits, start: usize, end: usize, previous: bool, pre: &Tree) {
        for &length in &pre.lengths[..20] {
            bits.put(length as usize, 4);
        }
        for &length in &self.lengths[start..end] {
            pre.emit(
                bits,
                if previous {
                    0
                } else {
                    (17 - length as usize) % 17
                },
            );
        }
    }
}

fn footer(slot: usize) -> usize {
    if slot < 4 {
        0
    } else {
        ((slot / 2) - 1).min(17)
    }
}
fn base(slot: usize) -> usize {
    if slot < 3 {
        0
    } else if slot < 36 {
        ((2 + (slot & 1)) << footer(slot)) - 2
    } else {
        262142 + (slot - 36) * 131072
    }
}
fn hash(bytes: &[u8], mask: usize) -> usize {
    (u32::from_le_bytes(bytes[..4].try_into().expect("four-byte hash")).wrapping_mul(0x9e3779b1)
        as usize
        >> 8)
        & mask
}
fn byte(source: &[u8], target: &[u8], position: usize) -> u8 {
    if position < source.len() {
        source[position]
    } else {
        target[position - source.len()]
    }
}

/// Create a chunk-prefixed MS-PATCH stream with reference and output matches.
/// Fixed complete Huffman trees are used; Intel preprocessing is disabled.
pub fn create_lzxd(
    source: &[u8],
    target: &[u8],
    window_order: u8,
    limits: &Limits,
) -> Result<Vec<u8>> {
    create_lzxd_intel(source, target, window_order, None, limits)
}

/// The first 0x8000 chunks are subject to Intel `E8` translation (the decoder's `frame_start`
/// bound of 0x4000_0000 bytes).
const E8_TRANSLATED_BYTES: usize = 0x4000_0000;

/// Forward Intel `E8` translation of one chunk, the exact inverse of the decoder's
/// `inverse_delta_e8`: `chunk_start` is the chunk's offset in the output stream and `file_size`
/// the translation size carried in the stream header. Positions up to the last ten bytes of the
/// chunk are scanned; after any `E8` the next five bytes are skipped whether or not the operand
/// was translated.
fn translate_e8_chunk(chunk: &mut [u8], chunk_start: usize, file_size: i32) {
    let mut position = 0;
    while position + 10 < chunk.len() {
        if chunk[position] != 0xe8 {
            position += 1;
            continue;
        }
        let relative = i32::from_le_bytes([
            chunk[position + 1],
            chunk[position + 2],
            chunk[position + 3],
            chunk[position + 4],
        ]);
        let current = (chunk_start + position) as i32;
        if relative >= -current && relative < file_size {
            let absolute = if relative < file_size.wrapping_sub(current) {
                relative.wrapping_add(current)
            } else {
                relative.wrapping_sub(file_size)
            };
            chunk[position + 1..position + 5].copy_from_slice(&absolute.to_le_bytes());
        }
        position += 5;
    }
}

/// Like [`create_lzxd`], optionally with Intel `E8` call translation: `intel_size` is the
/// translation size written into the first chunk header (the new file size in `mspatchc.dll`
/// output) and the target is translated chunk by chunk before it is encoded, so matches see the
/// translated bytes exactly as the decoder's history does. `Some(0)` writes the flag and a zero
/// size, which disables the translation on decode.
pub(crate) fn create_lzxd_intel(
    source: &[u8],
    target: &[u8],
    window_order: u8,
    intel_size: Option<u32>,
    limits: &Limits,
) -> Result<Vec<u8>> {
    let translated;
    let target = match intel_size {
        Some(size) if size != 0 && size <= i32::MAX as u32 => {
            let mut copy = target.to_vec();
            for (index, chunk) in copy.chunks_mut(FRAME).enumerate() {
                if index * FRAME >= E8_TRANSLATED_BYTES {
                    break;
                }
                translate_e8_chunk(chunk, index * FRAME, size as i32);
            }
            translated = copy;
            &translated[..]
        }
        Some(size) if size > i32::MAX as u32 => return Err(Error::Invalid("E8 translation size")),
        _ => target,
    };
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("source size"));
    }
    if target.len() > limits.max_output_bytes {
        return Err(Error::Limit("target size"));
    }
    if !(17..=25).contains(&window_order) {
        return Err(Error::Invalid("LZX Delta window order"));
    }
    let window = 1usize << window_order;
    if window > limits.max_window_bytes {
        return Err(Error::Limit("LZX Delta window"));
    }
    if source.len() > window - 3 {
        return Err(Error::Invalid("reference exceeds LZX Delta window"));
    }
    if target.is_empty() {
        return Ok(Vec::new());
    }
    if limits.max_patch_bytes < 2 {
        return Err(Error::Limit("patch size"));
    }
    source
        .len()
        .checked_add(target.len())
        .ok_or(Error::Limit("combined input size"))?;
    let slots = match window_order {
        20 => 42,
        21..=25 => 34 + (1usize << (window_order - 17)),
        _ => usize::from(window_order) * 2,
    };
    let workspace = std::mem::size_of::<Tree>() * 3 + 65535;
    let available = limits
        .max_parameter_bytes
        .checked_sub(workspace)
        .ok_or(Error::Limit("encoder workspace"))?
        / std::mem::size_of::<usize>();
    if available == 0 {
        return Err(Error::Limit("encoder match table"));
    }
    let entries = 1usize << available.min(65536).ilog2();
    let mut table = Vec::new();
    table
        .try_reserve_exact(entries)
        .map_err(|_| Error::Allocation)?;
    table.resize(entries, usize::MAX);
    let mask = entries - 1;
    for pos in 0..source.len().saturating_sub(3) {
        table[hash(&source[pos..], mask)] = pos;
    }
    let main = Tree::new(256 + slots * 8);
    let length = Tree::new(249);
    let pre = Tree::new(20);
    let mut recent = [1usize; 3];
    let mut result = Vec::new();
    for (frame_index, chunk) in target.chunks(FRAME).enumerate() {
        let frame_start = frame_index * FRAME;
        let mut bits = Bits::new()?;
        if frame_index == 0 {
            match intel_size {
                Some(size) => {
                    bits.put(1, 1);
                    bits.put((size >> 16) as usize, 16);
                    bits.put((size & 0xffff) as usize, 16);
                }
                None => bits.put(0, 1),
            }
        }
        bits.put(1, 3);
        bits.put(chunk.len() >> 8, 16);
        bits.put(chunk.len() & 255, 8);
        main.describe(&mut bits, 0, 256, frame_index != 0, &pre);
        main.describe(&mut bits, 256, main.count, frame_index != 0, &pre);
        length.describe(&mut bits, 0, length.count, frame_index != 0, &pre);
        let mut pos = frame_start;
        let end = frame_start + chunk.len();
        while pos < end {
            let absolute = source.len() + pos;
            let mut match_len = 0;
            let mut offset = 0;
            if end - pos >= 4 {
                let candidate = table[hash(&target[pos..], mask)];
                if candidate < absolute && absolute - candidate <= window - 3 {
                    let maximum = (end - pos).min(256);
                    while match_len < maximum
                        && byte(source, target, candidate + match_len) == target[pos + match_len]
                    {
                        match_len += 1;
                    }
                    offset = absolute - candidate;
                }
            }
            let consumed = if match_len >= 4 {
                let slot = if let Some(slot) = recent.iter().position(|&value| value == offset) {
                    recent.swap(slot, 0);
                    slot
                } else {
                    let slot = (3..slots)
                        .find(|&slot| {
                            offset >= base(slot) && offset < base(slot) + (1 << footer(slot))
                        })
                        .ok_or(Error::Invalid("unrepresentable match offset"))?;
                    recent = [offset, recent[0], recent[1]];
                    slot
                };
                let reduced = match_len - 2;
                main.emit(&mut bits, 256 + slot * 8 + reduced.min(7));
                if reduced >= 7 {
                    length.emit(&mut bits, reduced - 7);
                }
                if slot >= 3 {
                    bits.put(offset - base(slot), footer(slot));
                }
                match_len
            } else {
                main.emit(&mut bits, target[pos] as usize);
                1
            };
            for inserted in pos..pos + consumed {
                if target.len() - inserted >= 4 {
                    table[hash(&target[inserted..], mask)] = source.len() + inserted;
                }
            }
            pos += consumed;
        }
        let payload = bits.finish();
        let payload_len =
            u16::try_from(payload.len()).map_err(|_| Error::Limit("encoded chunk"))?;
        let additional = payload.len() + 2;
        if additional > limits.max_patch_bytes.saturating_sub(result.len()) {
            return Err(Error::Limit("patch size"));
        }
        result
            .try_reserve_exact(additional)
            .map_err(|_| Error::Allocation)?;
        result.extend_from_slice(&payload_len.to_le_bytes());
        result.extend_from_slice(&payload);
    }
    Ok(result)
}
