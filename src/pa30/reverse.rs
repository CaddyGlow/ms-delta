//! Native PA31 playback records, independently implemented from the pinned DLL.
use super::{Bits, Huffman, default_lengths, lzms_frame, rift::RiftTable};
use crate::{Error, Limits, Result};

pub(super) fn apply(
    source: &[u8],
    payload: &[u8],
    size: usize,
    limits: &Limits,
) -> Result<Vec<u8>> {
    if size > limits.max_output_bytes || source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA31 playback source or output size"));
    }
    if payload.len() > limits.max_patch_bytes {
        return Err(Error::Limit("PA31 playback payload size"));
    }
    let mut bits = Bits::new(payload)?;
    if bits.read(32)? != 0x4d53_5250 {
        return Err(Error::Invalid("PA31 playback signature"));
    }
    if bits.read(32)? != 1 {
        return Err(Error::Unsupported("PA31 playback version"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    output.resize(size, 0);
    let lengths = Huffman::new(&default_lengths(252), 16)?;
    let mut work = source
        .len()
        .saturating_add(size)
        .saturating_mul(4)
        .saturating_add(limits.max_parameter_bytes);
    while bits.position < bits.end {
        let record = bits.buffer()?;
        if record.len() > limits.max_parameter_bytes {
            return Err(Error::Limit("PA31 playback record size"));
        }
        let mut record_bits = Bits::new(record)?;
        let kind = record_bits.read(32)?;
        if !matches!(kind, 0..=2) {
            return Err(Error::Unsupported("PA31 playback record kind"));
        }
        if record_bits.read(32)? != 1 {
            return Err(Error::Unsupported("PA31 playback record version"));
        }
        let compressed = if kind == 1 { record_bits.read(32)? } else { 0 };
        let entries = RiftTable::read(&mut record_bits, limits)?;
        work = work
            .checked_sub(entries.entries().len())
            .ok_or(Error::Limit("PA31 playback work"))?;
        match kind {
            0 => {
                for &(left, right) in entries.entries() {
                    let length = signed_number(&lengths, &mut record_bits)? as u64;
                    let (left, right) = (left as u64, right as u64);
                    if left > size as u64 || right >= source.len() as u64 {
                        continue;
                    }
                    let length = length
                        .min(size as u64 - left)
                        .min(source.len() as u64 - right) as usize;
                    work = work
                        .checked_sub(length)
                        .ok_or(Error::Limit("PA31 playback work"))?;
                    let (left, right) = (left as usize, right as usize);
                    output[left..left + length].copy_from_slice(&source[right..right + length]);
                }
            }
            1 => {
                let literal = record_bits.buffer()?;
                let decoded;
                let literal = if compressed != 0 {
                    decoded =
                        lzms_frame::decompress_algorithm(literal, limits.max_parameter_bytes, 4)?;
                    decoded.as_slice()
                } else {
                    literal
                };
                let mut position = 0usize;
                for &(left, length) in entries.entries() {
                    let left = usize::try_from(left)
                        .map_err(|_| Error::Invalid("PA31 playback literal position"))?;
                    let length = usize::try_from(length)
                        .map_err(|_| Error::Invalid("PA31 playback literal length"))?;
                    let end = left
                        .checked_add(length)
                        .filter(|&end| end <= size)
                        .ok_or(Error::Invalid("PA31 playback literal target bounds"))?;
                    let data_end = position
                        .checked_add(length)
                        .filter(|&end| end <= literal.len())
                        .ok_or(Error::Invalid("PA31 playback literal bounds"))?;
                    work = work
                        .checked_sub(length)
                        .ok_or(Error::Limit("PA31 playback work"))?;
                    output[left..end].copy_from_slice(&literal[position..data_end]);
                    position = data_end;
                }
                if position != literal.len() {
                    return Err(Error::Invalid("PA31 playback trailing literals"));
                }
            }
            2 => {
                for &(left, byte) in entries.entries().iter().rev() {
                    let left = usize::try_from(left)
                        .map_err(|_| Error::Invalid("PA31 playback byte position"))?;
                    let target = output
                        .get_mut(left)
                        .ok_or(Error::Invalid("PA31 playback byte bounds"))?;
                    *target = byte as u8;
                }
            }
            _ => unreachable!(),
        }
        record_bits.finish()?;
    }
    bits.finish()?;
    Ok(output)
}

fn signed_number(code: &Huffman, bits: &mut Bits<'_>) -> Result<i64> {
    let symbol = code.decode(bits)?;
    let slot = symbol % 126;
    let magnitude = if slot < 4 {
        slot as u64
    } else {
        let width = (slot >> 1) - 1;
        ((2 | (slot & 1)) as u64) << width | bits.read(width)?
    };
    let value =
        i64::try_from(magnitude).map_err(|_| Error::Invalid("PA31 playback integer range"))?;
    Ok(if symbol < 126 { value } else { !value })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn playback_checks_limits_before_parsing_or_allocating() {
        let limits = Limits {
            max_output_bytes: 1,
            max_source_bytes: 1,
            max_patch_bytes: 1,
            ..Limits::default()
        };
        for (source, patch, size) in [
            (&[][..], &[][..], 2),
            (&[0, 0][..], &[][..], 0),
            (&[][..], &[0, 0][..], 0),
        ] {
            assert!(matches!(
                apply(source, patch, size, &limits),
                Err(Error::Limit(_))
            ));
        }
    }

    #[test]
    fn native_playback_restores_pe_cli_and_compressed_deleted_bytes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa31-native/reverse-extended");
        for name in [
            "i386-pointers-forward",
            "amd64-pointers-forward",
            "managed-x64-forward",
            "compressed-delete",
        ] {
            let source = std::fs::read(root.join(format!("{name}.target"))).unwrap();
            let target = std::fs::read(root.join(format!("{name}.source"))).unwrap();
            let patch = std::fs::read(root.join(format!("{name}.reverse"))).unwrap();
            assert_eq!(
                super::super::apply_pa31(&source, &patch, &Limits::default())
                    .unwrap_or_else(|e| panic!("{name}: {e}")),
                target,
                "{name}"
            );
        }
    }

    #[test]
    fn native_playback_recovers_original_sources() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa31-native");
        for name in ["empty", "abc", "identical", "changed", "reverse"] {
            let source = std::fs::read(root.join(format!("{name}.source"))).unwrap();
            let target = std::fs::read(root.join(format!("{name}.target"))).unwrap();
            for flags in [268435456u32, 436207616] {
                let patch =
                    std::fs::read(root.join(format!("reverse/{name}-{flags}.reverse"))).unwrap();
                assert_eq!(
                    super::super::apply_pa31(&target, &patch, &Limits::default()).unwrap(),
                    source,
                    "{name} {flags}"
                );
                for end in 0..patch.len() {
                    assert!(
                        super::super::apply_pa31(&target, &patch[..end], &Limits::default())
                            .is_err()
                    );
                }
                for offset in (0..patch.len()).step_by(7) {
                    for bit in 0..8 {
                        let mut mutated = patch.clone();
                        mutated[offset] ^= 1 << bit;
                        if let Ok(actual) =
                            super::super::apply_pa31(&target, &mutated, &Limits::default())
                        {
                            assert_eq!(actual, source);
                        }
                    }
                }
            }
        }
    }
}
