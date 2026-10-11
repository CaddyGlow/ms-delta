//! Windows Compression API LZMS buffer framing, independently implemented.
use crate::{Error, Result};

pub(super) fn decompress(input: &[u8], maximum: usize) -> Result<Vec<u8>> {
    decompress_algorithm(input, maximum, 5)
}

pub(super) fn decompress_algorithm(input: &[u8], maximum: usize, algorithm: u8) -> Result<Vec<u8>> {
    let header = input.get(..24).ok_or(Error::Invalid("LZMS frame header"))?;
    if header[..4] != [0x0a, 0x51, 0xe5, 0xc0] || header[4..6] != [24, 0] {
        return Err(Error::Invalid("LZMS frame signature or header size"));
    }
    if header[7] != algorithm || !matches!(algorithm, 4 | 5) {
        return Err(Error::Unsupported("compression frame algorithm"));
    }
    let mut crc = !0u32;
    for &byte in header[..6].iter().chain(header[7..].iter()) {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    if (!crc) as u8 != header[6] {
        return Err(Error::Integrity("LZMS frame header checksum"));
    }
    let size = usize::try_from(u64::from_le_bytes(
        header[8..16]
            .try_into()
            .map_err(|_| Error::Invalid("LZMS frame size field"))?,
    ))
    .map_err(|_| Error::Limit("LZMS frame size"))?;
    let chunk = usize::try_from(u64::from_le_bytes(
        header[16..24]
            .try_into()
            .map_err(|_| Error::Invalid("LZMS frame chunk field"))?,
    ))
    .map_err(|_| Error::Limit("LZMS frame chunk size"))?;
    if size > maximum {
        return Err(Error::Limit("LZMS frame size"));
    }
    if chunk == 0 || chunk > 0x400_0000 {
        return Err(Error::Invalid("LZMS frame chunk size"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    output.resize(size, 0);
    let mut consumed = 24usize;
    let mut produced = 0usize;
    while produced < size {
        let length = input
            .get(consumed..consumed + 4)
            .ok_or(Error::Invalid("LZMS frame chunk header"))?;
        let length = u32::from_le_bytes(
            length
                .try_into()
                .map_err(|_| Error::Invalid("LZMS frame chunk length"))?,
        ) as usize;
        consumed += 4;
        let end = consumed
            .checked_add(length)
            .ok_or(Error::Invalid("LZMS frame chunk bounds"))?;
        let block = input
            .get(consumed..end)
            .ok_or(Error::Invalid("LZMS frame chunk bounds"))?;
        let target = (size - produced).min(chunk);
        if length == target {
            output[produced..produced + target].copy_from_slice(block);
        } else {
            let target = &mut output[produced..produced + target];
            if algorithm == 5 {
                ms_compress::lzms::decompress_lzms(block, target)
                    .map_err(|error| Error::Codec(error.to_string()))?;
            } else {
                ms_compress::decompress_xpress_windows(block, target)
                    .map_err(|error| Error::Codec(error.to_string()))?;
            }
        }
        produced += target;
        consumed = end;
    }
    if consumed != input.len() {
        return Err(Error::Invalid("LZMS frame trailing bytes"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_frame(data: &[u8], chunk: usize) -> Vec<u8> {
        let mut frame = vec![0x0a, 0x51, 0xe5, 0xc0, 24, 0, 0, 5];
        frame.extend_from_slice(&(data.len() as u64).to_le_bytes());
        frame.extend_from_slice(&(chunk as u64).to_le_bytes());
        let mut crc = !0u32;
        for byte in frame[..6].iter().chain(frame[7..].iter()) {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        frame[6] = (!crc) as u8;
        for block in data.chunks(chunk) {
            frame.extend_from_slice(&(block.len() as u32).to_le_bytes());
            frame.extend_from_slice(block);
        }
        frame
    }

    #[test]
    fn raw_multichunk_frames_enforce_checksum_size_and_exact_consumption() {
        let expected = b"bounded raw compression framing";
        let frame = raw_frame(expected, 7);
        assert_eq!(decompress(&frame, expected.len()).unwrap(), expected);
        assert!(matches!(
            decompress(&frame, expected.len() - 1),
            Err(Error::Limit(_))
        ));
        for end in 0..frame.len() {
            assert!(decompress(&frame[..end], expected.len()).is_err());
        }
        let mut corrupt = frame.clone();
        corrupt[6] ^= 1;
        assert!(matches!(
            decompress(&corrupt, expected.len()),
            Err(Error::Integrity(_))
        ));
        let mut trailing = frame;
        trailing.push(0);
        assert!(matches!(
            decompress(&trailing, expected.len()),
            Err(Error::Invalid(_))
        ));
    }
}
