//! Independent Thumb ARM dictionary branch and paired-address transforms.
use super::{pe::PeLayout, rift::RiftTable};
use crate::{Error, Result};
fn read16(bytes: &[u8], offset: usize) -> Result<u16> {
    let data = bytes
        .get(offset..offset.checked_add(2).ok_or(Error::Invalid("ARM offset"))?)
        .ok_or(Error::Invalid("ARM halfword bounds"))?;
    Ok(u16::from_le_bytes(
        data.try_into()
            .map_err(|_| Error::Invalid("ARM halfword"))?,
    ))
}
fn read32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from(read16(bytes, offset)?) | (u32::from(read16(bytes, offset + 2)?) << 16))
}
fn write16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn map(used: &RiftTable, value: u32) -> u32 {
    used.map(i64::from(value)) as u32
}
fn immediate(first: u16, second: u16) -> u16 {
    ((first & 15) << 12) | ((first & 0x400) << 1) | ((second & 0x7000) >> 4) | (second & 255)
}

pub(super) fn address(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from(immediate(
        read16(bytes, offset)?,
        read16(bytes, offset + 2)?,
    )) | (u32::from(immediate(
        read16(bytes, offset + 4)?,
        read16(bytes, offset + 6)?,
    )) << 16))
}
pub(super) fn set_address(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    for (position, imm) in [(offset, value as u16), (offset + 4, (value >> 16) as u16)] {
        let first = read16(bytes, position)?;
        let second = read16(bytes, position + 2)?;
        write16(
            bytes,
            position,
            (first & !0x40f) | (imm >> 12) | ((imm & 0x800) >> 1),
        );
        write16(
            bytes,
            position + 2,
            (second & 0x8f00) | ((imm & 0x700) << 4) | (imm & 255),
        );
    }
    Ok(())
}
fn branch_offset(first: u16, second: u16) -> i32 {
    let sign = (u32::from(first) >> 10) & 1;
    let i1 = (!(u32::from(second) >> 13) ^ sign) & 1;
    let i2 = (!(u32::from(second) >> 11) ^ sign) & 1;
    let raw = (sign << 24)
        | (i1 << 23)
        | (i2 << 22)
        | (u32::from(first & 0x3ff) << 12)
        | (u32::from(second & 0x7ff) << 1);
    (raw << 7) as i32 >> 7
}
fn set_branch(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let first = read16(bytes, offset)?;
    let second = read16(bytes, offset + 2)?;
    let sign = value >> 31;
    let j1 = (!(value >> 23) ^ sign) & 1;
    let j2 = (!(value >> 22) ^ sign) & 1;
    write16(
        bytes,
        offset,
        (first & 0xf800) | (((value >> 12) as u16) & 0x3ff) | ((sign as u16) << 10),
    );
    write16(
        bytes,
        offset + 2,
        (second & 0xd000)
            | ((j1 as u16) << 13)
            | ((j2 as u16) << 11)
            | (((value >> 1) as u16) & 0x7ff),
    );
    Ok(())
}
fn mov_pair(bytes: &[u8], offset: usize) -> Result<Option<u32>> {
    let first = read16(bytes, offset)?;
    let second = read16(bytes, offset + 2)?;
    let third = read16(bytes, offset + 4)?;
    let fourth = read16(bytes, offset + 6)?;
    if third & 0xf800 != 0xf000
        || third & 0x3f0 != 0x2c0
        || fourth & 0x8000 != 0
        || second & 0x8000 != 0
    {
        return Ok(None);
    }
    if first & 0xf800 == 0xf000 && first & 0x3f0 == 0x240 {
        return address(bytes, offset).map(Some);
    }
    if first & 0xf800 == 0xf000 && first & 0x3e0 == 0x40 && first & 15 == 15 {
        let encoded = u32::from(second & 255)
            | ((u32::from((second >> 12) & 7) | ((u32::from(first & 0x400 != 0)) << 3)) << 8);
        let low = match encoded & 15 {
            0 => encoded & 255,
            1 => encoded & 0xff00ff,
            2 => encoded & 0xff00ff00,
            3 => encoded & 0xffffff00,
            shift => (encoded & (143 << shift)) | 0x80,
        };
        return Ok(Some(low | (u32::from(immediate(third, fourth)) << 16)));
    }
    Ok(None)
}
pub(super) fn pdata(layout: &PeLayout, output: &mut [u8], used: &RiftTable) -> Result<()> {
    super::arm64::pdata(layout, output, used)
}
pub(super) fn disassemble(
    layout: &PeLayout,
    output: &mut [u8],
    hints: &[u8],
    used: &RiftTable,
    image_base: u32,
) -> Result<()> {
    let Some((rva, size)) = layout.directory(3) else {
        return Ok(());
    };
    let start = layout.offset(rva, size)?;
    let mut work = output.len().saturating_mul(4);
    for entry in (start..start + size / 8 * 8).step_by(8) {
        let begin = read32(output, entry)?;
        let unwind = read32(output, entry + 4)?;
        let length = if unwind & 3 != 0 {
            ((unwind >> 1) & 0xffe) as usize
        } else {
            let header = layout.offset(unwind, 4)?;
            ((read32(output, header)? & 0x3ffff) * 2) as usize
        };
        if length == 0 {
            continue;
        }
        let pointer = layout.offset(begin, length)?;
        let offset = pointer
            .checked_sub(1)
            .ok_or(Error::Invalid("ARM Thumb function origin"))?;
        let available = length
            .checked_add(1)
            .ok_or(Error::Invalid("ARM function length"))?;
        if offset + available > output.len() {
            return Err(Error::Invalid("ARM function bounds"));
        }
        work = work
            .checked_sub(available)
            .ok_or(Error::Limit("ARM disassembly work"))?;
        let mut position = 0usize;
        while position < available {
            let at = offset + position;
            let hint = pointer + position;
            if hint >= hints.len() {
                return Err(Error::Invalid("ARM hint bounds"));
            }
            if hints[hint] & 3 != 0 {
                position += (available - position).min(2);
                continue;
            }
            if available - position < 2 {
                break;
            }
            let first = read16(output, at)?;
            let wide = matches!(first & 0xf800, 0xe800 | 0xf000 | 0xf800);
            let mut width = if wide {
                (available - position).min(4)
            } else {
                2
            };
            let mut branch = None;
            let mut absolute = None;
            if wide && width == 4 {
                let second = read16(output, at + 2)?;
                if first & 0xf000 == 0xf000
                    && first & 0x800 == 0
                    && second & 0xc000 == 0xc000
                    && second & 0x3800 == 0x3800
                {
                    branch = Some(branch_offset(first, second));
                } else if available - position >= 8 {
                    absolute = mov_pair(output, at)?;
                    if absolute.is_some() {
                        width = 8;
                    }
                }
            }
            if let Some(delta) =
                (1..width).find(|&delta| hints.get(hint + delta).is_none_or(|byte| byte & 2 != 0))
            {
                position += delta;
                continue;
            }
            if let Some(delta) = branch {
                if (pointer + position) as i64 + i64::from(delta) >= 0 {
                    let pc = begin
                        .wrapping_sub(1)
                        .wrapping_add(position as u32)
                        .wrapping_add(width as u32);
                    set_branch(
                        output,
                        at,
                        map(used, pc.wrapping_add(delta as u32)).wrapping_sub(map(used, pc)),
                    )?;
                }
            } else if let Some(value) = absolute {
                set_address(
                    output,
                    at,
                    map(used, value.wrapping_sub(image_base)).wrapping_add(image_base),
                )?;
            }
            position += width;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thumb_wide_addresses_and_signed_branch_offsets_roundtrip() {
        let mut pair = [0x40, 0xf2, 0x00, 0x00, 0xc0, 0xf2, 0x00, 0x00];
        for value in [0, 1, 0x12345678, u32::MAX] {
            set_address(&mut pair, 0, value).unwrap();
            assert_eq!(address(&pair, 0).unwrap(), value);
        }
        let mut branch = [0x00, 0xf0, 0x00, 0xf8];
        for delta in [0, 2, 4096, -2, -4096] {
            set_branch(&mut branch, 0, delta as u32).unwrap();
            assert_eq!(
                branch_offset(read16(&branch, 0).unwrap(), read16(&branch, 2).unwrap()),
                delta
            );
        }
    }
    #[test]
    fn native_arm_flag_matrix_reconstructs_exact_targets() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa30-arm-native/arm");
        let cases: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                .unwrap();
        for case in cases.as_array().unwrap() {
            let source = std::fs::read(directory.join(case["source"].as_str().unwrap())).unwrap();
            let target = std::fs::read(directory.join(case["target"].as_str().unwrap())).unwrap();
            let delta = std::fs::read(directory.join(case["delta"].as_str().unwrap())).unwrap();
            let actual = crate::pa30::apply_pa30(&source, &delta, &crate::Limits::default());
            assert_eq!(
                actual.unwrap_or_else(|error| panic!("{}: {error}", case["name"])),
                target,
                "{}",
                case["name"]
            );
        }
    }
}
