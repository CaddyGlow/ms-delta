//! Independently implemented legacy IA64 bundle dictionary transforms.
//! The modern UpdateCompression producer ignores these two IA64 flags; the
//! parent decoder distinguishes the dictionaries by the mandatory target hash.
use super::{pe::PeLayout, rift::RiftTable};
use crate::{Error, Result};

fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(4).ok_or(Error::Invalid("IA64 offset"))?)
            .ok_or(Error::Invalid("IA64 bounds"))?
            .try_into()
            .map_err(|_| Error::Invalid("IA64 word"))?,
    ))
}
fn mapped(used: &RiftTable, rva: i64) -> u32 {
    used.map(rva) as u32
}

// Each ordinary operand layout repeats at the three 41-bit instruction slots.
fn positions(kind: u8) -> ([u8; 60], usize) {
    let mut result = [0; 60];
    let (slot, ranges): (u8, &[(u8, u8)]) = match kind {
        1..=3 => (kind - 1, &[(13, 7), (27, 9), (22, 5), (36, 1)]),
        4..=6 => (kind - 4, &[(6, 7), (20, 13), (36, 1)]),
        7..=9 => (kind - 7, &[(24, 9)]),
        10..=12 => (kind - 10, &[(13, 20), (36, 1)]),
        13..=15 => (kind - 13, &[(6, 7), (26, 2)]),
        16..=17 => (kind - 15, &[(6, 20), (36, 1)]),
        18 => {
            let mut index = 0;
            for (start, count) in [(100, 20), (48, 16), (64, 23), (123, 1)] {
                for bit in start..start + count {
                    result[index] = bit;
                    index += 1;
                }
            }
            return (result, index);
        }
        _ => return (result, 0),
    };
    let mut index = 0;
    for &(start, count) in ranges {
        for bit in start..start + count {
            result[index] = 5 + slot * 41 + bit;
            index += 1;
        }
    }
    (result, index)
}
fn address(bundle: u128, kind: u8) -> i64 {
    let (bits, count) = positions(kind);
    let mut value = 0u64;
    for (index, &bit) in bits[..count].iter().enumerate() {
        value |= (((bundle >> bit) & 1) as u64) << index;
    }
    if count == 0 {
        0
    } else {
        ((value << (64 - count)) as i64) >> (64 - count)
    }
}
fn set_address(bundle: &mut u128, kind: u8, value: u64) {
    let (bits, count) = positions(kind);
    for (index, &bit) in bits[..count].iter().enumerate() {
        *bundle = (*bundle & !(1u128 << bit)) | (u128::from((value >> index) & 1) << bit);
    }
}

fn kinds(bundle: u128) -> ([u8; 6], usize) {
    let template = (bundle & 31) as u8;
    if matches!(template, 6 | 7 | 20 | 21 | 26 | 27 | 30 | 31) {
        return ([0; 6], 0);
    }
    let mut result = [0; 6];
    let mut count = 0;
    let mut push = |kind| {
        result[count] = kind;
        count += 1;
    };
    let fields = |slot: u8| {
        let instruction = (bundle >> (5 + 41 * slot)) as u64;
        (
            (instruction >> 37) & 15,
            (instruction >> 33) & 7,
            (instruction >> 27) & 63,
            (instruction >> 20) & 3,
        )
    };
    let (major, x, six, immediate) = fields(0);
    if !matches!(template, 6 | 7 | 20 | 21 | 26 | 27 | 30 | 31) {
        if matches!(template, 22 | 23) {
            match major {
                2 if matches!(six, 1 | 5) => push(13),
                4 | 5 => push(10),
                7 => {
                    push(10);
                    push(13);
                }
                _ => {}
            }
        } else {
            match major {
                0 if (4..=7).contains(&x) => push(10),
                1 if matches!(x, 1 | 3) => push(4),
                9 if immediate == 1 => push(1),
                _ => {}
            }
        }
    }
    let (major, x, six, immediate) = fields(1);
    if matches!(template, 0..=3 | 16 | 17) {
        match major {
            0 if x == 1 => push(5),
            0 if x == 7 => push(8),
            9 if immediate == 1 => push(2),
            _ => {}
        }
    } else if matches!(template, 12 | 13 | 28 | 29) {
        if major == 0 && x & 1 == 0 && six == 32 {
            push(16);
        }
    } else if matches!(template, 18 | 19 | 22 | 23) {
        match major {
            2 if matches!(six, 1 | 5) => push(14),
            4 | 5 => push(11),
            7 => {
                push(11);
                push(14);
            }
            _ => {}
        }
    } else if !matches!(template, 4 | 5) {
        match major {
            0 if (4..=7).contains(&x) => push(11),
            1 if matches!(x, 1 | 3) => push(5),
            9 if immediate == 1 => push(2),
            _ => {}
        }
    }
    let (major, x, six, immediate) = fields(2);
    if matches!(template, 4 | 5) {
        if matches!(major, 12 | 13) {
            push(18);
        }
    } else if matches!(template, 14 | 15) {
        if major == 0 && x & 1 == 0 && six == 32 {
            push(17);
        }
    } else if template >= 16 {
        match major {
            2 if matches!(six, 1 | 5) => push(15),
            4 | 5 => push(12),
            7 => {
                push(12);
                push(15);
            }
            _ => {}
        }
    } else {
        match major {
            0 if x == 1 => push(6),
            0 if x == 7 => push(9),
            9 if immediate == 1 => push(3),
            _ => {}
        }
    }
    (result, count)
}

pub(super) fn pdata(layout: &PeLayout, output: &mut [u8], used: &RiftTable) -> Result<()> {
    let Some((rva, size)) = layout.directory(3) else {
        return Ok(());
    };
    let start = layout.offset(rva, size)?;
    for position in (start..start + size / 12 * 12).step_by(4) {
        let value = mapped(used, i64::from(word(output, position)?));
        output[position..position + 4].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

pub(super) fn disassemble(
    layout: &PeLayout,
    output: &mut [u8],
    hints: &[u8],
    used: &RiftTable,
    target_gp: u32,
) -> Result<()> {
    let Some((rva, size)) = layout.directory(3) else {
        return Ok(());
    };
    let start = layout.offset(rva, size)?;
    let source_gp = layout.global_pointer();
    let mut remaining = output.len().saturating_mul(4);
    for record in (start..start + size / 12 * 12).step_by(12) {
        let begin = word(output, record)?;
        let end = word(output, record + 4)?;
        if end <= begin {
            continue;
        }
        let length = (end - begin) as usize;
        remaining = remaining
            .checked_sub(length)
            .ok_or(Error::Limit("IA64 instruction work"))?;
        let offset = layout.offset(begin, length)?;
        for pos in (0..length / 16 * 16).step_by(16) {
            let at = offset + pos;
            if hints
                .get(at..at + 16)
                .ok_or(Error::Invalid("IA64 hints"))?
                .iter()
                .any(|hint| hint & 3 != 0)
            {
                continue;
            }
            let mut bundle = u128::from_le_bytes(
                output[at..at + 16]
                    .try_into()
                    .map_err(|_| Error::Invalid("IA64 bundle"))?,
            );
            let (types, count) = kinds(bundle);
            let pc = begin.wrapping_add(pos as u32);
            for &kind in &types[..count] {
                let old = address(bundle, kind);
                let delta = if kind <= 3 {
                    mapped(used, old.wrapping_add(i64::from(source_gp))).wrapping_sub(target_gp)
                        as u64
                        | 0xffff_ffff_0000_0000
                } else {
                    let target = pc.wrapping_add((old as u32).wrapping_mul(16));
                    (u64::from(
                        mapped(used, i64::from(target)).wrapping_sub(mapped(used, i64::from(pc))),
                    ) | 0xffff_ffff_0000_0000)
                        >> 4
                };
                set_address(&mut bundle, kind, delta);
            }
            output[at..at + 16].copy_from_slice(&bundle.to_le_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_native_operand_layouts_roundtrip_signed_values() {
        for kind in 1..=18 {
            for value in [0i64, 1, -1, 127, -128, 12345, -12345] {
                let (_, width) = positions(kind);
                let mut bundle = u128::MAX;
                set_address(&mut bundle, kind, value as u64);
                let expected = (value << (64 - width)) >> (64 - width);
                assert_eq!(address(bundle, kind), expected, "kind{kind}");
            }
        }
    }
    #[test]
    fn template_selects_gp_relative_and_long_branch_operands() {
        let addl = (9u128 << 37) | (1 << 20);
        assert_eq!(
            kinds((addl << 5) | (addl << 46) | (addl << 87)),
            ([1, 2, 3, 0, 0, 0], 3)
        );
        assert_eq!(kinds(4 | (12u128 << 124)), ([18, 0, 0, 0, 0, 0], 1));
    }
    #[test]
    fn native_ia64_flag_matrix_reconstructs_exact_targets() {
        for subdirectory in [
            "docs/fixtures/pa30-arm-native/ia64",
            "docs/fixtures/pa30-arm-native/ia64/legacy-msdelta",
            "docs/fixtures/pa30-arm-native/ia64-imm64",
            "docs/fixtures/pa30-arm-native/ia64-imm64/legacy-msdelta",
        ] {
            let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(subdirectory);
            let cases: serde_json::Value =
                serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                    .unwrap();
            for case in cases.as_array().unwrap() {
                let source =
                    std::fs::read(directory.join(case["source"].as_str().unwrap())).unwrap();
                let target =
                    std::fs::read(directory.join(case["target"].as_str().unwrap())).unwrap();
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
}
