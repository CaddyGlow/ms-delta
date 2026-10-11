//! Managed IL token normalization compatible with native PA30 CLI4 disassembly.
//!
//! Opcode operand forms follow ECMA-335, partition III. Native compatibility
//! observations use msdelta 19041 `RiftTransformCli4Disasm::Transform` (RVA
//! 0x149a0) and `CliHelper::GetMethodOffset` (0x144d4). This implementation was
//! independently written; it does not embed native instruction table bytes.

use crate::{Error, Result};

/// Normalize token operands in all but the final MethodDef, as native PA30 does.
/// The locator returns file offset and available bytes in the backed PE region.
pub(super) fn normalize(
    bytes: &mut [u8],
    method_rvas: &[u32],
    map_token: impl Fn(u32) -> u32,
    locate: impl Fn(u32) -> Option<(usize, usize)>,
) -> Result<()> {
    let mut remaining_work = bytes.len().saturating_mul(4);
    for &rva in method_rvas.iter().take(method_rvas.len().saturating_sub(1)) {
        charge_work(&mut remaining_work, 1)?;
        let Some((offset, header, length)) = locate_method(bytes, rva, &locate) else {
            continue;
        };
        charge_work(&mut remaining_work, length)?;
        normalize_code(
            &mut bytes[offset + header..offset + header + length],
            &map_token,
        );
    }
    Ok(())
}

/// Prevent native AMD64 disassembly from treating managed method bodies as code.
/// Native marking includes the method header and skips the final MethodDef.
pub(super) fn mark_methods(
    bytes: &[u8],
    hints: &mut [u8],
    method_rvas: &[u32],
    locate: impl Fn(u32) -> Option<(usize, usize)>,
) -> Result<()> {
    if hints.len() != bytes.len() {
        return Err(Error::Invalid("PA30 CLI hint buffer size"));
    }
    let mut remaining_work = bytes.len().saturating_mul(4);
    for &rva in method_rvas.iter().take(method_rvas.len().saturating_sub(1)) {
        charge_work(&mut remaining_work, 1)?;
        let Some((offset, header, length)) = locate_method(bytes, rva, &locate) else {
            continue;
        };
        charge_work(&mut remaining_work, header + length)?;
        hints[offset..offset + header + length].fill(3);
    }
    Ok(())
}

fn charge_work(remaining: &mut usize, work: usize) -> Result<()> {
    *remaining = remaining
        .checked_sub(work)
        .ok_or(Error::Limit("PA30 CLI method work"))?;
    Ok(())
}

fn locate_method(
    bytes: &[u8],
    rva: u32,
    locate: &impl Fn(u32) -> Option<(usize, usize)>,
) -> Option<(usize, usize, usize)> {
    let (offset, available) = locate(rva)?;
    // Native uses zero as an invalid image offset sentinel.
    if offset == 0 {
        return None;
    }
    let end = offset.checked_add(available)?;
    let (header, length) = method_body(bytes.get(offset..end)?)?;
    Some((offset, header, length))
}

/// Header interpretation intentionally does not parse EH clauses or rewrite
/// local-variable signatures; the native CLI4 pass only walks instruction bytes.
fn method_body(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    let (header, length) = match first & 3 {
        2 => (1, usize::from(first >> 2)),
        3 => {
            if bytes.len() < 12 {
                return None;
            }
            let header = usize::from(bytes[1] >> 4) * 4;
            if header < 12 || header > bytes.len() {
                return None;
            }
            (
                header,
                u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?) as usize,
            )
        }
        _ => return None,
    };
    (length <= bytes.len().checked_sub(header)?).then_some((header, length))
}

#[derive(Clone, Copy)]
enum Operand {
    Bytes(usize),
    Token,
    Switch,
}

fn operand(opcode: u8, extended: bool) -> Operand {
    use Operand::{Bytes, Switch, Token};
    if extended {
        return match opcode {
            0x06 | 0x07 | 0x15 | 0x16 | 0x1c => Token,
            0x09..=0x0e => Bytes(2),
            0x12 => Bytes(1),
            _ => Bytes(0),
        };
    }
    match opcode {
        0x27
        | 0x28
        | 0x6f
        | 0x70..=0x75
        | 0x79
        | 0x7b..=0x81
        | 0x8c
        | 0x8d
        | 0x8f
        | 0xa3..=0xa5
        | 0xc2
        | 0xc6
        | 0xd0 => Token,
        0x45 => Switch,
        0x0e..=0x13 | 0x1f | 0x2b..=0x37 | 0xde => Bytes(1),
        0x20 | 0x22 | 0x29 | 0x38..=0x44 | 0xdd => Bytes(4),
        0x21 | 0x23 => Bytes(8),
        _ => Bytes(0),
    }
}

/// Truncated operands terminate this method, preserving earlier transformations,
/// rather than causing the native pass to reject the complete delta.
fn normalize_code(bytes: &mut [u8], map_token: &impl Fn(u32) -> u32) {
    let mut position = 0;
    while position < bytes.len() {
        let mut opcode = bytes[position];
        position += 1;
        let extended = opcode == 0xfe;
        if extended {
            let Some(&second) = bytes.get(position) else {
                break;
            };
            opcode = second;
            position += 1;
        }
        match operand(opcode, extended) {
            Operand::Bytes(length) => {
                if length > bytes.len() - position {
                    break;
                }
                position += length;
            }
            Operand::Token => {
                let Some(operand) = bytes.get_mut(position..position.saturating_add(4)) else {
                    break;
                };
                let token = u32::from_le_bytes([operand[0], operand[1], operand[2], operand[3]]);
                operand.copy_from_slice(&map_token(token).to_le_bytes());
                position += 4;
            }
            Operand::Switch => {
                let Some(count) = bytes.get(position..position.saturating_add(4)) else {
                    break;
                };
                let count = u32::from_le_bytes([count[0], count[1], count[2], count[3]]) as usize;
                position += 4;
                if count > (bytes.len() - position) / 4 {
                    break;
                }
                position += count * 4;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shifted_token(token: u32) -> u32 {
        match token >> 24 {
            0..=63 | 0x70 => token.wrapping_add(7),
            _ => token,
        }
    }

    #[test]
    fn tiny_and_fat_method_headers_reject_out_of_region_lengths() {
        assert_eq!(method_body(&[0x0a, 0x00, 0x2a]), Some((1, 2)));
        assert_eq!(method_body(&[0x0e, 0x00, 0x2a]), None);
        let mut fat = [0u8; 15];
        fat[0] = 3;
        fat[1] = 0x30;
        fat[4] = 3;
        assert_eq!(method_body(&fat), Some((12, 3)));
        fat[4] = 4;
        assert_eq!(method_body(&fat), None);
        fat[4] = 0;
        fat[1] = 0x20;
        assert_eq!(method_body(&fat), None);
    }

    #[test]
    fn token_operands_map_but_signature_and_numeric_operands_do_not() {
        let mut code = vec![
            0x28, 1, 0, 0, 6, 0x72, 2, 0, 0, 0x70, 0xfe, 0x16, 3, 0, 0, 1, 0x29, 4, 0, 0, 0x11,
            0x20, 0x28, 1, 0, 6, 0x2a,
        ];
        normalize_code(&mut code, &shifted_token);
        assert_eq!(code[1], 8);
        assert_eq!(code[6], 9);
        assert_eq!(code[12], 10);
        assert_eq!(&code[17..21], &[4, 0, 0, 0x11]);
        assert_eq!(&code[22..26], &[0x28, 1, 0, 6]);
    }

    #[test]
    fn switch_entries_are_skipped_and_incomplete_tail_stops_without_panic() {
        let mut code = vec![0x45, 1, 0, 0, 0, 0x28, 1, 0, 6, 0x28, 1, 0, 0, 6, 0xfe];
        normalize_code(&mut code, &shifted_token);
        assert_eq!(&code[5..9], &[0x28, 1, 0, 6]);
        assert_eq!(code[10], 8);
        let mut bad = [0x45, 0xff, 0xff, 0xff, 0xff, 0x28, 1, 0, 0, 6];
        normalize_code(&mut bad, &shifted_token);
        assert_eq!(bad[6], 1);
        for length in 0..code.len() {
            normalize_code(&mut code[..length].to_vec(), &shifted_token);
        }
    }

    #[test]
    fn managed_marking_includes_headers_skips_final_and_bounds_repeated_work() {
        let mut bytes = [0u8; 32];
        bytes[1] = 0x0a;
        bytes[10] = 0x0a;
        let mut hints = [0u8; 32];
        mark_methods(&bytes, &mut hints, &[1, 10], |rva| Some((rva as usize, 3))).unwrap();
        assert_eq!(&hints[1..4], &[3, 3, 3]);
        assert_eq!(&hints[10..13], &[0, 0, 0]);
        assert!(mark_methods(&bytes, &mut hints[..31], &[1, 10], |_| Some((1, 3))).is_err());
        assert!(matches!(
            mark_methods(&bytes, &mut hints, &[1; 64], |_| Some((1, 3))),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn native_iteration_skips_final_method_and_bounds_repeated_work() {
        let mut bytes = vec![0u8; 32];
        for start in [1, 10] {
            bytes[start] = 0x1a;
            bytes[start + 1..start + 7].copy_from_slice(&[0x28, 1, 0, 0, 6, 0x2a]);
        }
        normalize(&mut bytes, &[1, 10], shifted_token, |rva| {
            Some((rva as usize, 7))
        })
        .unwrap();
        assert_eq!(bytes[3], 8);
        assert_eq!(bytes[12], 1);
        assert!(matches!(
            normalize(&mut bytes, &[1; 64], shifted_token, |_| Some((1, 7))),
            Err(Error::Limit(_))
        ));
    }
}
