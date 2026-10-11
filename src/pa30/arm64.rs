//! Independent ARM64 dictionary instruction and exception-table transforms.
use super::{pe::PeLayout, rift::RiftTable};
use crate::{Error, Result};

fn read(bytes: &[u8], offset: usize) -> Result<u32> {
    let word = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or(Error::Invalid("ARM64 offset"))?,
        )
        .ok_or(Error::Invalid("ARM64 instruction bounds"))?;
    Ok(u32::from_le_bytes(
        word.try_into().map_err(|_| Error::Invalid("ARM64 word"))?,
    ))
}
fn write(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn signed(value: u32, width: u32) -> i64 {
    i64::from((value << (32 - width)) as i32 >> (32 - width))
}
fn map(used: &RiftTable, value: i64) -> i64 {
    i64::from(used.map(value) as u32)
}

#[derive(Clone, Copy)]
struct Instruction {
    word: u32,
    kind: u8,
    rd: usize,
    rn: usize,
    writeback: bool,
}
impl Instruction {
    fn new(word: u32) -> Self {
        let hi = (word >> 16) as u16;
        let low = word as u16;
        let rd = (word & 31) as usize;
        let rn = ((word >> 5) & 31) as usize;
        let mut result = Self {
            word,
            kind: 2,
            rd: 32,
            rn: 32,
            writeback: false,
        };
        if ((hi >> 8) & 31) == 17 {
            result.kind = if ((hi & 0xc0).wrapping_sub(128) & 0xffbf) == 0 {
                8
            } else {
                7
            };
            result.rd = rd;
            result.rn = rn;
            result.writeback = true;
        } else if ((hi >> 8) & 31) == 16 {
            result.kind = 3 + (hi >> 15) as u8;
            result.rd = rd;
        } else if hi & 0x7c00 == 0x1400 {
            result.kind = 5 + (hi >> 15) as u8;
        } else if hi & 0xfe00 == 0x5400 && hi & 0x100 == 0 && low & 0x10 == 0 {
            result.kind = 9;
        } else if hi >> 14 >= 2
            && ((hi >> 8) & 63) == 0x38
            && hi & 0x80 == 0
            && hi & 0x20 == 0
            && matches!(low & 0xc00, 0x400 | 0xc00)
        {
            result.kind = if hi & 0xc0 == 0x40 {
                if low & 0xc00 == 0x400 { 11 } else { 10 }
            } else if low & 0xc00 == 0x400 {
                15
            } else {
                14
            };
            result.rd = rd;
            result.rn = rn;
            result.writeback = true;
        } else if hi >> 14 >= 2 && hi & 0x3f00 == 0x3900 && hi & 0x80 == 0 {
            result.kind = if hi & 0xc0 == 0x40 { 12 } else { 16 };
            result.rd = rd;
            result.rn = rn;
        } else if hi & 0x7e00 == 0x3400 {
            result.kind = 17 + u8::from(hi & 0x100 != 0);
        } else if hi & 0x7e00 == 0x3600 {
            result.kind = 21 + u8::from(hi & 0x100 != 0);
        }
        result
    }
    fn target(self, pc: i64) -> i64 {
        match self.kind {
            3 | 4 => {
                let value = ((self.word >> 5) & 0x7ffff) << 2 | ((self.word >> 29) & 3);
                let delta = signed(value, 21);
                if self.kind == 4 {
                    (pc & !4095).wrapping_add(delta << 12)
                } else {
                    pc.wrapping_add(delta)
                }
            }
            5 | 6 => pc
                .wrapping_add(4)
                .wrapping_add(signed(self.word & 0x3ffffff, 26) << 2),
            9 | 17 | 18 => pc
                .wrapping_add(4)
                .wrapping_add(signed((self.word >> 5) & 0x7ffff, 19) << 2),
            21 | 22 => pc
                .wrapping_add(4)
                .wrapping_add(signed((self.word >> 5) & 0x3fff, 14) << 2),
            _ => 0,
        }
    }
    fn set_target(&mut self, pc: i64, target: i64) {
        let delta = target.wrapping_sub(pc);
        self.word = match self.kind {
            3 | 4 => {
                let immediate = if self.kind == 4 {
                    ((target & !4095).wrapping_sub(pc & !4095) >> 12) as u32
                } else {
                    delta as u32
                };
                (self.word & !0x60ffffe0)
                    | ((immediate & 3) << 29)
                    | (((immediate >> 2) & 0x7ffff) << 5)
            }
            5 | 6 => (self.word & !0x3ffffff) | ((delta.wrapping_sub(4) >> 2) as u32 & 0x3ffffff),
            9 | 17 | 18 => {
                (self.word & !0xffffe0) | (((delta.wrapping_sub(4) >> 2) as u32 & 0x7ffff) << 5)
            }
            21 | 22 => {
                (self.word & !0x7ffe0) | (((delta.wrapping_sub(4) >> 2) as u32 & 0x3fff) << 5)
            }
            _ => self.word,
        };
    }
    fn increment(self) -> i64 {
        match self.kind {
            7 => {
                let value = i64::from((self.word >> 10) & 4095);
                match (self.word >> 22) & 3 {
                    0 => value,
                    1 => value << 12,
                    _ => -1,
                }
            }
            10 | 11 | 14 | 15 => signed((self.word >> 12) & 511, 9),
            12 | 16 => i64::from((self.word >> 10) & 4095) << (self.word >> 30),
            _ => 0,
        }
    }
    fn mem_target(self, registers: &[i64; 32]) -> i64 {
        if self.rn == 31 {
            0
        } else {
            registers[self.rn].wrapping_add(self.increment())
        }
    }
    fn set_mem(&mut self, registers: &[i64; 32], target: i64) {
        let value = target.wrapping_sub(registers[self.rn]);
        match self.kind {
            7 => {
                let encoded = if (0..4096).contains(&value) {
                    Some((value as u32, 0))
                } else if (0..0x1000000).contains(&value) && value % 4096 == 0 {
                    Some(((value >> 12) as u32, 1))
                } else {
                    None
                };
                if let Some((imm, shift)) = encoded {
                    self.word = (self.word & !0x00fffc00) | (imm << 10) | (shift << 22);
                }
            }
            10 | 11 | 14 | 15 => self.word = (self.word & !0x1ff000) | ((value as u32 & 511) << 12),
            12 | 16 => {
                self.word =
                    (self.word & !0x3ffc00) | (((value >> (self.word >> 30)) as u32 & 4095) << 10)
            }
            _ => {}
        }
    }
    fn emulate(self, pc: i64, registers: &mut [i64; 32]) {
        match self.kind {
            3 | 4 => registers[self.rd] = self.target(pc),
            7 => registers[self.rd] = registers[self.rn].wrapping_add(self.increment()),
            10 | 11 | 14 | 15 => {
                registers[self.rn] = registers[self.rn].wrapping_add(self.increment())
            }
            _ => {}
        }
    }
}

pub(super) fn pdata(layout: &PeLayout, output: &mut [u8], used: &RiftTable) -> Result<()> {
    let Some((rva, size)) = layout.directory(3) else {
        return Ok(());
    };
    let start = layout.offset(rva, size)?;
    for pos in (start..start + size / 8 * 8).step_by(8) {
        let value = read(output, pos)?;
        write(output, pos, map(used, i64::from(value)) as u32);
    }
    Ok(())
}

pub(super) fn disassemble(
    layout: &PeLayout,
    output: &mut [u8],
    hints: &[u8],
    used: &RiftTable,
) -> Result<()> {
    let Some((rva, size)) = layout.directory(3) else {
        return Ok(());
    };
    let start = layout.offset(rva, size)?;
    let mut work = output.len().saturating_mul(4);
    for pos in (start..start + size / 8 * 8).step_by(8) {
        let begin = read(output, pos)?;
        let unwind = read(output, pos + 4)?;
        // Pinned native graph uses two bytes per encoded length unit.
        let length = if unwind & 3 != 0 {
            ((unwind >> 1) & 0xffe) as usize
        } else {
            let header = layout.offset(unwind, 4)?;
            ((read(output, header)? & 0x3ffff) * 2) as usize
        };
        if length == 0 {
            continue;
        }
        let offset = layout.offset(begin, length)?;
        work = work
            .checked_sub(length)
            .ok_or(Error::Limit("ARM64 disassembly work"))?;
        function(output, hints, offset, length, i64::from(begin), used)?;
    }
    Ok(())
}
fn function(
    output: &mut [u8],
    hints: &[u8],
    start: usize,
    length: usize,
    rva: i64,
    used: &RiftTable,
) -> Result<()> {
    let mut old = [0i64; 32];
    let mut new = [0i64; 32];
    let mut state = [0u8; 32];
    let mut pending = [None; 32];
    let mut pos = 0usize;
    while pos < length {
        let offset = start + pos;
        let pc = rva + pos as i64;
        if hints[offset] & 3 != 0 {
            pos += (length - pos).min(2);
            continue;
        }
        if length - pos < 4 {
            break;
        }
        if let Some(delta) = (1..4).find(|&delta| hints[offset + delta] & 2 != 0) {
            pos += delta;
            continue;
        }
        let mut instruction = Instruction::new(read(output, offset)?);
        match instruction.kind {
            4 => {
                state[instruction.rd] = 1;
                pending[instruction.rd] = Some((pc, offset));
                instruction.emulate(pc, &mut old);
                instruction.emulate(pc, &mut new);
            }
            3 | 5 | 6 | 9 | 17 | 18 | 21 | 22 => {
                let target = instruction.target(pc);
                instruction.set_target(map(used, pc), map(used, target));
                write(output, offset, instruction.word);
                if instruction.kind == 3 {
                    state[instruction.rd] = 2;
                }
            }
            7 | 10 | 11 | 12 | 14 | 15 | 16 => {
                let rn = instruction.rn;
                if rn == 31 {
                    state[rn] = 0;
                }
                if state[rn] == 1 && pending[rn].is_some() {
                    let (adr_pc, adr_offset) = pending[rn].take().expect("checked pending ADRP");
                    let target = map(used, instruction.mem_target(&old));
                    instruction.emulate(pc, &mut old);
                    let mut adr = Instruction::new(read(output, adr_offset)?);
                    adr.set_target(map(used, adr_pc), target);
                    write(output, adr_offset, adr.word);
                    adr.emulate(map(used, adr_pc), &mut new);
                    instruction.set_mem(&new, target);
                    write(output, offset, instruction.word);
                    instruction.emulate(pc, &mut new);
                    if instruction.writeback {
                        state[rn] = 2;
                    }
                } else if state[rn] != 0 {
                    let target = instruction.mem_target(&new);
                    instruction.set_mem(&new, target);
                    write(output, offset, instruction.word);
                    instruction.emulate(pc, &mut old);
                    instruction.emulate(pc, &mut new);
                    if instruction.writeback {
                        state[rn] = 2;
                    }
                } else if instruction.writeback {
                    state[rn] = 0;
                }
                if instruction.rd < 32 {
                    state[instruction.rd] = 0;
                }
            }
            _ => {}
        }
        pos += 4;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn branch_encoding_preserves_native_plus_four_pc_convention() {
        let mut branch = Instruction::new(0x14000004);
        assert_eq!(branch.target(0x1000), 0x1014);
        branch.set_target(0x2000, 0x3000);
        assert_eq!(branch.target(0x2000), 0x3000);
        for word in [0x54000080, 0xb4000080, 0x36000080, 0x10000080, 0x90000080] {
            let mut ins = Instruction::new(word);
            let target = ins.target(0x1000);
            let original = ins.word;
            ins.set_target(0x1000, target);
            assert_eq!(ins.word, original);
        }
    }
    #[test]
    fn pending_adrp_and_add_remap_one_memory_target() {
        let mut code = Vec::new();
        for word in [0x90000000u32, 0x91004000] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let limits = crate::Limits::default();
        let used =
            RiftTable::from_entries(vec![(0, 0), (0x1000, 0x2000), (0x1010, 0x3010)], &limits)
                .unwrap();
        function(&mut code, &[0; 8], 0, 8, 0x1000, &used).unwrap();
        let adr = Instruction::new(read(&code, 0).unwrap());
        let add = Instruction::new(read(&code, 4).unwrap());
        let mut registers = [0; 32];
        adr.emulate(0x2000, &mut registers);
        assert_eq!(add.mem_target(&registers), 0x3010);
    }
    #[test]
    fn native_arm64_flag_matrix_reconstructs_exact_targets() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa30-arm-native/arm64");
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
