//! Checked i386 and AMD64 PE source normalization for PA30 preprocessing.
//!
//! Formats and transform order were independently derived from Microsoft PE
//! documentation and the pinned native MSDelta graph, then checked by oracles.

use super::{
    cli::{CliMaps, MetadataInfo},
    cli_il,
    rift::RiftTable,
};
use crate::{Error, Limits, Result};
use iced_x86::{Decoder, DecoderOptions, EncodingKind, OpKind};

#[derive(Debug)]
pub(super) struct TargetInfo {
    pub image_base: u64,
    pub global_pointer: u32,
    pub time_stamp: u32,
    pub rva_to_offset: RiftTable,
}

#[derive(Debug)]
struct Section {
    header: usize,
    raw: usize,
    size: usize,
    virtual_size: usize,
    rva: u32,
    characteristics: u32,
}

#[derive(Debug)]
pub(super) struct PeLayout {
    nt: usize,
    optional: usize,
    headers: usize,
    image_base: u64,
    is_pe32: bool,
    machine: u16,
    image_size: u32,
    directory_offset: usize,
    directories: [(u32, u32); 16],
    directory_count: usize,
    sections: Vec<Section>,
}

impl PeLayout {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let parsed = hexspell::pe::view::PeHeaders::parse(bytes)
            .map_err(|_| Error::Invalid("PA30 source PE headers"))?;
        let nt = parsed.nt;
        let machine = parsed.coff.machine.value;
        let count = usize::from(parsed.coff.number_of_sections.value);
        if count == 0 || count > 96 {
            return Err(Error::Invalid("PE section count"));
        }
        let optional_size = usize::from(parsed.coff.size_of_optional_header.value);
        let optional = parsed.optional;
        range(bytes, optional, optional_size)?;
        let is_pe32 = match (
            machine,
            parsed
                .magic()
                .map_err(|_| Error::Invalid("PE optional magic"))?,
        ) {
            (0x14c | 0x1c0 | 0x1c4, 0x10b) => true,
            (0x8664 | 0xaa64 | 0x200, 0x20b) => false,
            _ => {
                return Err(Error::Unsupported(
                    "PA30 source PE architecture or optional header",
                ));
            }
        };
        let directory_offset = parsed
            .directory_offset()
            .map_err(|_| Error::Invalid("PE optional magic"))?;
        if optional_size < directory_offset {
            return Err(Error::Invalid("PE optional header size"));
        }
        let directory_count = read32(bytes, optional + directory_offset - 4)? as usize;
        if directory_count > 16 || directory_count * 8 > optional_size - directory_offset {
            return Err(Error::Invalid("PE directory count"));
        }
        let headers = read32(bytes, optional + 60)? as usize;
        if headers > bytes.len() {
            return Err(Error::Invalid("PE headers exceed source"));
        }
        let section_start = optional
            .checked_add(optional_size)
            .ok_or(Error::Invalid("PE section offset"))?;
        range(bytes, section_start, count * 40)?;
        if section_start + count * 40 > headers {
            return Err(Error::Invalid("PE sections outside headers"));
        }
        let mut directories = [(0, 0); 16];
        for (index, directory) in directories.iter_mut().take(directory_count).enumerate() {
            *directory = parsed
                .directory_slot(index)
                .map_err(|_| Error::Invalid("PE data directory"))?;
        }
        let mut sections = Vec::new();
        sections
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for index in 0..count {
            let header = section_start + index * 40;
            let section = parsed
                .section(index)
                .map_err(|_| Error::Invalid("PE section header"))?;
            let rva = section.virtual_address.value;
            let size = section.size_of_raw_data.value as usize;
            let raw = section.pointer_to_raw_data.value as usize;
            if size != 0 {
                range(bytes, raw, size)?;
                if raw < headers {
                    return Err(Error::Invalid("PE section overlaps headers"));
                }
            }
            if u64::from(rva) + size as u64 > u64::from(u32::MAX) + 1 {
                return Err(Error::Invalid("PE section RVA overflow"));
            }
            for previous in &sections {
                let previous: &Section = previous;
                if size != 0
                    && previous.size != 0
                    && (raw < previous.raw + previous.size && previous.raw < raw + size)
                {
                    return Err(Error::Invalid("PE raw sections overlap"));
                }
                if size != 0
                    && previous.size != 0
                    && (u64::from(rva) < u64::from(previous.rva) + previous.size as u64
                        && u64::from(previous.rva) < u64::from(rva) + size as u64)
                {
                    return Err(Error::Invalid("PE RVA sections overlap"));
                }
            }
            sections.push(Section {
                header,
                raw,
                size,
                virtual_size: section.virtual_size.value as usize,
                rva,
                characteristics: section.characteristics.value,
            });
        }
        Ok(Self {
            nt,
            optional,
            headers,
            image_base: if is_pe32 {
                u64::from(read32(bytes, optional + 28)?)
            } else {
                read64(bytes, optional + 24)?
            },
            is_pe32,
            machine,
            image_size: read32(bytes, optional + 56)?,
            directory_offset,
            directories,
            directory_count,
            sections,
        })
    }

    pub(super) fn machine(&self) -> u16 {
        self.machine
    }

    #[cfg(test)]
    pub(super) fn is_pe32(&self) -> bool {
        self.is_pe32
    }

    pub(super) fn target_info(&self, bytes: &[u8], limits: &Limits) -> Result<TargetInfo> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.sections.len() + 1)
            .map_err(|_| Error::Allocation)?;
        entries.push((0, 0));
        for section in &self.sections {
            if section.raw != 0 && section.rva != 0 {
                entries.push((i64::from(section.rva), section.raw as i64));
            }
        }
        Ok(TargetInfo {
            image_base: self.image_base,
            global_pointer: self.directories[8].0,
            time_stamp: read32(bytes, self.nt + 8)?,
            rva_to_offset: RiftTable::from_entries(entries, limits)?,
        })
    }

    /// Match section names to build a source RVA to target RVA dictionary map.
    /// Unmatched sections keep the translation of the preceding matched entry.
    pub(super) fn section_map(
        &self,
        target: &Self,
        source_bytes: &[u8],
        target_bytes: &[u8],
        limits: &Limits,
    ) -> Result<RiftTable> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.sections.len() + 1)
            .map_err(|_| Error::Allocation)?;
        entries.push((0, 0));
        for source in &self.sections {
            let name = range(source_bytes, source.header, 8)?;
            if let Some(destination) = target
                .sections
                .iter()
                .find(|section| target_bytes.get(section.header..section.header + 8) == Some(name))
            {
                entries.push((i64::from(source.rva), i64::from(destination.rva)));
            }
        }
        RiftTable::from_entries(entries, limits)
    }

    pub(super) fn offset(&self, rva: u32, length: usize) -> Result<usize> {
        let start = rva as usize;
        if start < self.headers && length <= self.headers - start {
            return Ok(start);
        }
        for section in &self.sections {
            if rva >= section.rva {
                let delta = (rva - section.rva) as usize;
                if delta < section.size && length <= section.size - delta {
                    return Ok(section.raw + delta);
                }
            }
        }
        Err(Error::Invalid("PE RVA is not backed by source bytes"))
    }

    pub(super) fn available(&self, rva: u32) -> usize {
        if (rva as usize) < self.headers {
            return self.headers - rva as usize;
        }
        self.sections
            .iter()
            .find_map(|section| {
                let delta = rva.checked_sub(section.rva)? as usize;
                (delta < section.size).then(|| section.size - delta)
            })
            .unwrap_or(0)
    }

    pub(super) fn directory(&self, index: usize) -> Option<(u32, usize)> {
        let (rva, size) = self.directories[index];
        (rva != 0 && size != 0).then_some((rva, size as usize))
    }

    pub(super) fn global_pointer(&self) -> u32 {
        self.directories[8].0
    }

    pub(super) fn has_cli_directory(&self) -> bool {
        self.directories[14] != (0, 0)
    }

    pub(super) fn file_offset_to_rva(&self, limits: &Limits) -> Result<RiftTable> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.sections.len() + 1)
            .map_err(|_| Error::Allocation)?;
        entries.push((0, 0));
        for section in &self.sections {
            if section.raw != 0 && section.rva != 0 {
                entries.push((section.raw as i64, i64::from(section.rva)));
            }
        }
        entries.sort_unstable_by_key(|entry| entry.0);
        RiftTable::from_entries(entries, limits)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Native PE graph supplies distinct target and mapping inputs"
)]
pub(super) fn preprocess_cli(
    source: &[u8],
    flags: u64,
    target: &TargetInfo,
    used: &RiftTable,
    source_cli: &MetadataInfo,
    target_cli: &MetadataInfo,
    cli_maps: &CliMaps,
    limits: &Limits,
) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PE source size"));
    }
    let layout = PeLayout::parse(source)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(source.len())
        .map_err(|_| Error::Allocation)?;
    output.extend_from_slice(source);
    let mut hints = Vec::new();
    hints
        .try_reserve_exact(source.len())
        .map_err(|_| Error::Allocation)?;
    hints.resize(source.len(), 0);
    if flags & 0x2000 != 0 {
        unbind(&layout, &mut output)?;
    }
    if flags & 2 != 0 {
        mark(&layout, &mut hints)?;
        if source_cli.metadata_size != 0 {
            let methods = source_cli.method_rvas(&output, limits)?;
            cli_il::mark_methods(&output, &mut hints, &methods, |rva| {
                layout
                    .offset(rva, 1)
                    .ok()
                    .map(|offset| (offset, layout.available(rva)))
            })?;
        }
    }
    if flags & 4 != 0 {
        imports(&layout, &mut output, &mut hints, used)?;
    }
    if flags & 8 != 0 {
        exports(&layout, &mut output, &mut hints, used)?;
    }
    if flags & 16 != 0 {
        resources(&layout, &mut output, used)?;
    }
    if flags & 32 != 0 {
        relocations(
            &layout,
            &mut output,
            &mut hints,
            used,
            target.image_base,
            limits,
        )?;
    }
    if source_cli.metadata_size != 0 {
        let locate = |rva| {
            layout
                .offset(rva, 1)
                .ok()
                .map(|offset| (offset, layout.available(rva)))
        };
        if flags & 0x200000 != 0 {
            let methods = source_cli.method_rvas(&output, limits)?;
            cli_il::normalize(
                &mut output,
                &methods,
                |token| cli_maps.map_token(token),
                locate,
            )?;
        }
        if flags & 0x400000 != 0 {
            super::cli::normalize(&mut output, source_cli, target_cli, cli_maps, used, limits)?;
        }
    }
    if layout.machine == 0x14c {
        if flags & 0x40 != 0 {
            smash_lock_prefixes(&layout, &mut output)?;
        }
        if flags & 0x80 != 0 {
            relative_i386(&layout, &mut output, &hints, used, false)?;
        }
        if flags & 0x100 != 0 {
            relative_i386(&layout, &mut output, &hints, used, true)?;
        }
    }
    if layout.machine == 0x8664 && flags & 0x200 != 0 {
        disassemble(&layout, &mut output, &hints, used)?;
    }
    if layout.machine == 0x8664 && flags & 0x400 != 0 {
        pdata(&layout, &mut output, used)?;
    }
    if layout.machine == 0x1c4 {
        if flags & 0x80000 != 0 {
            super::arm::disassemble(&layout, &mut output, &hints, used, layout.image_base as u32)?;
        }
        if flags & 0x100000 != 0 {
            super::arm::pdata(&layout, &mut output, used)?;
        }
    }
    if layout.machine == 0x200 {
        if flags & 0x800 != 0 {
            super::ia64::disassemble(&layout, &mut output, &hints, used, target.global_pointer)?;
        }
        if flags & 0x1000 != 0 {
            super::ia64::pdata(&layout, &mut output, used)?;
        }
    }
    if layout.machine == 0xaa64 {
        if flags & 0x800000 != 0 {
            super::arm64::disassemble(&layout, &mut output, &hints, used)?;
        }
        if flags & 0x1000000 != 0 {
            super::arm64::pdata(&layout, &mut output, used)?;
        }
    }
    if layout.is_pe32 {
        write32(&mut output, layout.optional + 28, target.image_base as u32)?;
    } else {
        write64(&mut output, layout.optional + 24, target.image_base)?;
    }
    write32(&mut output, layout.nt + 8, target.time_stamp)?;
    write32(&mut output, layout.optional + 64, 0)?;
    if layout.directory_count > 8 {
        write32(
            &mut output,
            layout.optional + layout.directory_offset + 8 * 8,
            target.global_pointer,
        )?;
    }
    Ok(output)
}

fn mapped(table: &RiftTable, rva: u32) -> u32 {
    table.map(i64::from(rva)) as u32
}

fn mark(layout: &PeLayout, hints: &mut [u8]) -> Result<()> {
    hints[..layout.headers].fill(3);
    for section in &layout.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            hints[section.raw..section.raw + section.size].fill(1);
        }
    }
    for index in 0..layout.directory_count {
        if let Some((rva, size)) = layout.directory(index) {
            let offset = if index == 4 {
                rva as usize
            } else {
                layout.offset(rva, size)?
            };
            range(hints, offset, size)?;
            hints[offset..offset + size].fill(3);
        }
    }
    Ok(())
}

fn unbind(layout: &PeLayout, output: &mut [u8]) -> Result<()> {
    let mut work = Work::new(output.len());
    if let Some((rva, size)) = layout.directory(11) {
        let offset = layout.offset(rva, size)?;
        output[offset..offset + size].fill(0);
        let header = layout.optional + layout.directory_offset + 11 * 8;
        output[header..header + 8].fill(0);
    }
    if let Some((rva, size)) = layout.directory(1) {
        let offset = layout.offset(rva, size)?;
        for index in 0..size / 20 {
            let descriptor = offset + index * 20;
            if read32(output, descriptor)? == 0 && read32(output, descriptor + 16)? == 0 {
                break;
            }
            if read32(output, descriptor + 4)? == 0 {
                continue;
            }
            write32(output, descriptor + 4, 0)?;
            write32(output, descriptor + 8, 0)?;
            let original = read32(output, descriptor)?;
            let first = read32(output, descriptor + 16)?;
            if original != 0 && first != 0 {
                let width = if layout.is_pe32 { 4 } else { 8 };
                let original_offset = layout.offset(original, width)?;
                let first_offset = layout.offset(first, width)?;
                let count = layout.available(original).min(layout.available(first)) / width;
                for i in 0..count {
                    work.consume(width)?;
                    if read32(output, original_offset + i * width)? == 0
                        || read32(output, first_offset + i * width)? == 0
                    {
                        break;
                    }
                    output.copy_within(
                        original_offset + i * width..original_offset + (i + 1) * width,
                        first_offset + i * width,
                    );
                }
            }
        }
    }
    for section in &layout.sections {
        if output[section.header..section.header + 8].eq_ignore_ascii_case(b".idata\0\0") {
            write32(
                output,
                section.header + 36,
                section.characteristics | 0xc000_0000,
            )?;
            break;
        }
    }
    Ok(())
}

fn imports(layout: &PeLayout, output: &mut [u8], hints: &mut [u8], used: &RiftTable) -> Result<()> {
    let mut work = Work::new(output.len());
    let Some((rva, size)) = layout.directory(1) else {
        return Ok(());
    };
    let offset = layout.offset(rva, size)?;
    for index in 0..size / 20 {
        let descriptor = offset + index * 20;
        let original = read32(output, descriptor)?;
        let first = read32(output, descriptor + 16)?;
        if original == 0 && first == 0 {
            break;
        }
        let bound = read32(output, descriptor + 4)? != 0;
        for (thunk_rva, is_bound) in [(original, false), (first, bound)] {
            if thunk_rva == 0 {
                continue;
            }
            let width = if layout.is_pe32 { 4 } else { 8 };
            let thunk = layout.offset(thunk_rva, width)?;
            let count = layout.available(thunk_rva) / width;
            let first_ordinal = layout.is_pe32 && read32(output, thunk)? & 0x8000_0000 != 0;
            for i in 0..count {
                work.consume(width)?;
                let cell = thunk + i * width;
                let value = if layout.is_pe32 {
                    u64::from(read32(output, cell)?)
                } else {
                    read64(output, cell)?
                };
                if value == 0 {
                    break;
                }
                if is_bound {
                    let mapped_value =
                        u64::from(mapped(used, value.wrapping_sub(layout.image_base) as u32))
                            .wrapping_add(layout.image_base);
                    if layout.is_pe32 {
                        write32(output, cell, mapped_value as u32)?;
                    } else {
                        write64(output, cell, mapped_value)?;
                    }
                } else if if layout.is_pe32 {
                    if thunk_rva == original {
                        !first_ordinal
                    } else {
                        value & 0x8000_0000 == 0
                    }
                } else {
                    value & (1u64 << 63) == 0
                } {
                    let name_rva = value as u32;
                    let name = match layout.offset(name_rva, 3) {
                        Ok(name) => name,
                        Err(_) if layout.is_pe32 => {
                            // Native first-thunk classification can encounter an
                            // ordinal later in an otherwise named lookup table.
                            hints[cell..cell + width].fill(3);
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    let available = layout.available(name_rva);
                    let length = output[name + 2..name + available]
                        .iter()
                        .position(|byte| *byte == 0)
                        .ok_or(Error::Invalid("PE import name terminator"))?
                        + 3;
                    work.consume(length)?;
                    hints[name..name + length].fill(3);
                    write32(output, cell, mapped(used, name_rva))?;
                }
                hints[cell..cell + width].fill(3);
            }
        }
        for delta in [0, 12, 16] {
            let value = read32(output, descriptor + delta)?;
            write32(output, descriptor + delta, mapped(used, value))?;
        }
    }
    Ok(())
}

fn exports(layout: &PeLayout, output: &mut [u8], hints: &mut [u8], used: &RiftTable) -> Result<()> {
    let Some((rva, size)) = layout.directory(0) else {
        return Ok(());
    };
    if size < 40 {
        return Err(Error::Invalid("PE export directory size"));
    }
    let offset = layout.offset(rva, 40)?;
    for (count_offset, table_offset, width) in [(20, 28, 4), (24, 32, 4), (24, 36, 2)] {
        let count = read32(output, offset + count_offset)? as usize;
        let table_rva = read32(output, offset + table_offset)?;
        if count == 0 || table_rva == 0 {
            continue;
        }
        let length = count
            .checked_mul(width)
            .ok_or(Error::Invalid("PE export table size"))?;
        let table = layout.offset(table_rva, length)?;
        hints[table..table + length].fill(3);
        if width == 4 {
            for index in 0..count {
                let value = read32(output, table + index * 4)?;
                write32(output, table + index * 4, mapped(used, value))?;
            }
        }
    }
    for delta in [12, 28, 32, 36] {
        let value = read32(output, offset + delta)?;
        write32(output, offset + delta, mapped(used, value))?;
    }
    Ok(())
}

fn resources(layout: &PeLayout, output: &mut [u8], used: &RiftTable) -> Result<()> {
    let Some((rva, size)) = layout.directory(2) else {
        return Ok(());
    };
    let offset = layout.offset(rva, size)?;
    let mut visits = 0;
    resource_directory(
        &mut output[offset..offset + size],
        0,
        rva,
        used,
        0,
        &mut visits,
    )
}

fn resource_directory(
    bytes: &mut [u8],
    directory: usize,
    base_rva: u32,
    used: &RiftTable,
    depth: usize,
    visits: &mut usize,
) -> Result<()> {
    if depth > 64 {
        return Err(Error::Limit("PE resource depth"));
    }
    *visits += 1;
    if *visits > bytes.len() / 8 {
        return Err(Error::Limit("PE resource node count"));
    }
    range(bytes, directory, 16)?;
    let count =
        usize::from(read16(bytes, directory + 12)?) + usize::from(read16(bytes, directory + 14)?);
    range(bytes, directory + 16, count * 8)?;
    let mapped_base = mapped(used, base_rva);
    for index in 0..count {
        let entry = directory + 16 + index * 8;
        let name = read32(bytes, entry)?;
        let destination = read32(bytes, entry + 4)?;
        let relative = (destination & 0x7fff_ffff) as usize;
        if destination & 0x8000_0000 != 0 {
            // Native traversal only descends into forward directory records.
            if relative <= entry {
                return Err(Error::Invalid("PE resource directory cycle"));
            }
            resource_directory(bytes, relative, base_rva, used, depth + 1, visits)?;
            write32(
                bytes,
                entry + 4,
                0x8000_0000
                    | (mapped(used, base_rva.wrapping_add(relative as u32))
                        .wrapping_sub(mapped_base)
                        & 0x7fff_ffff),
            )?;
        } else {
            range(bytes, relative, 16)?;
            let data = read32(bytes, relative)?;
            write32(
                bytes,
                relative,
                mapped(used, base_rva.wrapping_add(data)).wrapping_sub(mapped_base),
            )?;
        }
        if name & 0x8000_0000 != 0 {
            write32(
                bytes,
                entry,
                0x8000_0000
                    | (mapped(used, base_rva.wrapping_add(name & 0x7fff_ffff))
                        .wrapping_sub(mapped_base)
                        & 0x7fff_ffff),
            )?;
        }
    }
    Ok(())
}

fn disassemble(layout: &PeLayout, output: &mut [u8], hints: &[u8], used: &RiftTable) -> Result<()> {
    let mut work = Work::new(output.len());
    let Some((rva, size)) = layout.directory(3) else {
        return Ok(());
    };
    let offset = layout.offset(rva, size)?;
    for index in 0..size / 12 {
        let begin = read32(output, offset + index * 12)?;
        let end = read32(output, offset + index * 12 + 4)?;
        if end <= begin {
            continue;
        }
        let length = (end - begin) as usize;
        work.consume(length)?;
        let file = layout.offset(begin, length)?;
        let mut position = 0;
        while position < length {
            if hints[file + position] & 3 != 0 {
                position += 1;
                continue;
            }
            let mut decoder = Decoder::with_ip(
                64,
                &output[file + position..file + length],
                u64::from(begin) + position as u64,
                DecoderOptions::NONE,
            );
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                position += 1;
                continue;
            }
            let size = instruction.len();
            if size == 0 || size > length - position {
                return Err(Error::Invalid("PE instruction length"));
            }
            if let Some(boundary) = (1..size).find(|index| hints[file + position + index] & 2 != 0)
            {
                position += boundary;
                continue;
            }
            let constants = decoder.get_constant_offsets(&instruction);
            let displacement =
                if instruction.is_ip_rel_memory_operand() && constants.displacement_size() == 4 {
                    Some(constants.displacement_offset())
                } else if (0..instruction.op_count())
                    .any(|index| instruction.op_kind(index) == OpKind::NearBranch64)
                    && constants.immediate_size() == 4
                {
                    Some(constants.immediate_offset())
                } else {
                    None
                };
            // Native MSDelta leaves VEX-encoded operands unchanged, although
            // their decoded size still advances the instruction walk. Selected
            // SSU native oracle confirms this for AVX RIP-relative operands.
            if let Some(displacement) = displacement
                && instruction.encoding() != EncodingKind::VEX
            {
                let cell = file + position + displacement;
                let next = begin
                    .wrapping_add(position as u32)
                    .wrapping_add(size as u32);
                let destination = next.wrapping_add(read32(output, cell)?);
                write32(
                    output,
                    cell,
                    mapped(used, destination).wrapping_sub(mapped(used, next)),
                )?;
            }
            position += size;
        }
    }
    Ok(())
}

/// Repeated PE records can otherwise rescan the same source quadratically.
/// Each traversal admits at most four source lengths of cumulative work.
struct Work {
    remaining: usize,
}

impl Work {
    fn new(source_size: usize) -> Self {
        Self {
            remaining: source_size.saturating_mul(4),
        }
    }

    fn consume(&mut self, bytes: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(Error::Limit("PA30 PE repeated traversal work"))?;
        Ok(())
    }
}

fn pdata(layout: &PeLayout, output: &mut [u8], used: &RiftTable) -> Result<()> {
    let Some((rva, size)) = layout.directory(3) else {
        return Ok(());
    };
    let offset = layout.offset(rva, size)?;
    for index in 0..size / 12 {
        let entry = offset + index * 12;
        let unwind = read32(output, entry + 8)?;
        if let Ok(unwind_offset) = layout.offset(unwind, 4)
            && (unwind_offset < offset || unwind_offset > offset + size)
        {
            let first = output[unwind_offset];
            let count = usize::from(output[unwind_offset + 2]);
            let tail = 4 + count.div_ceil(2) * 4;
            if first & 0x38 != 0 && layout.available(unwind) > tail + 4 {
                let cell = unwind_offset + tail;
                let value = read32(output, cell)?;
                write32(output, cell, mapped(used, value))?;
            }
        }
        for delta in [0, 4, 8] {
            let value = read32(output, entry + delta)?;
            write32(output, entry + delta, mapped(used, value))?;
        }
    }
    Ok(())
}

fn relocations(
    layout: &PeLayout,
    output: &mut [u8],
    hints: &mut [u8],
    used: &RiftTable,
    target_base: u64,
    limits: &Limits,
) -> Result<()> {
    let Some((rva, size)) = layout.directory(5) else {
        if layout.machine == 0x14c {
            return inferred_relocations_i386(layout, output, hints, used, target_base as u32);
        }
        return Ok(());
    };
    let offset = layout.offset(rva, size)?;
    let max_entries = size / 2;
    if max_entries
        .checked_mul(8)
        .is_none_or(|bytes| bytes > limits.max_parameter_bytes)
    {
        return Err(Error::Limit("PE relocation entries"));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(max_entries)
        .map_err(|_| Error::Allocation)?;
    let mut cursor = offset;
    while cursor < offset + size {
        if offset + size - cursor < 8 {
            return Err(Error::Invalid("PE relocation block header"));
        }
        let page = read32(output, cursor)?;
        let block_size = read32(output, cursor + 4)? as usize;
        if block_size < 8 || block_size > offset + size - cursor || !block_size.is_multiple_of(2) {
            return Err(Error::Invalid("PE relocation block size"));
        }
        for index in 0..(block_size - 8) / 2 {
            let word = read16(output, cursor + 8 + index * 2)?;
            let kind = word >> 12;
            if kind == 0 {
                break;
            }
            let location = page.wrapping_add(u32::from(word & 0xfff));
            // Native graphs retain the mapped location of ARM MOV32T and
            // IA64 IMM64 entries with type zero, leaving their bytes untouched.
            if (kind == 9 && layout.machine == 0x200) || (kind == 7 && layout.machine == 0x1c4) {
                entries.push((mapped(used, location), 0));
                continue;
            }
            let width = match kind {
                3 => 4,
                10 => 8,
                _ => return Err(Error::Unsupported("PA30 PE relocation type")),
            };
            let cell = layout.offset(location, width)?;
            hints[cell..cell + width]
                .iter_mut()
                .for_each(|hint| *hint |= 1);
            // Native AMD64 relocation normalization uses the low 32-bit RVA.
            let original = read32(output, cell)?;
            let relative = original.wrapping_sub(layout.image_base as u32);
            let value = u64::from(mapped(used, relative)).wrapping_add(target_base);
            if width == 8 {
                write64(output, cell, value)?;
            } else {
                write32(output, cell, value as u32)?;
            }
            entries.push((mapped(used, location), kind));
        }
        cursor += block_size;
    }
    entries.sort_unstable_by_key(|entry| entry.0);
    let capacity = layout.available(rva);
    cursor = offset;
    let mut index = 0;
    while index < entries.len() && offset + capacity - cursor >= 8 {
        let page = entries[index].0 & !0xfff;
        write32(output, cursor, page)?;
        let start = cursor;
        cursor += 8;
        while index < entries.len()
            && entries[index].0 & !0xfff == page
            && offset + capacity - cursor >= 2
        {
            write16(
                output,
                cursor,
                (entries[index].0 as u16 & 0xfff) | (entries[index].1 << 12),
            )?;
            cursor += 2;
            index += 1;
        }
        if offset + capacity - cursor >= 2 && !(cursor - start).is_multiple_of(4) {
            write16(output, cursor, 0)?;
            cursor += 2;
        }
        write32(output, start + 4, (cursor - start) as u32)?;
    }
    // Remapping can grow the table beyond the declared directory length into
    // the original section's raw padding. Keep the writer within backed section
    // bytes; unmodified bytes after the emitted blocks remain source dictionary.
    Ok(())
}

fn inferred_relocations_i386(
    layout: &PeLayout,
    output: &mut [u8],
    hints: &mut [u8],
    used: &RiftTable,
    target_base: u32,
) -> Result<()> {
    let base = layout.image_base as u32;
    let end = base.wrapping_add(layout.image_size);
    let mut position = layout.headers;
    // Native inference excludes the final four-byte candidate.
    while position < output.len().saturating_sub(4) {
        let value = read32(output, position)?;
        if value > base && value < end {
            if hints[position..position + 4]
                .iter()
                .all(|hint| hint & 2 == 0)
            {
                hints[position..position + 4]
                    .iter_mut()
                    .for_each(|hint| *hint |= 1);
                write32(
                    output,
                    position,
                    mapped(used, value.wrapping_sub(base)).wrapping_add(target_base),
                )?;
            }
            position += 4;
        } else {
            position += 1;
        }
    }
    Ok(())
}

/// Native flag six uses the load-config LockPrefixTable, not opcode decoding.
fn smash_lock_prefixes(layout: &PeLayout, output: &mut [u8]) -> Result<()> {
    let Some((rva, size)) = layout.directory(10) else {
        return Ok(());
    };
    if size < 36 {
        return Ok(());
    }
    let config = layout.offset(rva, 36)?;
    let pointer = read32(output, config + 32)?;
    if pointer == 0 {
        return Ok(());
    }
    let table_rva = pointer.wrapping_sub(layout.image_base as u32);
    let Ok(table) = layout.offset(table_rva, 4) else {
        return Ok(());
    };
    for index in 0..layout.available(table_rva) / 4 {
        let address = read32(output, table + index * 4)?;
        if address == 0 {
            break;
        }
        let rva = address.wrapping_sub(layout.image_base as u32);
        if let Ok(offset) = layout.offset(rva, 1)
            && layout
                .sections
                .iter()
                .any(|section| offset >= section.raw && offset - section.raw < section.size)
        {
            output[offset] = 0xf0;
        }
    }
    Ok(())
}

/// Native i386 normalization scans bytes, preserving its strict tail exclusion.
/// Long jumps may become short opcodes without compacting the remaining bytes.
fn relative_i386(
    layout: &PeLayout,
    output: &mut [u8],
    hints: &[u8],
    used: &RiftTable,
    calls: bool,
) -> Result<()> {
    for section in &layout.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let length = section.virtual_size.min(section.size);
        let mut position = 0usize;
        while position < length.saturating_sub(5) {
            let mut cell = section.raw + position;
            let opcode = output[cell];
            let conditional = !calls
                && opcode == 0x0f
                && position + 1 < length - 5
                && output[cell + 1] & 0xf0 == 0x80;
            if conditional {
                position += 1;
                cell += 1;
            }
            if (calls && opcode != 0xe8) || (!calls && opcode != 0xe9 && !conditional) {
                position += 1;
                continue;
            }
            if hints[cell..cell + 5].iter().any(|hint| hint & 1 != 0)
                || conditional && hints[cell - 1] & 1 != 0
            {
                position += 1;
                continue;
            }
            let old = read32(output, cell + 1)? as i32;
            if !calls && (-128..=127).contains(&old) {
                position += 1;
                continue;
            }
            let next = section.rva.wrapping_add(position as u32).wrapping_add(5);
            let target = next.wrapping_add(old as u32);
            let target_offset = layout.offset(target, 1).ok();
            if target >= layout.image_size
                || target_offset.is_none_or(|offset| offset == 0 || hints[offset] & 1 != 0)
            {
                position += 1;
                continue;
            }
            let displacement = mapped(used, target).wrapping_sub(mapped(used, next)) as i32;
            if !calls && (-128..=127).contains(&displacement) {
                if conditional {
                    output[cell - 1] = (output[cell] & 0x0f) | 0x70;
                    output[cell] = displacement as u8;
                } else {
                    output[cell] = 0xeb;
                    output[cell + 1] = displacement as u8;
                }
            } else if displacement != old {
                write32(output, cell + 1, displacement as u32)?;
            }
            position += 5;
        }
    }
    Ok(())
}

fn range(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or(Error::Invalid("PE range overflow"))?,
        )
        .ok_or(Error::Invalid("PE truncated range"))
}
fn read16(bytes: &[u8], offset: usize) -> Result<u16> {
    hexspell::utils::extract_u16(bytes, offset).map_err(|_| Error::Invalid("PE u16"))
}
fn read32(bytes: &[u8], offset: usize) -> Result<u32> {
    hexspell::utils::extract_u32(bytes, offset).map_err(|_| Error::Invalid("PE u32"))
}
fn read64(bytes: &[u8], offset: usize) -> Result<u64> {
    hexspell::utils::extract_u64(bytes, offset).map_err(|_| Error::Invalid("PE u64"))
}
fn write16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    range(bytes, offset, 2)?;
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn write32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    range(bytes, offset, 4)?;
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn write64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    range(bytes, offset, 8)?;
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe32_image() -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[..2].copy_from_slice(b"MZ");
        write32(&mut bytes, 0x3c, 0x80).unwrap();
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        write16(&mut bytes, 0x84, 0x14c).unwrap();
        write16(&mut bytes, 0x86, 1).unwrap();
        write16(&mut bytes, 0x94, 224).unwrap();
        write16(&mut bytes, 0x98, 0x10b).unwrap();
        write32(&mut bytes, 0x98 + 28, 0x400000).unwrap();
        write32(&mut bytes, 0x98 + 56, 0x2000).unwrap();
        write32(&mut bytes, 0x98 + 60, 512).unwrap();
        write32(&mut bytes, 0x98 + 92, 16).unwrap();
        bytes[0x178..0x180].copy_from_slice(b".text\0\0\0");
        for (offset, value) in [
            (8, 512),
            (12, 0x1000),
            (16, 512),
            (20, 512),
            (36, 0x60000020),
        ] {
            write32(&mut bytes, 0x178 + offset, value).unwrap();
        }
        bytes
    }

    fn set_pe32_directory(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
        write32(bytes, 0x98 + 96 + index * 8, rva).unwrap();
        write32(bytes, 0x98 + 100 + index * 8, size).unwrap();
    }

    #[test]
    fn pe32_layout_reads_short_image_base_and_directory_offsets() {
        let mut bytes = pe32_image();
        set_pe32_directory(&mut bytes, 14, 0x1100, 72);
        let layout = PeLayout::parse(&bytes).unwrap();
        assert!(layout.is_pe32());
        assert_eq!(layout.image_base, 0x400000);
        assert_eq!(layout.directory(14), Some((0x1100, 72)));
        assert_eq!(layout.offset(0x1100, 72).unwrap(), 768);
        for end in 0..bytes.len() {
            assert!(PeLayout::parse(&bytes[..end]).is_err());
        }
        write16(&mut bytes, 0x84, 0x8664).unwrap();
        assert!(matches!(
            PeLayout::parse(&bytes),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn pe32_imports_walk_four_byte_thunks_and_preserve_ordinals() {
        let mut bytes = pe32_image();
        set_pe32_directory(&mut bytes, 1, 0x10bc, 40);
        write32(&mut bytes, 700, 0x1100).unwrap();
        write32(&mut bytes, 716, 0x1110).unwrap();
        for start in [768, 784] {
            write32(&mut bytes, start, 0x1120).unwrap();
            write32(&mut bytes, start + 4, 0x80000007).unwrap();
        }
        bytes[802..806].copy_from_slice(b"foo\0");
        let layout = PeLayout::parse(&bytes).unwrap();
        let used =
            RiftTable::from_entries(vec![(0, 0), (0x1120, 0x1130)], &Limits::default()).unwrap();
        let mut hints = vec![0; bytes.len()];
        imports(&layout, &mut bytes, &mut hints, &used).unwrap();
        assert_eq!(read32(&bytes, 768).unwrap(), 0x1130);
        assert_eq!(read32(&bytes, 784).unwrap(), 0x1130);
        assert_eq!(read32(&bytes, 772).unwrap(), 0x80000007);
        assert_eq!(&hints[768..776], &[3; 8]);
    }

    #[test]
    fn unbind_stops_at_null_descriptor_before_import_directory_trailing_data() {
        let mut bytes = pe32_image();
        set_pe32_directory(&mut bytes, 1, 0x10bc, 80);
        write32(&mut bytes, 700, 0x1100).unwrap();
        write32(&mut bytes, 716, 0x1110).unwrap();
        // Name/thunk data may share the import directory's declared extent.
        bytes[740..760].fill(0xff);
        let layout = PeLayout::parse(&bytes).unwrap();
        unbind(&layout, &mut bytes).unwrap();
        assert_eq!(&bytes[740..760], &[0xff; 20]);
    }

    #[test]
    fn pe32_highlow_and_inferred_relocations_preserve_native_exclusions() {
        let limits = Limits::default();
        let used = RiftTable::from_entries(vec![(0, 0), (0x1050, 0x1060)], &limits).unwrap();
        let mut bytes = pe32_image();
        set_pe32_directory(&mut bytes, 5, 0x11a0, 12);
        write32(&mut bytes, 928, 0x1000).unwrap();
        write32(&mut bytes, 932, 12).unwrap();
        write16(&mut bytes, 936, 0x3020).unwrap();
        write32(&mut bytes, 544, 0x401050).unwrap();
        let layout = PeLayout::parse(&bytes).unwrap();
        let mut hints = vec![0; bytes.len()];
        relocations(&layout, &mut bytes, &mut hints, &used, 0x500000, &limits).unwrap();
        assert_eq!(read32(&bytes, 544).unwrap(), 0x501060);
        assert_eq!(&hints[544..548], &[1; 4]);
        let mut bytes = pe32_image();
        for start in [600, 608, 1020] {
            write32(&mut bytes, start, 0x401050).unwrap();
        }
        let layout = PeLayout::parse(&bytes).unwrap();
        let mut hints = vec![0; bytes.len()];
        hints[609] = 2;
        relocations(&layout, &mut bytes, &mut hints, &used, 0x500000, &limits).unwrap();
        assert_eq!(read32(&bytes, 600).unwrap(), 0x501060);
        assert_eq!(read32(&bytes, 608).unwrap(), 0x401050);
        assert_eq!(read32(&bytes, 1020).unwrap(), 0x401050);
    }

    #[test]
    fn remapped_relocations_grow_into_backed_section_padding() {
        let limits = Limits::default();
        let mut bytes = pe32_image();
        set_pe32_directory(&mut bytes, 5, 0x11a0, 12);
        write32(&mut bytes, 928, 0x1000).unwrap();
        write32(&mut bytes, 932, 12).unwrap();
        write16(&mut bytes, 936, 0x3020).unwrap();
        write16(&mut bytes, 938, 0x3030).unwrap();
        write32(&mut bytes, 544, 0x401020).unwrap();
        write32(&mut bytes, 560, 0x401030).unwrap();
        let layout = PeLayout::parse(&bytes).unwrap();
        let used = RiftTable::from_entries(vec![(0, 0), (0x1030, 0x2030)], &limits).unwrap();
        let mut hints = vec![0; bytes.len()];
        relocations(&layout, &mut bytes, &mut hints, &used, 0x500000, &limits).unwrap();
        assert_eq!(read32(&bytes, 932).unwrap(), 12);
        assert_eq!(read32(&bytes, 940).unwrap(), 0x2000);
        assert_eq!(read32(&bytes, 944).unwrap(), 12);
        assert_eq!(read16(&bytes, 948).unwrap(), 0x3030);
        assert_eq!(read32(&bytes, 560).unwrap(), 0x502030);
        assert!(bytes[952..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn amd64_walk_preserves_vex_rip_operand_and_maps_adjacent_legacy_operand() {
        let limits = Limits::default();
        let mut bytes = pe32_image();
        set_pe32_directory(&mut bytes, 3, 0x1100, 12);
        write32(&mut bytes, 768, 0x1000).unwrap();
        write32(&mut bytes, 772, 0x1010).unwrap();
        // A focused instruction-walk fixture; layout address mapping is shared
        // with PE32 while the isolated decoder explicitly runs in 64-bit mode.
        let layout = PeLayout::parse(&bytes).unwrap();
        bytes[512..528].copy_from_slice(&[
            0xc5, 0xf8, 0x10, 0x05, 0x20, 0, 0, 0, 0xf3, 0x0f, 0x10, 0x05, 0x18, 0, 0, 0,
        ]);
        let used = RiftTable::from_entries(vec![(0, 0), (0x1028, 0x1128)], &limits).unwrap();
        let hints = vec![0; bytes.len()];
        disassemble(&layout, &mut bytes, &hints, &used).unwrap();
        assert_eq!(read32(&bytes, 516).unwrap(), 0x20);
        assert_eq!(read32(&bytes, 524).unwrap(), 0x118);
    }

    #[test]
    fn i386_relative_scans_shorten_jumps_transform_calls_and_skip_tail() {
        let mut bytes = pe32_image();
        bytes[512] = 0xe9;
        write32(&mut bytes, 513, 0xfb).unwrap();
        bytes[520..522].copy_from_slice(&[0x0f, 0x85]);
        write32(&mut bytes, 522, 0xf2).unwrap();
        bytes[536] = 0xe8;
        write32(&mut bytes, 537, 0xe3).unwrap();
        bytes[1019] = 0xe8;
        write32(&mut bytes, 1020, 0x100u32.wrapping_sub(512)).unwrap();
        let layout = PeLayout::parse(&bytes).unwrap();
        let used = RiftTable::from_entries(
            vec![(0, 0), (0x1100, 0x1010), (0x1101, 0x1101)],
            &Limits::default(),
        )
        .unwrap();
        let hints = vec![0; bytes.len()];
        relative_i386(&layout, &mut bytes, &hints, &used, false).unwrap();
        assert_eq!(&bytes[512..517], &[0xeb, 11, 0, 0, 0]);
        assert_eq!(&bytes[520..522], &[0x75, 2]);
        relative_i386(&layout, &mut bytes, &hints, &used, true).unwrap();
        assert_eq!(read32(&bytes, 537).unwrap() as i32, -13);
        assert_eq!(read32(&bytes, 1020).unwrap(), 0xffffff00);
    }

    #[test]
    fn lock_smashing_uses_load_config_addresses_and_excludes_headers() {
        let mut bytes = pe32_image();
        set_pe32_directory(&mut bytes, 10, 0x1100, 36);
        write32(&mut bytes, 768 + 32, 0x401140).unwrap();
        write32(&mut bytes, 832, 0x401050).unwrap();
        write32(&mut bytes, 836, 0x400100).unwrap();
        let layout = PeLayout::parse(&bytes).unwrap();
        smash_lock_prefixes(&layout, &mut bytes).unwrap();
        assert_eq!(bytes[592], 0xf0);
        assert_eq!(bytes[256], 0);
    }

    #[test]
    fn repeated_pdata_ranges_cannot_amplify_disassembly_work() {
        let mut source = include_bytes!("../../docs/fixtures/pa30-pe-native/source.exe").to_vec();
        let layout = PeLayout::parse(&source).unwrap();
        let (rva, _) = layout.directory(3).unwrap();
        let offset = layout.offset(rva, 512).unwrap();
        write32(&mut source, layout.optional + 112 + 3 * 8 + 4, 512).unwrap();
        for index in 0..512 / 12 {
            write32(&mut source, offset + index * 12, 0x1000).unwrap();
            write32(&mut source, offset + index * 12 + 4, 0x1200).unwrap();
            write32(&mut source, offset + index * 12 + 8, 0).unwrap();
        }
        let layout = PeLayout::parse(&source).unwrap();
        let hints = vec![0; source.len()];
        assert!(matches!(
            disassemble(&layout, &mut source, &hints, &RiftTable::default()),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn every_truncated_pe_source_is_rejected_without_panicking() {
        let source = include_bytes!("../../docs/fixtures/pa30-pe-native/source.exe");
        let layout = PeLayout::parse(source).unwrap();
        let required = layout
            .sections
            .iter()
            .map(|s| s.raw + s.size)
            .max()
            .unwrap();
        for end in 0..required {
            assert!(PeLayout::parse(&source[..end]).is_err(), "truncation {end}");
        }
    }

    #[test]
    fn resource_cycles_and_out_of_bounds_records_are_rejected() {
        let used = RiftTable::from_entries(vec![(0, 0)], &Limits::default()).unwrap();
        let mut resource = [0u8; 32];
        resource[14..16].copy_from_slice(&1u16.to_le_bytes());
        resource[20..24].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        assert!(matches!(
            resource_directory(&mut resource, 0, 4096, &used, 0, &mut 0),
            Err(Error::Invalid("PE resource directory cycle"))
        ));
        resource[20..24].copy_from_slice(&31u32.to_le_bytes());
        assert!(resource_directory(&mut resource, 0, 4096, &used, 0, &mut 0).is_err());
    }

    #[test]
    fn available_skips_earlier_sections_without_subtraction_underflow() {
        let layout = PeLayout::parse(include_bytes!(
            "../../docs/fixtures/pa30-pe-native/source.exe"
        ))
        .unwrap();
        let last = layout.sections.last().unwrap();
        assert_eq!(layout.available(last.rva), last.size);
        assert_eq!(layout.available(u32::MAX), 0);
    }
}
