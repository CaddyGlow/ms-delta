//! PE32 source normalization and rift-based transformation used by PA19.
//!
//! This is a bounds-checked port of the `mspatcha.dll` routines
//! `NormalizeCoffImage`, `TransformCoffImage` and the legacy-order
//! `TransformOldFile_PE_*` helpers. Where `mspatcha.dll` reads or writes
//! outside the image (or raises its PE format exception) this port returns
//! [`Error::Invalid`].

use crate::{Error, Result};

const BAD_PE: Error = Error::Invalid("malformed PE32 source image");

/// Rift table: cumulative `(old_rva, new_rva)` pairs, as stored in PA19.
pub(super) type Rift = [(u32, u32)];

fn rd16(buf: &[u8], offset: usize) -> Result<u16> {
    hexspell::utils::extract_u16(buf, offset).map_err(|_| BAD_PE)
}

fn rd32(buf: &[u8], offset: usize) -> Result<u32> {
    hexspell::utils::extract_u32(buf, offset).map_err(|_| BAD_PE)
}

fn wr16(buf: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let end = offset.checked_add(2).ok_or(BAD_PE)?;
    buf.get_mut(offset..end)
        .ok_or(BAD_PE)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn wr32(buf: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let end = offset.checked_add(4).ok_or(BAD_PE)?;
    buf.get_mut(offset..end)
        .ok_or(BAD_PE)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn set_mark(mark: &mut [u8], offset: usize, length: usize, value: u8) {
    if let Some(end) = offset.checked_add(length)
        && let Some(slice) = mark.get_mut(offset..end.min(mark.len()))
    {
        slice.fill(value);
    }
}

fn or_mark(mark: &mut [u8], offset: usize, mask: &[u8]) {
    for (index, bit) in mask.iter().enumerate() {
        if let Some(byte) = mark.get_mut(offset + index) {
            *byte |= bit;
        }
    }
}

/// `GetNewRvaFromRiftTable`: the delta of the last entry whose old RVA is at or below `rva`.
pub(super) fn new_rva(rift: &Rift, rva: u32) -> u32 {
    let (mut low, mut high) = (0usize, rift.len());
    while low < high {
        let mid = (low + high) >> 1;
        let (old, new) = rift[mid];
        if old >= rva {
            if old <= rva {
                return rva.wrapping_add(new).wrapping_sub(old);
            }
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    if low == 0 {
        rva
    } else {
        let (old, new) = rift[low - 1];
        rva.wrapping_add(new).wrapping_sub(old)
    }
}

/// Offset of the NT headers, validated like `GetNtHeader`; `None` for non-PE32 data.
pub(super) fn nt_header(buf: &[u8]) -> Option<usize> {
    let size = buf.len();
    if size < 0x200 || buf[0] != b'M' || buf[1] != b'Z' {
        return None;
    }
    let headers = hexspell::pe::view::PeHeaders::parse(buf).ok()?;
    let nt = headers.nt;
    if nt.checked_add(248)? > size || headers.magic().ok()? != 0x10b {
        return None;
    }
    let sections = headers.sections;
    let sections_end = sections + 40 * usize::from(headers.coff.number_of_sections.value);
    let dirs_end = nt + 8 * (rd32(buf, nt + 116).ok()? as usize + 15);
    (sections > nt
        && sections <= sections_end
        && sections_end <= size
        && nt + 120 <= dirs_end
        && dirs_end <= size)
        .then_some(nt)
}

fn first_section(buf: &[u8], nt: usize) -> Result<usize> {
    Ok(nt + usize::from(rd16(buf, nt + 20)?) + 24)
}

fn section_header(buf: &[u8], nt: usize, index: usize) -> Result<usize> {
    let header = first_section(buf, nt)? + 40 * index;
    if header + 40 > buf.len() {
        return Err(BAD_PE);
    }
    Ok(header)
}

/// `ImageRvaToFileOffset`; zero means not found.
fn rva_to_offset(buf: &[u8], nt: usize, rva: u32) -> Result<u32> {
    if rva < rd32(buf, nt + 84)? {
        return Ok(rva);
    }
    for index in 0..usize::from(rd16(buf, nt + 6)?) {
        let header = section_header(buf, nt, index)?;
        let section =
            hexspell::pe::section::PeSection::parse_section(buf, header).map_err(|_| BAD_PE)?;
        let virtual_address = section.virtual_address.value;
        let raw_size = section.size_of_raw_data.value;
        if rva >= virtual_address && rva < raw_size.wrapping_add(virtual_address) {
            return Ok(rva
                .wrapping_add(section.pointer_to_raw_data.value)
                .wrapping_sub(virtual_address));
        }
    }
    Ok(0)
}

/// Data directory `(rva, size)`; `None` when the index is beyond the table or the RVA is zero.
fn directory(buf: &[u8], nt: usize, index: usize) -> Result<Option<(u32, u32)>> {
    if index >= rd32(buf, nt + 116)? as usize {
        return Ok(None);
    }
    let entry = nt + 120 + 8 * index;
    let directory =
        hexspell::pe::header::DataDirectoryEntry::parse(buf, entry).map_err(|_| BAD_PE)?;
    let rva = directory.virtual_address.value;
    let size = directory.size.value;
    Ok((rva != 0).then_some((rva, size)))
}

/// `ImageDirectoryOffsetAndSize`: file offset (zero if unmapped) and directory size.
fn directory_offset(buf: &[u8], nt: usize, index: usize) -> Result<Option<(usize, u32)>> {
    match directory(buf, nt, index)? {
        Some((rva, size)) => Ok(Some((rva_to_offset(buf, nt, rva)? as usize, size))),
        None => Ok(None),
    }
}

/// `ImageDirectoryMappedAddress`: directory file offset only if wholly inside the image.
fn directory_mapped(buf: &[u8], nt: usize, index: usize) -> Result<Option<(usize, u32)>> {
    let Some((rva, size)) = directory(buf, nt, index)? else {
        return Ok(None);
    };
    let offset = rva_to_offset(buf, nt, rva)? as usize;
    if offset == 0 || offset >= buf.len() || offset + size as usize > buf.len() {
        return Ok(None);
    }
    Ok(Some((offset, size)))
}

fn rebase(buf: &mut [u8], nt: usize, new_base: u32) -> Result<bool> {
    let delta = new_base.wrapping_sub(rd32(buf, nt + 52)?);
    let Some((mut block, mut remaining)) = directory_mapped(buf, nt, 5)?
        .map(|(offset, size)| (offset, i64::from(size as i32)))
        .filter(|(offset, _)| offset + 8 <= buf.len())
    else {
        return Ok(false);
    };
    wr32(buf, nt + 52, new_base)?;
    let end = buf.len();
    while remaining > 0 {
        let page = rd32(buf, block)?;
        let block_size = rd32(buf, block + 4)?;
        if i64::from(block_size) > remaining || block_size <= 8 {
            break;
        }
        let base = rva_to_offset(buf, nt, page)? as usize;
        let mut entry = block + 8;
        let mut count = (block_size - 8) >> 1;
        while count != 0 {
            count -= 1;
            if entry + 2 > end {
                break;
            }
            let word = rd16(buf, entry)?;
            let target = base + usize::from(word & 0xfff);
            if target + 2 <= end {
                match word >> 12 {
                    1 => {
                        let value = u32::from(rd16(buf, target)?) << 16;
                        wr16(buf, target, (value.wrapping_add(delta) >> 16) as u16)?;
                    }
                    2 => {
                        let value = rd16(buf, target)?;
                        wr16(buf, target, value.wrapping_add(delta as u16))?;
                    }
                    3 if target + 4 <= end => {
                        let value = rd32(buf, target)?;
                        wr32(buf, target, value.wrapping_add(delta))?;
                    }
                    4 => {
                        count = count.wrapping_sub(1);
                        entry += 2;
                        if entry + 2 <= end {
                            let low = i32::from(rd16(buf, entry)? as i16);
                            let high = u32::from(rd16(buf, target)?) << 16;
                            let sum = (low as u32)
                                .wrapping_add(delta)
                                .wrapping_add(high)
                                .wrapping_add(0x8000);
                            wr16(buf, target, (sum >> 16) as u16)?;
                        }
                    }
                    _ => {}
                }
            }
            entry += 2;
        }
        remaining -= i64::from(block_size);
        block += block_size as usize;
        if block + 8 > end {
            return Err(BAD_PE);
        }
    }
    Ok(true)
}

fn unbind(buf: &mut [u8], nt: usize) -> Result<bool> {
    let mut changed = false;
    if let Some((offset, size)) = directory_mapped(buf, nt, 11)? {
        buf[offset..offset + size as usize].fill(0);
        wr32(buf, nt + 208, 0)?;
        wr32(buf, nt + 212, 0)?;
        changed = true;
    }
    let size = buf.len();
    if let Some((offset, _)) = directory_mapped(buf, nt, 1)?
        && offset + 20 <= size
    {
        let mut descriptor = offset;
        while descriptor + 20 <= size {
            let original = rd32(buf, descriptor)?;
            if original == 0 {
                break;
            }
            if rd32(buf, descriptor + 4)? != 0 {
                wr32(buf, descriptor + 4, 0)?;
                changed = true;
                let source = rva_to_offset(buf, nt, original)? as usize;
                let target = rva_to_offset(buf, nt, rd32(buf, descriptor + 16)?)? as usize;
                if source != 0 && source < size && target != 0 && target < size {
                    let mut cursor = source;
                    while cursor + 4 <= size {
                        let destination = cursor as i64 + (target as i64 - source as i64);
                        if destination < 0 || destination as usize + 4 > size {
                            break;
                        }
                        let value = rd32(buf, cursor)?;
                        if value == 0 {
                            break;
                        }
                        wr32(buf, destination as usize, value)?;
                        cursor += 4;
                    }
                }
            }
            if rd32(buf, descriptor + 8)? != 0 {
                wr32(buf, descriptor + 8, 0)?;
                changed = true;
            }
            descriptor += 20;
        }
    }
    for index in 0..usize::from(rd16(buf, nt + 6)?) {
        let header = section_header(buf, nt, index)?;
        let name = u64::from_le_bytes(buf[header..header + 8].try_into().map_err(|_| BAD_PE)?);
        if name | 0x2020_2020_2020_2020 == 0x2020_6174_6164_692e {
            let flags = rd32(buf, header + 36)?;
            if flags & 0x8000_0000 == 0 {
                wr32(buf, header + 36, flags | 0xC000_0000)?;
                changed = true;
            }
            break;
        }
    }
    Ok(changed)
}

fn smash_lock_prefixes(buf: &mut [u8], nt: usize) -> Result<bool> {
    let Some((config, _)) = directory_mapped(buf, nt, 10)? else {
        return Ok(false);
    };
    let table = rd32(buf, config + 32)?;
    if table == 0 {
        return Ok(false);
    }
    let base = rd32(buf, nt + 52)?;
    if table < base {
        return Err(BAD_PE);
    }
    let table_offset = rva_to_offset(buf, nt, table - base)? as usize;
    if table_offset == 0 || table_offset >= buf.len() {
        return Ok(false);
    }
    let mut changed = false;
    let mut cursor = table_offset;
    while cursor + 4 <= buf.len() {
        let value = rd32(buf, cursor)?;
        if value == 0 {
            return Ok(changed);
        }
        if value < base {
            break;
        }
        let offset = rva_to_offset(buf, nt, value - base)? as usize;
        if offset != 0
            && offset < buf.len()
            && let Some(byte) = buf.get_mut(offset)
            && *byte != 0xf0
        {
            *byte = 0xf0;
            changed = true;
        }
        cursor += 4;
    }
    Err(BAD_PE)
}

fn pe_checksum(buf: &[u8]) -> u32 {
    let size = buf.len();
    let mut sum = 0u32;
    let mut words = buf[..size & !1].as_chunks::<2>().0.iter().peekable();
    while words.peek().is_some() {
        let mut part = 0u32;
        for word in words.by_ref().take(0x10000) {
            part = part.wrapping_add(u32::from(u16::from_le_bytes([word[0], word[1]])));
        }
        sum = sum.wrapping_add((part >> 16) + (part & 0xffff));
    }
    if size & 1 != 0 {
        sum = sum.wrapping_add(u32::from(buf[size - 1]));
    }
    let folded = (sum >> 16) + (sum & 0xffff);
    (size as u32).wrapping_add((folded + (folded >> 16)) & 0xffff)
}

/// `NormalizeCoffImage`: rebase/retimestamp, unbind, smash lock prefixes, fix the checksum.
///
/// Returns whether any byte changed. Does nothing for non-PE32 data.
pub(super) fn normalize(
    buf: &mut [u8],
    flags: u32,
    coff_base: u32,
    coff_time: u32,
) -> Result<bool> {
    let Some(nt) = nt_header(buf) else {
        return Ok(false);
    };
    let mut changed = false;
    if flags & 0x40000 == 0 {
        if coff_time != 0 && rd32(buf, nt + 8)? != coff_time {
            wr32(buf, nt + 8, coff_time)?;
            changed = true;
        }
        if coff_base != 0 && rd32(buf, nt + 52)? != coff_base {
            changed |= rebase(buf, nt, coff_base)?;
        }
    }
    if flags & 0x10000 == 0 {
        changed |= unbind(buf, nt)?;
    }
    if flags & 0x20000 == 0 {
        changed |= smash_lock_prefixes(buf, nt)?;
    }
    if flags & 0x20_0000 != 0 {
        if rd32(buf, nt + 88)? != 0 {
            wr32(buf, nt + 88, 0)?;
            return Ok(true);
        }
    } else if changed {
        wr32(buf, nt + 88, 0)?;
        let checksum = pe_checksum(buf);
        wr32(buf, nt + 88, checksum)?;
    }
    Ok(changed)
}

/// Whether the transform options select the unsupported newer ordering.
pub(super) fn option_selects_new_order(options: u32) -> bool {
    options & 0x300 != 0
}

/// `TransformCoffImage`, driven by the rift table and `options`.
///
/// Does nothing for non-PE32 data. `options` bits 0x1/0x2/0x4/0x8/0x10/0x20 disable the
/// relocation, import, export, relative-jump, relative-call and resource passes.
/// Without option bits 0x100/0x200 the legacy order is used (marks, relocations, imports,
/// exports, jumps, calls, resources through the "old compatible" resource walker); with either
/// bit the current order is used (marks that skip unmapped directories, imports, exports,
/// resources through the current walker, relocations, jumps, calls). Bit 0x200 additionally
/// replaces a missing or unmapped relocation directory of an x86 image by a scan for absolute
/// pointers into the image.
pub(super) fn transform(
    buf: &mut [u8],
    options: u32,
    resource_time: u32,
    rift: &Rift,
) -> Result<()> {
    let Some(nt) = nt_header(buf) else {
        return Ok(());
    };
    let mut mark = Vec::new();
    mark.try_reserve_exact(buf.len())
        .map_err(|_| Error::Allocation)?;
    mark.resize(buf.len(), 0u8);
    if option_selects_new_order(options) {
        mark_non_exe(buf, nt, &mut mark, false)?;
        if options & 2 == 0 {
            imports(buf, nt, &mut mark, rift)?;
        }
        if options & 4 == 0 {
            exports(buf, nt, &mut mark, rift)?;
        }
        if options & 0x20 == 0 {
            resources_current(buf, nt, resource_time, rift)?;
        }
        if options & 1 == 0 {
            if options & 0x200 == 0 || relocation_directory_mapped(buf, nt)? {
                relocations(buf, nt, &mut mark, rift)?;
            } else if rd16(buf, nt + 4)? == 0x14c {
                scan_absolute_pointers(buf, nt, &mut mark, rift)?;
            }
        }
        if options & 8 == 0 {
            relative_branches(buf, nt, &mark, rift, true)?;
        }
        if options & 0x10 == 0 {
            relative_branches(buf, nt, &mark, rift, false)?;
        }
        return Ok(());
    }
    mark_non_exe(buf, nt, &mut mark, true)?;
    if options & 1 == 0 {
        relocations(buf, nt, &mut mark, rift)?;
    }
    if options & 2 == 0 {
        imports(buf, nt, &mut mark, rift)?;
    }
    if options & 4 == 0 {
        exports(buf, nt, &mut mark, rift)?;
    }
    if options & 8 == 0 {
        relative_branches(buf, nt, &mark, rift, true)?;
    }
    if options & 0x10 == 0 {
        relative_branches(buf, nt, &mark, rift, false)?;
    }
    if options & 0x20 == 0 {
        resources(buf, nt, resource_time, rift)?;
    }
    Ok(())
}

/// `ImageDirectoryOffsetAndSize(5)` is nonzero and the directory lies inside the file.
fn relocation_directory_mapped(buf: &[u8], nt: usize) -> Result<bool> {
    Ok(match directory_offset(buf, nt, 5)? {
        Some((offset, size)) => offset != 0 && offset as u64 + u64::from(size) <= buf.len() as u64,
        None => false,
    })
}

/// The x86 fallback of the current pass order for images without usable relocations: every
/// aligned-by-scan dword whose value points into `(ImageBase, ImageBase + SizeOfImage)` and
/// whose mark bits allow it is treated as an absolute pointer and moved through the rift.
fn scan_absolute_pointers(buf: &mut [u8], nt: usize, mark: &mut [u8], rift: &Rift) -> Result<()> {
    let base = rd32(buf, nt + 52)?;
    let limit = base.wrapping_add(rd32(buf, nt + 80)?);
    let mut position = rd32(buf, nt + 84)? as usize;
    while position + 4 <= buf.len() && position < buf.len().saturating_sub(4) {
        let value = rd32(buf, position)?;
        if value > base && value < limit {
            let marked = rd32(mark, position)?;
            if marked & 0x0202_0202 == 0 {
                wr32(mark, position, marked | 0x0101_0101)?;
                let old = value.wrapping_sub(base);
                let new = new_rva(rift, old);
                if new != old {
                    wr32(buf, position, new.wrapping_add(base))?;
                }
                position += 4;
                continue;
            }
        }
        position += 1;
    }
    Ok(())
}

/// `TransformOldFile_PE_MarkNonExe`. `legacy` is its last argument: the legacy order marks a
/// directory even when its RVA maps to file offset zero, the current order does not.
fn mark_non_exe(buf: &mut [u8], nt: usize, mark: &mut [u8], legacy: bool) -> Result<()> {
    let size = buf.len();
    for index in 0..usize::from(rd16(buf, nt + 6)?) {
        let header = first_section(buf, nt)? + 40 * index;
        let flags = rd32(buf, header + 36)?;
        let pointer = rd32(buf, header + 20)? as usize;
        if flags & 0x2000_0000 == 0 && pointer < size {
            let length = (rd32(buf, header + 16)? as usize).min(size - pointer);
            set_mark(mark, pointer, length, 1);
        }
    }
    let mut headers = rd32(buf, nt + 84)?;
    if headers as usize > size {
        headers = size as u32;
        wr32(buf, nt + 84, headers)?;
    }
    set_mark(mark, 0, headers as usize, 3);
    for index in 0..16 {
        let rva = rd32(buf, nt + 120 + 8 * index)?;
        let length = rd32(buf, nt + 124 + 8 * index)? as usize;
        if rva != 0 && length != 0 {
            let offset = rva_to_offset(buf, nt, rva)? as usize;
            if (offset != 0 || legacy) && offset < size {
                set_mark(mark, offset, length.min(size - offset), 3);
            }
        }
    }
    Ok(())
}

struct RelocEntry {
    rva: u32,
    kind: u8,
}

/// Port of the unstable `RelocQsort`, ordered by RVA only, without recursion.
fn reloc_qsort(entries: &mut [RelocEntry]) {
    let mut pending = vec![(0isize, entries.len() as isize - 1)];
    while let Some((mut low, high)) = pending.pop() {
        loop {
            let (mut left, mut right) = (low, high);
            let mut mid = low + (high - low) / 2;
            let pivot = entries[mid as usize].rva;
            loop {
                if left > right {
                    break;
                }
                loop {
                    if entries[left as usize].rva > pivot {
                        break;
                    }
                    left += 1;
                    if left > right {
                        break;
                    }
                }
                while right >= left && entries[right as usize].rva >= pivot {
                    right -= 1;
                }
                let mut again = left <= right;
                if left < right {
                    entries.swap(left as usize, right as usize);
                    left += 1;
                    right -= 1;
                    again = left <= right;
                }
                if !again {
                    break;
                }
            }
            if left >= mid {
                if right > mid {
                    entries.swap(right as usize, mid as usize);
                    mid = right;
                }
            } else {
                entries.swap(left as usize, mid as usize);
                mid = left;
            }
            if low < mid - 1 {
                pending.push((low, mid - 1));
            }
            low = mid + 1;
            if low >= high {
                break;
            }
        }
    }
}

fn relocations(buf: &mut [u8], nt: usize, mark: &mut [u8], rift: &Rift) -> Result<()> {
    let size = buf.len();
    let base = rd32(buf, nt + 52)?;
    match directory_offset(buf, nt, 5)? {
        Some((dir, dir_size)) if dir != 0 && dir_size as usize + dir <= size => {
            set_mark(mark, dir, dir_size as usize, 3);
            let mut entries: Vec<RelocEntry> = Vec::new();
            let mut block = dir;
            let mut remaining = i64::from(dir_size as i32);
            while remaining > 0 {
                if block + 8 > size {
                    return Err(BAD_PE);
                }
                let page = rd32(buf, block)?;
                let block_size = rd32(buf, block + 4)?;
                if i64::from(block_size) > remaining || block_size <= 8 {
                    break;
                }
                let page_offset = rva_to_offset(buf, nt, page)? as usize;
                let page_va = base.wrapping_add(page);
                let mut entry = block + 8;
                let mut count = (block_size - 8) >> 1;
                loop {
                    if count == 0 {
                        break;
                    }
                    count -= 1;
                    if entry + 2 > size {
                        return Err(BAD_PE);
                    }
                    let word = rd16(buf, entry)?;
                    let kind = (word >> 12) as u8;
                    if kind != 0 {
                        let rva = new_rva(
                            rift,
                            page_va
                                .wrapping_add(u32::from(word & 0xfff))
                                .wrapping_sub(base),
                        );
                        entries.try_reserve(1).map_err(|_| Error::Allocation)?;
                        entries.push(RelocEntry { rva, kind });
                        let location = page_offset + usize::from(word & 0xfff);
                        match kind {
                            1 | 2 => {
                                if location + 2 < size {
                                    or_mark(mark, location, &[1, 1]);
                                }
                            }
                            3 => {
                                if location + 4 <= size {
                                    or_mark(mark, location, &[1, 1, 1, 1]);
                                    let value = rd32(buf, location)?;
                                    let updated =
                                        new_rva(rift, value.wrapping_sub(base)).wrapping_add(base);
                                    wr32(buf, location, updated)?;
                                }
                            }
                            4 => {
                                if location + 2 < size {
                                    or_mark(mark, location, &[1, 1]);
                                }
                                entry += 2;
                                count = count.wrapping_sub(1);
                                if entry + 2 > size {
                                    return Err(BAD_PE);
                                }
                            }
                            _ => {}
                        }
                    }
                    entry += 2;
                }
                remaining -= i64::from(block_size);
                block += block_size as usize;
            }
            if entries.len() > 1 {
                reloc_qsort(&mut entries);
            }
            let mut available = dir_size;
            for index in 0..usize::from(rd16(buf, nt + 6)?) {
                let header = section_header(buf, nt, index)?;
                let name =
                    u64::from_le_bytes(buf[header..header + 8].try_into().map_err(|_| BAD_PE)?);
                if name | 0x2020_2020_2020_2020 == 0x2020_636f_6c65_722e {
                    let pointer = rd32(buf, header + 20)?;
                    if dir as u32 >= pointer {
                        let end = pointer.wrapping_add(rd32(buf, header + 16)?);
                        if (dir as u32) < end {
                            available = end - dir as u32;
                        }
                    }
                }
            }
            if dir + available as usize > size {
                return Err(BAD_PE);
            }
            let mut left = i64::from((available & !1) as i32);
            let mut position = dir;
            let mut index = 0usize;
            while left > 8 && index < entries.len() {
                let page = entries[index].rva & 0xffff_f000;
                wr32(buf, position, page)?;
                let mut cursor = position + 8;
                left -= 8;
                while left > 0 {
                    if index >= entries.len() || entries[index].rva & 0xffff_f000 != page {
                        if cursor & 2 != 0 {
                            wr16(buf, cursor, 0)?;
                            cursor += 2;
                            left -= 2;
                        }
                        break;
                    }
                    let item = &entries[index];
                    wr16(
                        buf,
                        cursor,
                        ((item.rva & 0xfff) as u16) | (u16::from(item.kind) << 12),
                    )?;
                    cursor += 2;
                    left -= 2;
                    index += 1;
                }
                wr32(buf, position + 4, (cursor - position) as u32)?;
                position = cursor;
            }
        }
        _ => {
            if rd16(buf, nt + 4)? == 0x14c {
                let first = first_section(buf, nt)?;
                let low = base.wrapping_add(rd32(buf, first + 12)?);
                let high = base.wrapping_add(rd32(buf, nt + 80)?);
                let mut cursor = rd32(buf, first + 20)? as usize;
                if size >= 4 && cursor < size - 4 {
                    loop {
                        let value = rd32(buf, cursor)?;
                        if value >= low && value < high {
                            or_mark(mark, cursor, &[1, 1, 1, 1]);
                            let updated =
                                new_rva(rift, value.wrapping_sub(base)).wrapping_add(base);
                            wr32(buf, cursor, updated)?;
                            cursor += 3;
                        }
                        cursor += 1;
                        if cursor >= size - 4 {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Length of the thunk-name record at `offset` (hint, name, NUL), after `mspatcha` checks.
fn import_name_length(buf: &[u8], offset: usize) -> Result<usize> {
    if offset + 4 > buf.len() || offset + 2 >= buf.len() {
        return Err(BAD_PE);
    }
    let name = &buf[offset + 2..];
    name.iter().position(|byte| *byte == 0).ok_or(BAD_PE)
}

fn import_thunks(buf: &mut [u8], nt: usize, mark: &mut [u8], rift: &Rift, rva: u32) -> Result<()> {
    let size = buf.len();
    let start = rva_to_offset(buf, nt, rva)? as usize;
    let mut cursor = start;
    while cursor + 4 <= size {
        let value = rd32(buf, cursor)?;
        if value == 0 {
            break;
        }
        if (value as i32) >= 0 {
            let offset = rva_to_offset(buf, nt, value)? as usize;
            let length = import_name_length(buf, offset)?;
            if offset + length + 3 <= size {
                set_mark(mark, offset, length + 3, 3);
            }
            wr32(buf, cursor, new_rva(rift, value))?;
        }
        cursor += 4;
    }
    set_mark(mark, start, cursor - start, 3);
    Ok(())
}

fn imports(buf: &mut [u8], nt: usize, mark: &mut [u8], rift: &Rift) -> Result<()> {
    let size = buf.len();
    let Some((dir, dir_size)) = directory_offset(buf, nt, 1)? else {
        return Ok(());
    };
    if dir == 0 || dir_size as usize + dir > size {
        return Ok(());
    }
    set_mark(mark, dir, dir_size as usize, 3);
    let mut descriptor = dir;
    while descriptor + 20 <= size {
        let original = rd32(buf, descriptor)?;
        if original == 0 {
            break;
        }
        if rd32(buf, descriptor + 4)? == 0 {
            import_thunks(buf, nt, mark, rift, original)?;
            let first_thunk = rd32(buf, descriptor + 16)?;
            import_thunks(buf, nt, mark, rift, first_thunk)?;
        }
        let name = rd32(buf, descriptor + 12)?;
        wr32(buf, descriptor + 12, new_rva(rift, name))?;
        wr32(buf, descriptor, new_rva(rift, original))?;
        let first_thunk = rd32(buf, descriptor + 16)?;
        wr32(buf, descriptor + 16, new_rva(rift, first_thunk))?;
        descriptor += 20;
    }
    Ok(())
}

fn transform_table(
    buf: &mut [u8],
    mark: &mut [u8],
    rift: &Rift,
    offset: usize,
    count: usize,
    element: usize,
    rewrite: bool,
) -> Result<()> {
    let size = buf.len();
    if offset + count * element <= size {
        set_mark(mark, offset, count * element, 3);
    }
    if rewrite {
        let mut cursor = offset;
        for _ in 0..count {
            if cursor + 4 > size {
                break;
            }
            let value = rd32(buf, cursor)?;
            wr32(buf, cursor, new_rva(rift, value))?;
            cursor += 4;
        }
    }
    Ok(())
}

fn exports(buf: &mut [u8], nt: usize, mark: &mut [u8], rift: &Rift) -> Result<()> {
    let size = buf.len();
    let Some((dir, dir_size)) = directory_offset(buf, nt, 0)? else {
        return Ok(());
    };
    if dir == 0 || dir_size as usize + dir > size {
        return Ok(());
    }
    set_mark(mark, dir, dir_size as usize, 3);
    let functions = rd32(buf, dir + 20)? as usize;
    let names = rd32(buf, dir + 24)? as usize;
    let functions_rva = rd32(buf, dir + 28)?;
    let names_rva = rd32(buf, dir + 32)?;
    let ordinals_rva = rd32(buf, dir + 36)?;
    let functions_offset = rva_to_offset(buf, nt, functions_rva)? as usize;
    transform_table(buf, mark, rift, functions_offset, functions, 4, true)?;
    let names_offset = rva_to_offset(buf, nt, names_rva)? as usize;
    transform_table(buf, mark, rift, names_offset, names, 4, true)?;
    let ordinals_offset = rva_to_offset(buf, nt, ordinals_rva)? as usize;
    transform_table(buf, mark, rift, ordinals_offset, names, 2, false)?;
    for (field, rva) in [
        (12, rd32(buf, dir + 12)?),
        (28, functions_rva),
        (32, names_rva),
        (36, ordinals_rva),
    ] {
        wr32(buf, dir + field, new_rva(rift, rva))?;
    }
    Ok(())
}

/// Port of `TransformOldFile_PE_RelativeJmps` (`jumps`) and `..._RelativeCalls`.
///
/// The jump pass handles `E9` near jumps and `0F 8x` near conditional jumps and may narrow a
/// displacement to the short form (`EB`/`7x`); the call pass handles `E8` only and never narrows.
fn relative_branches(
    buf: &mut [u8],
    nt: usize,
    mark: &[u8],
    rift: &Rift,
    jumps: bool,
) -> Result<()> {
    let size = buf.len();
    let image_size = rd32(buf, nt + 80)?;
    for index in 0..usize::from(rd16(buf, nt + 6)?) {
        let header = section_header(buf, nt, index)?;
        if rd32(buf, header + 36)? & 0x2000_0000 == 0 {
            continue;
        }
        let pointer = rd32(buf, header + 20)? as usize;
        let length = rd32(buf, header + 16)?.min(rd32(buf, header + 8)?) as usize;
        let virtual_address = rd32(buf, header + 12)?;
        if pointer >= size || pointer + length > size || rd16(buf, nt + 4)? != 0x14c {
            continue;
        }
        let Some(end) = (pointer + length).checked_sub(5) else {
            continue;
        };
        let mut position = pointer;
        while position < end {
            let opcode = buf[position];
            let mut instruction = position;
            let mut candidate = false;
            if opcode == if jumps { 0xe9 } else { 0xe8 } {
                candidate = true;
            } else if jumps && opcode == 0x0f {
                let next = buf[position + 1];
                if next & 0xf0 == 0x80 {
                    instruction = position + 1;
                    if instruction < end {
                        candidate = true;
                    }
                    position = instruction;
                }
            }
            if candidate {
                let is_whole_opcode = buf[instruction] != 0x0f && buf[instruction] & 0xf0 != 0x80;
                let prefix_marked = !is_whole_opcode && mark[instruction - 1] & 1 != 0;
                let clear = mark[instruction..instruction + 5]
                    .iter()
                    .all(|byte| byte & 1 == 0);
                if !prefix_marked && clear {
                    let displacement = rd32(buf, instruction + 1)?;
                    let long = displacement.wrapping_add(128) > 0xff;
                    if !jumps || long {
                        let next_rva = virtual_address
                            .wrapping_add((instruction - pointer) as u32)
                            .wrapping_add(5);
                        let target = next_rva.wrapping_add(displacement);
                        if target < image_size {
                            let target_offset = rva_to_offset(buf, nt, target)? as usize;
                            let marked = mark.get(target_offset).ok_or(BAD_PE)? & 1 != 0;
                            if !marked {
                                let moved_target = new_rva(rift, target);
                                let moved_next = new_rva(rift, next_rva);
                                let updated = moved_target.wrapping_sub(moved_next);
                                if updated.wrapping_add(128) > 0xff || !jumps {
                                    if updated != displacement {
                                        wr32(buf, instruction + 1, updated)?;
                                    }
                                } else if is_whole_opcode {
                                    buf[instruction] = 0xeb;
                                    buf[instruction + 1] = updated as u8;
                                } else {
                                    let opcode = buf[instruction];
                                    buf[instruction] = updated as u8;
                                    buf[instruction - 1] = (opcode & 0xf) | 0x70;
                                }
                                position = instruction + 4;
                            }
                        }
                    }
                }
            }
            position += 1;
        }
    }
    Ok(())
}

struct ResourceContext<'a> {
    rift: &'a Rift,
    directory: usize,
    end: usize,
    budget: u32,
    consumed: u32,
    time: u32,
    old_rva: u32,
    new_rva: u32,
}

struct ResourceFrame {
    cursor: usize,
    remaining: i32,
    after_child: bool,
}

fn enter_resource_directory(
    buf: &mut [u8],
    context: &mut ResourceContext<'_>,
    node: usize,
) -> Result<Option<ResourceFrame>> {
    if node >= context.end || node + 16 >= context.end {
        return Ok(None);
    }
    context.consumed = context.consumed.wrapping_add(16);
    if context.consumed > context.budget {
        return Ok(None);
    }
    if rd32(buf, node + 4)? != context.time {
        wr32(buf, node + 4, context.time)?;
    }
    let entries = i32::from(rd16(buf, node + 12)?) + i32::from(rd16(buf, node + 14)?);
    Ok(Some(ResourceFrame {
        cursor: node + 16,
        remaining: entries,
        after_child: false,
    }))
}

/// `TransformOldFile_PE_ResourcesOldCompatible`, with an explicit stack instead of recursion.
fn resources(buf: &mut [u8], nt: usize, time: u32, rift: &Rift) -> Result<()> {
    let Some((directory_offset, directory_size)) = directory_mapped(buf, nt, 2)? else {
        return Ok(());
    };
    if directory_size < 0x10 {
        return Ok(());
    }
    let old_rva = directory(buf, nt, 2)?.map_or(0, |(rva, _)| rva);
    let mut context = ResourceContext {
        rift,
        directory: directory_offset,
        end: (directory_offset + directory_size as usize).min(buf.len()),
        budget: directory_size,
        consumed: 0,
        time,
        old_rva,
        new_rva: new_rva(rift, old_rva),
    };
    let mut stack = Vec::new();
    if let Some(frame) = enter_resource_directory(buf, &mut context, directory_offset)? {
        stack.push(frame);
    }
    while let Some(frame) = stack.last_mut() {
        if !frame.after_child {
            if frame.remaining == 0 || frame.cursor + 8 >= context.end {
                stack.pop();
                continue;
            }
            let offset_field = rd32(buf, frame.cursor + 4)?;
            if (offset_field as i32) >= 0 {
                let leaf = context.directory + offset_field as usize;
                if leaf > context.directory && leaf + 16 < context.end {
                    context.consumed = context.consumed.wrapping_add(rd32(buf, leaf + 4)?);
                    if context.consumed > context.budget {
                        stack.pop();
                        continue;
                    }
                    let rva = rd32(buf, leaf)?;
                    wr32(buf, leaf, new_rva(context.rift, rva))?;
                }
            } else {
                frame.after_child = true;
                let node = context.directory + (offset_field & 0x7fff_ffff) as usize;
                if let Some(child) = enter_resource_directory(buf, &mut context, node)? {
                    stack.push(child);
                    continue;
                }
            }
        }
        let frame = stack.last_mut().ok_or(BAD_PE)?;
        frame.after_child = false;
        let cursor = frame.cursor;
        let relocate = |field: u32| -> u32 {
            new_rva(
                context.rift,
                (field & 0x7fff_ffff).wrapping_add(context.old_rva),
            )
            .wrapping_sub(context.new_rva)
        };
        let offset_field = rd32(buf, cursor + 4)?;
        let updated = relocate(offset_field);
        wr32(
            buf,
            cursor + 4,
            offset_field ^ ((updated ^ offset_field) & 0x7fff_ffff),
        )?;
        let name_field = rd32(buf, cursor)?;
        if (name_field as i32) < 0 {
            let updated = relocate(name_field);
            wr32(
                buf,
                cursor,
                name_field ^ ((updated ^ name_field) & 0x7fff_ffff),
            )?;
        }
        context.consumed = context.consumed.wrapping_add(8);
        if context.consumed > context.budget {
            stack.pop();
            continue;
        }
        frame.cursor += 8;
        frame.remaining -= 1;
    }
    Ok(())
}

/// `TransformOldFile_PE_Resources` with `TransformResourceRecursive` (current order), with an
/// explicit stack instead of recursion. Differences from the old-compatible walker: leaf data
/// entries do not add their size to the byte budget, a bad leaf or subdirectory offset sets an
/// error flag and the entry fields are still updated, and a child that exhausts the budget ends
/// every enclosing directory.
fn resources_current(buf: &mut [u8], nt: usize, time: u32, rift: &Rift) -> Result<()> {
    let Some((directory_offset, directory_size)) = directory_mapped(buf, nt, 2)? else {
        return Ok(());
    };
    if directory_size < 0x10 {
        return Ok(());
    }
    let old_rva = directory(buf, nt, 2)?.map_or(0, |(rva, _)| rva);
    let mut context = ResourceContext {
        rift,
        directory: directory_offset,
        end: (directory_offset + directory_size as usize).min(buf.len()),
        budget: directory_size,
        consumed: 0,
        time,
        old_rva,
        new_rva: new_rva(rift, old_rva),
    };
    // Enter a directory: None means the function returned immediately (error flag only).
    fn enter(
        buf: &mut [u8],
        context: &mut ResourceContext<'_>,
        node: usize,
    ) -> Result<Option<ResourceFrame>> {
        if node < context.directory || node + 16 > context.end {
            return Ok(None);
        }
        context.consumed = context.consumed.wrapping_add(16);
        if context.consumed > context.budget {
            return Ok(None);
        }
        if rd32(buf, node + 4)? != context.time {
            wr32(buf, node + 4, context.time)?;
        }
        let entries = i32::from(rd16(buf, node + 12)?) + i32::from(rd16(buf, node + 14)?);
        Ok(Some(ResourceFrame {
            cursor: node + 16,
            remaining: entries,
            after_child: false,
        }))
    }
    let mut stack = Vec::new();
    if let Some(frame) = enter(buf, &mut context, directory_offset)? {
        stack.push(frame);
    }
    while let Some(frame) = stack.last_mut() {
        if !frame.after_child {
            if frame.remaining == 0 {
                stack.pop();
                continue;
            }
            if frame.cursor + 8 > context.end {
                stack.pop();
                continue;
            }
            context.consumed = context.consumed.wrapping_add(8);
            if context.consumed > context.budget {
                stack.pop();
                continue;
            }
            let offset_field = rd32(buf, frame.cursor + 4)?;
            if (offset_field as i32) >= 0 {
                let leaf = context.directory + offset_field as usize;
                if leaf >= context.directory && leaf + 16 <= context.end {
                    let rva = rd32(buf, leaf)?;
                    let updated = new_rva(context.rift, rva);
                    if updated != rva {
                        wr32(buf, leaf, updated)?;
                    }
                }
            } else if context.budget >= 0x10 && (offset_field & 0x7fff_ffff) <= context.budget - 16
            {
                frame.after_child = true;
                let node = context.directory + (offset_field & 0x7fff_ffff) as usize;
                if let Some(child) = enter(buf, &mut context, node)? {
                    stack.push(child);
                    continue;
                }
                // The child returned at once: the parent's budget check runs on the next pass.
                continue;
            }
        } else if context.consumed > context.budget {
            // A child finished and left the budget exhausted: this directory returns too.
            stack.pop();
            continue;
        }
        let frame = stack.last_mut().ok_or(BAD_PE)?;
        frame.after_child = false;
        let cursor = frame.cursor;
        let relocate = |field: u32| -> u32 {
            new_rva(
                context.rift,
                (field & 0x7fff_ffff).wrapping_add(context.old_rva),
            )
            .wrapping_sub(context.new_rva)
        };
        let offset_field = rd32(buf, cursor + 4)?;
        let updated = relocate(offset_field);
        wr32(
            buf,
            cursor + 4,
            offset_field ^ ((updated ^ offset_field) & 0x7fff_ffff),
        )?;
        let name_field = rd32(buf, cursor)?;
        if (name_field as i32) < 0 {
            let updated = relocate(name_field);
            wr32(
                buf,
                cursor,
                name_field ^ ((updated ^ name_field) & 0x7fff_ffff),
            )?;
        }
        frame.cursor += 8;
        frame.remaining -= 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 16) as u32
        }

        fn below(&mut self, bound: u32) -> u32 {
            self.next() % bound.max(1)
        }
    }

    /// A PE32 skeleton with three sections whose directories point at random places.
    fn skeleton(random: &mut Random) -> Vec<u8> {
        let size = 0x2000 + random.below(0x2000) as usize;
        let mut image: Vec<u8> = (0..size).map(|_| random.next() as u8).collect();
        image[..2].copy_from_slice(b"MZ");
        let nt = 0x80usize;
        image[60..64].copy_from_slice(&(nt as u32).to_le_bytes());
        image[nt..nt + 4].copy_from_slice(b"PE\0\0");
        image[nt + 4..nt + 6].copy_from_slice(&0x14cu16.to_le_bytes());
        image[nt + 6..nt + 8].copy_from_slice(&3u16.to_le_bytes());
        image[nt + 20..nt + 22].copy_from_slice(&224u16.to_le_bytes());
        image[nt + 24..nt + 26].copy_from_slice(&0x10bu16.to_le_bytes());
        image[nt + 52..nt + 56].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        image[nt + 80..nt + 84].copy_from_slice(&0x6000u32.to_le_bytes());
        image[nt + 84..nt + 88].copy_from_slice(&0x400u32.to_le_bytes());
        image[nt + 116..nt + 120].copy_from_slice(&16u32.to_le_bytes());
        for index in 0..16 {
            let rva = random.below(0x6000);
            let length = random.below(0x600);
            let entry = nt + 120 + 8 * index;
            image[entry..entry + 4].copy_from_slice(&rva.to_le_bytes());
            image[entry + 4..entry + 8].copy_from_slice(&length.to_le_bytes());
        }
        let first = nt + 24 + 224;
        for (index, name) in [&b".text\0\0\0"[..], b".idata\0\0", b".reloc\0\0"]
            .into_iter()
            .enumerate()
        {
            let header = first + 40 * index;
            image[header..header + 8].copy_from_slice(name);
            let fields = [
                0x1000 + random.below(0x400),
                0x1000 * (index as u32 + 1),
                0x400 + random.below(0x1000),
                0x400 + 0x200 * index as u32,
            ];
            for (slot, value) in fields.iter().enumerate() {
                image[header + 8 + 4 * slot..header + 12 + 4 * slot]
                    .copy_from_slice(&value.to_le_bytes());
            }
            let flags = if index == 0 {
                0x6000_0020u32
            } else {
                0x4000_0040
            };
            image[header + 36..header + 40].copy_from_slice(&flags.to_le_bytes());
        }
        image
    }

    #[test]
    fn hostile_pe32_images_never_panic_in_normalize_or_transform() {
        let mut random = Random(0x9e37_79b9_7f4a_7c15);
        for round in 0..3000 {
            let mut image = skeleton(&mut random);
            let rift: Vec<(u32, u32)> = (0..random.below(6))
                .scan((0u32, 0u32), |state, _| {
                    state.0 = state.0.wrapping_add(random.below(0x2000));
                    state.1 = state.1.wrapping_add(random.below(0x200));
                    Some(*state)
                })
                .collect();
            let flags = random.next() & 0x0007_0000;
            let _ = normalize(&mut image, flags, 0x2000_0000, 0x1234_5678);
            let options = random.next() & 0x3f;
            let _ = transform(&mut image, options, round, &rift);
        }
    }

    #[test]
    fn new_rva_follows_the_last_entry_at_or_below_the_address() {
        let rift = [(0x1000, 0x1010), (0x2000, 0x2040)];
        assert_eq!(new_rva(&rift, 0x0800), 0x0800);
        assert_eq!(new_rva(&rift, 0x1000), 0x1010);
        assert_eq!(new_rva(&rift, 0x1fff), 0x200f);
        assert_eq!(new_rva(&rift, 0x2000), 0x2040);
        assert_eq!(new_rva(&rift, 0x9000), 0x9040);
        assert_eq!(new_rva(&[], 5), 5);
    }

    #[test]
    fn checksum_matches_the_standard_pe_algorithm() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        // words 0x0201 + 0x0403 = 0x0604, odd byte 5 -> 0x0609, plus the length.
        assert_eq!(pe_checksum(&data), 0x0609 + 5);
    }

    #[test]
    fn qsort_orders_by_rva() {
        let mut random = Random(7);
        for length in [2usize, 3, 10, 200] {
            let mut entries: Vec<RelocEntry> = (0..length)
                .map(|_| RelocEntry {
                    rva: random.below(50),
                    kind: 3,
                })
                .collect();
            reloc_qsort(&mut entries);
            assert!(entries.windows(2).all(|pair| pair[0].rva <= pair[1].rva));
        }
    }
}
