//! Independent bounded managed-metadata map construction and serialization.
use super::{
    cli::{CliMaps, MetadataInfo},
    encode::Writer,
    rift::RiftTable,
    rift_encode,
};
use crate::{Error, Limits, Result};
use std::collections::HashMap;

pub(super) fn write_metadata(info: &MetadataInfo, writer: &mut Writer) -> Result<()> {
    writer.bits(u64::from(info.metadata_size != 0), 1)?;
    if info.metadata_size == 0 {
        return Ok(());
    }
    for field in [
        info.image_offset,
        info.metadata_size,
        info.base_rva as usize,
        info.stream_count,
        info.stream_headers,
        info.strings_offset,
        info.strings_size,
        info.user_strings_offset,
        info.user_strings_size,
        info.blob_offset,
        info.blob_size,
        info.guid_offset,
        info.guid_size,
        info.tables_offset,
        info.tables_size,
    ] {
        writer.bits(
            u32::try_from(field).map_err(|_| Error::Limit("CLI creation metadata field"))? as u64,
            32,
        )?;
    }
    for width in info.heap_widths {
        writer.bits(u64::from(width), 1)?;
    }
    writer.bits(info.valid_mask & 0xffff_ffff, 32)?;
    writer.bits(info.valid_mask >> 32, 32)?;
    for table in 0..64 {
        if info.valid_mask & (1 << table) != 0 {
            writer.bits(u64::from(info.rows[table]), 32)?;
        }
    }
    Ok(())
}

pub(super) fn write_maps(maps: &CliMaps, writer: &mut Writer, limits: &Limits) -> Result<()> {
    writer.bits(1, 1)?;
    for _ in 0..4 {
        rift_encode::write_format(writer)?;
    }
    let mut count = 0usize;
    for map in [&maps.strings, &maps.user_strings, &maps.blob, &maps.guid]
        .into_iter()
        .chain(maps.tables.iter())
    {
        count = count
            .checked_add(map.entries().len())
            .ok_or(Error::Limit("CLI creation maps"))?;
        if count > limits.max_parameter_bytes / 16 {
            return Err(Error::Limit("CLI creation maps"));
        }
        rift_encode::write_with_formats(map, writer, limits)?;
    }
    Ok(())
}

fn slice(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or(Error::Invalid("CLI creation range"))?,
        )
        .ok_or(Error::Invalid("CLI creation range"))
}
fn compressed(bytes: &[u8]) -> Result<(usize, usize)> {
    let first = *bytes
        .first()
        .ok_or(Error::Invalid("CLI creation heap length"))?;
    let count = if first < 128 {
        1
    } else if first < 192 {
        2
    } else if first < 224 {
        4
    } else {
        return Err(Error::Invalid("CLI creation heap prefix"));
    };
    let bytes = slice(bytes, 0, count)?;
    let mut value = usize::from(
        first
            & match count {
                1 => 127,
                2 => 63,
                _ => 31,
            },
    );
    for &byte in &bytes[1..] {
        value = value * 256 + usize::from(byte);
    }
    Ok((value, count))
}
fn records<'a>(bytes: &'a [u8], kind: usize, limits: &Limits) -> Result<Vec<(usize, &'a [u8])>> {
    let mut result = Vec::new();
    let mut position = if kind == 3 {
        0
    } else {
        usize::from(!bytes.is_empty())
    };
    while position < bytes.len() {
        let (start, end, key) = match kind {
            0 => {
                let size = bytes[position..]
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(Error::Invalid("CLI creation string terminator"))?;
                (
                    position,
                    position + size + 1,
                    &bytes[position..position + size],
                )
            }
            3 => (
                position / 16 + 1,
                position + 16,
                slice(bytes, position, 16)?,
            ),
            _ => {
                let (size, prefix) = compressed(&bytes[position..])?;
                let key = slice(bytes, position + prefix, size)?;
                (position, position + prefix + size, key)
            }
        };
        if result.len() >= limits.max_parameter_bytes / 128 {
            return Err(Error::Limit("CLI creation heap records"));
        }
        if result.len() == result.capacity() {
            let maximum = limits.max_parameter_bytes / 128;
            let next = result.capacity().saturating_mul(2).max(4).min(maximum);
            result
                .try_reserve_exact(next - result.len())
                .map_err(|_| Error::Allocation)?;
        }
        result.push((start, key));
        position = end;
    }
    Ok(result)
}

fn matching_map<K: std::hash::Hash + Eq>(
    source: impl IntoIterator<Item = (usize, K)>,
    target: impl IntoIterator<Item = (usize, K)>,
    end: usize,
    limits: &Limits,
) -> Result<RiftTable> {
    let mut candidates: HashMap<K, Option<usize>> = HashMap::new();
    for (offset, key) in target {
        if candidates.len() >= limits.max_parameter_bytes / 128 {
            return Err(Error::Limit("CLI creation matching workspace"));
        }
        candidates.try_reserve(1).map_err(|_| Error::Allocation)?;
        candidates
            .entry(key)
            .and_modify(|value| *value = None)
            .or_insert(Some(offset));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(1)
        .map_err(|_| Error::Allocation)?;
    entries.push((0, 0));
    let mut changed = false;
    for (offset, key) in source {
        let target = candidates.get(&key).copied().flatten().unwrap_or(offset);
        changed |= target != offset;
        if entries.len() >= limits.max_parameter_bytes / 32 {
            return Err(Error::Limit("CLI creation map entries"));
        }
        if entries.len() == entries.capacity() {
            let maximum = limits.max_parameter_bytes / 32;
            let next = entries.capacity().saturating_mul(2).max(4).min(maximum);
            entries
                .try_reserve_exact(next - entries.len())
                .map_err(|_| Error::Allocation)?;
        }
        entries.push((offset as i64, target as i64));
    }
    if !changed {
        return Ok(RiftTable::default());
    }
    entries
        .try_reserve_exact(1)
        .map_err(|_| Error::Allocation)?;
    entries.push((end as i64, end as i64));
    RiftTable::from_entries(entries, limits)
}

fn column(
    bytes: &[u8],
    info: &MetadataInfo,
    table: usize,
    row: usize,
    column: usize,
) -> Result<usize> {
    let offset = info.table_offsets[table]
        + row * info.row_sizes[table]
        + info.column_offsets[table][column];
    let data = slice(bytes, offset, info.column_widths[table][column])?;
    Ok(data.iter().enumerate().fold(0, |value, (shift, byte)| {
        value | (usize::from(*byte) << (shift * 8))
    }))
}
fn name<'a>(
    bytes: &'a [u8],
    info: &MetadataInfo,
    offset: usize,
    work: &mut usize,
) -> Result<&'a [u8]> {
    let strings = slice(bytes, info.strings_offset, info.strings_size)?;
    let text = strings
        .get(offset..)
        .ok_or(Error::Invalid("CLI creation string index"))?;
    let length = text
        .iter()
        .take(work.saturating_add(1))
        .position(|&byte| byte == 0)
        .ok_or(if text.len() > *work {
            Error::Limit("CLI creation name work")
        } else {
            Error::Invalid("CLI creation string terminator")
        })?;
    *work = work
        .checked_sub(length)
        .ok_or(Error::Limit("CLI creation name work"))?;
    Ok(&text[..length])
}
type RowKey<'a> = (usize, (&'a [u8], &'a [u8]));

fn row_keys<'a>(
    bytes: &'a [u8],
    info: &MetadataInfo,
    table: usize,
    limits: &Limits,
) -> Result<Vec<RowKey<'a>>> {
    let count = info.rows[table] as usize;
    if count > limits.max_parameter_bytes / 128 {
        return Err(Error::Limit("CLI creation table rows"));
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    let name_column = match table {
        1 | 2 | 4 | 10 => 1,
        6 => 3,
        _ => return Err(Error::Invalid("CLI creation name table")),
    };
    let mut work = bytes.len().saturating_mul(4);
    for row in 0..count {
        let primary = name(
            bytes,
            info,
            column(bytes, info, table, row, name_column)?,
            &mut work,
        )?;
        let secondary = if table == 1 || table == 2 {
            name(bytes, info, column(bytes, info, table, row, 2)?, &mut work)?
        } else if table == 10 {
            let index = column(bytes, info, table, row, 2)?;
            let heap = slice(bytes, info.blob_offset, info.blob_size)?;
            let (size, prefix) = compressed(
                heap.get(index..)
                    .ok_or(Error::Invalid("CLI creation blob index"))?,
            )?;
            work = work
                .checked_sub(size)
                .ok_or(Error::Limit("CLI creation signature work"))?;
            slice(heap, index + prefix, size)?
        } else {
            &[]
        };
        result.push((row + 1, (primary, secondary)));
    }
    Ok(result)
}

pub(super) fn maps(
    source: &[u8],
    target: &[u8],
    source_info: &MetadataInfo,
    target_info: &MetadataInfo,
    limits: &Limits,
) -> Result<CliMaps> {
    let mut heaps = [
        RiftTable::default(),
        RiftTable::default(),
        RiftTable::default(),
        RiftTable::default(),
    ];
    for (kind, ((source_offset, source_size), (target_offset, target_size))) in [
        (
            (source_info.strings_offset, source_info.strings_size),
            (target_info.strings_offset, target_info.strings_size),
        ),
        (
            (
                source_info.user_strings_offset,
                source_info.user_strings_size,
            ),
            (
                target_info.user_strings_offset,
                target_info.user_strings_size,
            ),
        ),
        (
            (source_info.blob_offset, source_info.blob_size),
            (target_info.blob_offset, target_info.blob_size),
        ),
        (
            (source_info.guid_offset, source_info.guid_size),
            (target_info.guid_offset, target_info.guid_size),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let source_records = records(slice(source, source_offset, source_size)?, kind, limits)?;
        let target_records = records(slice(target, target_offset, target_size)?, kind, limits)?;
        heaps[kind] = matching_map(
            source_records,
            target_records,
            if kind == 3 {
                source_size / 16 + 1
            } else {
                source_size
            },
            limits,
        )?;
    }
    let mut tables = std::array::from_fn(|_| RiftTable::default());
    for table in [1, 2, 4, 6, 10] {
        tables[table] = matching_map(
            row_keys(source, source_info, table, limits)?,
            row_keys(target, target_info, table, limits)?,
            source_info.rows[table] as usize + 1,
            limits,
        )?;
    }
    let [strings, user_strings, blob, guid] = heaps;
    let maps = CliMaps {
        strings,
        user_strings,
        blob,
        guid,
        tables,
    };
    let total = [&maps.strings, &maps.user_strings, &maps.blob, &maps.guid]
        .into_iter()
        .chain(maps.tables.iter())
        .try_fold(0usize, |sum, map| {
            sum.checked_add(map.entries().len())
                .ok_or(Error::Limit("CLI creation maps"))
        })?;
    if total > limits.max_parameter_bytes / 16 {
        return Err(Error::Limit("CLI creation maps"));
    }
    Ok(maps)
}

#[cfg(test)]
mod tests {
    use super::super::{Bits, pe::PeLayout};
    use super::*;
    const SOURCE: &[u8] = include_bytes!("../../docs/fixtures/pa30-cli-native/source.dll");
    const TARGET: &[u8] = include_bytes!("../../docs/fixtures/pa30-cli-native/target.dll");
    #[test]
    fn metadata_wire_preserves_target_layout_and_map_pairs() {
        let limits = Limits::default();
        let source =
            MetadataInfo::parse(SOURCE, &PeLayout::parse(SOURCE).unwrap(), &limits).unwrap();
        let target =
            MetadataInfo::parse(TARGET, &PeLayout::parse(TARGET).unwrap(), &limits).unwrap();
        let maps = maps(SOURCE, TARGET, &source, &target, &limits).unwrap();
        assert!(
            maps.tables[2]
                .entries()
                .iter()
                .any(|(left, right)| left != right)
        );
        assert!(
            maps.tables[6]
                .entries()
                .iter()
                .any(|(left, right)| left != right)
        );
        let mut writer = Writer::new(limits.max_parameter_bytes).unwrap();
        write_metadata(&target, &mut writer).unwrap();
        write_maps(&maps, &mut writer, &limits).unwrap();
        let bytes = writer.finish();
        let mut reader = Bits::new(&bytes).unwrap();
        let decoded_target = MetadataInfo::read(&mut reader, &limits).unwrap();
        let decoded_maps = CliMaps::read(&mut reader, &limits).unwrap();
        reader.finish().unwrap();
        assert_eq!(decoded_target.image_offset, target.image_offset);
        assert_eq!(decoded_target.heap_widths, target.heap_widths);
        assert_eq!(decoded_target.table_offsets, target.table_offsets);
        assert_eq!(decoded_target.row_sizes, target.row_sizes);
        for (a, b) in [&maps.strings, &maps.user_strings, &maps.blob, &maps.guid]
            .into_iter()
            .chain(maps.tables.iter())
            .zip(
                [
                    &decoded_maps.strings,
                    &decoded_maps.user_strings,
                    &decoded_maps.blob,
                    &decoded_maps.guid,
                ]
                .into_iter()
                .chain(decoded_maps.tables.iter()),
            )
        {
            assert_eq!(a.entries(), b.entries());
        }
    }
    #[test]
    fn ambiguous_names_stay_identity_and_exact_matches_move() {
        let limits = Limits::default();
        let map = matching_map(
            vec![
                (1, b"A".as_slice()),
                (2, b"B".as_slice()),
                (3, b"C".as_slice()),
            ],
            vec![
                (7, b"A".as_slice()),
                (8, b"A".as_slice()),
                (10, b"B".as_slice()),
            ],
            4,
            &limits,
        )
        .unwrap();
        assert_eq!(map.map(0), 0);
        assert_eq!(map.map(1), 1);
        assert_eq!(map.map(2), 10);
        assert_eq!(map.map(3), 3);
        assert_eq!(map.map(4), 4);
    }
    #[test]
    fn malformed_heaps_and_record_limits_fail_closed() {
        let limits = Limits::default();
        assert!(records(b"\0unterminated", 0, &limits).is_err());
        assert!(records(b"\0\xff", 1, &limits).is_err());
        assert!(records(b"\0\x08a", 2, &limits).is_err());
        assert!(records(b"short", 3, &limits).is_err());
        assert!(
            records(
                b"\0a\0",
                0,
                &Limits {
                    max_parameter_bytes: 0,
                    ..limits
                }
            )
            .is_err()
        );
    }
    #[test]
    fn named_row_scanning_is_bounded_before_terminator_search() {
        let info = MetadataInfo {
            strings_size: 6,
            ..MetadataInfo::default()
        };
        let mut work = 2;
        assert!(matches!(
            name(b"abcde\0", &info, 0, &mut work),
            Err(Error::Limit(_))
        ));
        let mut work = 5;
        assert_eq!(name(b"abcde\0", &info, 0, &mut work).unwrap(), b"abcde");
        assert_eq!(work, 0);
    }
    #[test]
    fn normalized_managed_dictionaries_match_independent_native_probes() {
        for (source, target, expected) in [
            (include_bytes!("../../docs/fixtures/pa30-cli-native/signatures/source.dll").as_slice(),
             include_bytes!("../../docs/fixtures/pa30-cli-native/signatures/target.dll").as_slice(),
             include_bytes!("../../docs/fixtures/pa30-created-cli-native/diagnostic-nohash/signatures-all-nohash.output").as_slice()),
            (include_bytes!("../../docs/fixtures/pa30-cli-native/attributes/source.dll").as_slice(),
             include_bytes!("../../docs/fixtures/pa30-cli-native/attributes/target.dll").as_slice(),
             include_bytes!("../../docs/fixtures/pa30-created-cli-native/diagnostic-nohash/attributes-all-nohash.output").as_slice()),
        ] {
            let limits = Limits::default();
            let sl = PeLayout::parse(source).unwrap(); let tl = PeLayout::parse(target).unwrap();
            let sm = MetadataInfo::parse(source, &sl, &limits).unwrap(); let tm = MetadataInfo::parse(target, &tl, &limits).unwrap();
            let maps = maps(source, target, &sm, &tm, &limits).unwrap();
            let ti = tl.target_info(target, &limits).unwrap(); let used = sl.section_map(&tl, source, target, &limits).unwrap();
            let normalized = super::super::pe::preprocess_cli(source, 0x600000, &ti, &used, &sm, &tm, &maps, &limits).unwrap();
            assert_eq!(normalized, expected);
        }
    }
}
