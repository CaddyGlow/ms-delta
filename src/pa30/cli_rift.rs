//! CLI heap/row mappings converted to target-offset compression dictionaries.
//! Derived independently from the pinned native legacy and CLI4 graphs. Their
//! heap and row mapping algorithms agree; metadata supplies each graph's schema.

use super::cli::{CliMaps, MetadataInfo};
use super::rift::RiftTable;
use crate::{Error, Limits, Result};

pub(super) fn compression(
    source: &MetadataInfo,
    target: &MetadataInfo,
    maps: &CliMaps,
    normalized: &[u8],
    limits: &Limits,
) -> Result<RiftTable> {
    if source.metadata_size == 0 || target.metadata_size == 0 {
        return Ok(RiftTable::default());
    }
    let mut pairs = Pairs {
        entries: Vec::new(),
        limits,
    };
    for (from, to, map) in [
        (source.strings_offset, target.strings_offset, &maps.strings),
        (
            source.user_strings_offset,
            target.user_strings_offset,
            &maps.user_strings,
        ),
        (source.blob_offset, target.blob_offset, &maps.blob),
    ] {
        pairs.scaled(from, to, 1, 0, map)?;
    }
    pairs.scaled(source.guid_offset, target.guid_offset, 16, 1, &maps.guid)?;
    // The native widening path maps inserted zero words to this source sentinel.
    let sentinel = normalized
        .windows(2)
        .position(|word| word == [0, 0])
        .unwrap_or(normalized.len());
    for table in 0..64 {
        if source.rows[table] == 0 || target.rows[table] == 0 {
            continue;
        }
        let from = source.table_offsets[table];
        let to = target.table_offsets[table];
        let old_size = source.row_sizes[table];
        let new_size = target.row_sizes[table];
        let old_widths = &source.column_widths[table];
        let new_widths = &target.column_widths[table];
        let map = &maps.tables[table];
        if old_size == new_size && old_widths == new_widths {
            pairs.scaled(from, to, old_size, 1, map)?;
            continue;
        }
        let count = source.rows[table] as usize;
        // Native per-row traversal excludes the final row, just like CLI IL.
        for row in 1..count {
            let mapped = map.map(row as i64).wrapping_sub(1);
            let dst = (to as i64).wrapping_add((new_size as i64).wrapping_mul(mapped));
            let src = (from as i64).wrapping_add((old_size as i64).wrapping_mul(row as i64 - 1));
            pairs.push(dst, src)?;
        }
        let columns = old_widths.iter().take_while(|&&width| width != 0).count();
        for column in 0..columns {
            let old = old_widths[column];
            let new = new_widths[column];
            if old == new {
                continue;
            }
            if !matches!((old, new), (2, 4) | (4, 2)) {
                return Err(Error::Invalid("CLI column width transition"));
            }
            for row in 1..count {
                let mapped = map.map(row as i64).wrapping_sub(1);
                let dst = (to as i64)
                    .wrapping_add((new_size as i64).wrapping_mul(mapped))
                    .wrapping_add(target.column_offsets[table][column] as i64);
                let src = (from as i64)
                    .wrapping_add((old_size as i64).wrapping_mul(row as i64 - 1))
                    .wrapping_add(source.column_offsets[table][column] as i64);
                if old == 4 {
                    if column + 1 < columns {
                        pairs.push(dst.wrapping_add(2), src.wrapping_add(4))?;
                    }
                } else {
                    pairs.push(dst.wrapping_add(2), sentinel as i64)?;
                    if column + 1 < columns {
                        pairs.push(dst.wrapping_add(4), src.wrapping_add(2))?;
                    }
                }
            }
        }
    }
    RiftTable::from_entries(pairs.entries, limits)
}

struct Pairs<'a> {
    entries: Vec<(i64, i64)>,
    limits: &'a Limits,
}
impl Pairs<'_> {
    fn push(&mut self, left: i64, right: i64) -> Result<()> {
        if self.entries.len() >= self.limits.max_parameter_bytes / 16 {
            return Err(Error::Limit("CLI compression map workspace"));
        }
        self.entries.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.entries.push((left, right));
        Ok(())
    }
    fn scaled(
        &mut self,
        from: usize,
        to: usize,
        scale: usize,
        origin: i64,
        map: &RiftTable,
    ) -> Result<()> {
        let entries = map.entries();
        if entries.is_empty() {
            return self.push(to as i64, from as i64);
        }
        let first = entries.partition_point(|&(left, _)| left <= origin);
        let index = if first == 0 {
            entries.len() - 1
        } else {
            first - 1
        };
        let (left, right) = entries[index];
        self.push(
            (to as i64).wrapping_add((scale as i64).wrapping_mul(right.wrapping_sub(left))),
            from as i64,
        )?;
        for &(left, right) in &entries[first..] {
            if left > i64::from(u32::MAX) {
                break;
            }
            self.push(
                (to as i64).wrapping_add((scale as i64).wrapping_mul(right.wrapping_sub(origin))),
                (from as i64).wrapping_add((scale as i64).wrapping_mul(left.wrapping_sub(origin))),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_maps_reverse_offsets_and_preserve_circular_prefix_translation() {
        let limits = Limits::default();
        let map = RiftTable::from_entries(vec![(2, 8), (7, 10)], &limits).unwrap();
        let mut pairs = Pairs {
            entries: Vec::new(),
            limits: &limits,
        };
        pairs.scaled(100, 200, 1, 0, &map).unwrap();
        assert_eq!(pairs.entries, [(203, 100), (208, 102), (210, 107)]);
        let map = RiftTable::from_entries(vec![(1, 3), (4, 1)], &limits).unwrap();
        let mut pairs = Pairs {
            entries: Vec::new(),
            limits: &limits,
        };
        pairs.scaled(100, 200, 16, 1, &map).unwrap();
        assert_eq!(pairs.entries, [(232, 100), (200, 148)]);
    }

    #[test]
    fn signed_row_mapping_wraps_geometry_without_overflow_panics() {
        let limits = Limits::default();
        let mut maps = CliMaps {
            strings: RiftTable::default(),
            user_strings: RiftTable::default(),
            blob: RiftTable::default(),
            guid: RiftTable::default(),
            tables: std::array::from_fn(|_| RiftTable::default()),
        };
        let mapped = i64::MAX / 4;
        maps.tables[1] = RiftTable::from_entries(vec![(1, mapped + 1)], &limits).unwrap();
        let mut source = MetadataInfo {
            metadata_size: 100,
            ..MetadataInfo::default()
        };
        source.rows[1] = 2;
        source.table_offsets[1] = 20;
        source.row_sizes[1] = 2;
        source.column_widths[1][0] = 2;
        let mut target = MetadataInfo {
            metadata_size: 100,
            ..MetadataInfo::default()
        };
        target.rows[1] = 2;
        target.table_offsets[1] = 40;
        target.row_sizes[1] = 4;
        target.column_widths[1][0] = 4;
        let result = compression(&source, &target, &maps, &[0, 0], &limits).unwrap();
        let left = 40i64.wrapping_add(4i64.wrapping_mul(mapped));
        assert_eq!(result.map(left), 20);
        assert_eq!(result.map(left.wrapping_add(2)), 0);
    }

    #[test]
    fn final_column_narrowing_preserves_native_row_map_without_resume_entry() {
        let limits = Limits::default();
        let maps = CliMaps {
            strings: RiftTable::default(),
            user_strings: RiftTable::default(),
            blob: RiftTable::default(),
            guid: RiftTable::default(),
            tables: std::array::from_fn(|_| RiftTable::default()),
        };
        let mut source = MetadataInfo {
            metadata_size: 100,
            ..MetadataInfo::default()
        };
        source.rows[1] = 3;
        source.table_offsets[1] = 20;
        source.row_sizes[1] = 4;
        source.column_widths[1][0] = 4;
        let mut target = MetadataInfo {
            metadata_size: 100,
            ..MetadataInfo::default()
        };
        target.rows[1] = 3;
        target.table_offsets[1] = 40;
        target.row_sizes[1] = 2;
        target.column_widths[1][0] = 2;
        let result = compression(&source, &target, &maps, &[0, 0], &limits).unwrap();
        assert_eq!(result.map(40), 20);
        assert_eq!(result.map(41), 21);
        assert_eq!(result.map(42), 24);
        assert_eq!(result.map(43), 25);
        assert_eq!(result.map(44), 26); // final row has no separately added entry
    }

    #[test]
    fn column_widening_maps_added_zero_word_and_resume_to_source_columns() {
        let limits = Limits::default();
        let maps = CliMaps {
            strings: RiftTable::default(),
            user_strings: RiftTable::default(),
            blob: RiftTable::default(),
            guid: RiftTable::default(),
            tables: std::array::from_fn(|_| RiftTable::default()),
        };
        let mut source = MetadataInfo {
            metadata_size: 100,
            ..MetadataInfo::default()
        };
        source.rows[1] = 3;
        source.table_offsets[1] = 20;
        source.row_sizes[1] = 4;
        source.column_widths[1][..2].copy_from_slice(&[2, 2]);
        source.column_offsets[1][1] = 2;
        let mut target = MetadataInfo {
            metadata_size: 100,
            ..MetadataInfo::default()
        };
        target.rows[1] = 3;
        target.table_offsets[1] = 40;
        target.row_sizes[1] = 6;
        target.column_widths[1][..2].copy_from_slice(&[4, 2]);
        target.column_offsets[1][1] = 4;
        let normalized = [7, 0, 0, 9];
        let result = compression(&source, &target, &maps, &normalized, &limits).unwrap();
        assert_eq!(result.map(40), 20);
        assert_eq!(result.map(42), 1);
        assert_eq!(result.map(44), 22);
        assert_eq!(result.map(46), 24);
        assert_eq!(result.map(48), 1);
        assert_eq!(result.map(50), 26);
        let small = Limits {
            max_parameter_bytes: 16,
            ..limits
        };
        assert!(matches!(
            compression(&source, &target, &maps, &normalized, &small),
            Err(Error::Limit(_))
        ));
    }
}
