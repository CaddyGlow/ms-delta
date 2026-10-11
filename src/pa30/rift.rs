//! PA30 piecewise address maps and their independently decoded wire representation.
//!
//! Derived from observed behavior of Microsoft msdelta 19041 and its public PDB.
//! A pair `(left, right)` sets the translation `right - left` starting at `left`.
//! Before the first breakpoint the last translation applies, matching the native
//! circular signed-address domain. Empty tables implement identity.

use super::{Bits, Huffman};
use crate::{Error, Limits, Result};

#[derive(Clone, Debug, Default)]
pub(super) struct RiftTable {
    entries: Vec<(i64, i64)>,
}

impl RiftTable {
    pub(super) fn read(bits: &mut Bits<'_>, limits: &Limits) -> Result<Self> {
        if bits.read(1)? == 0 {
            return Ok(Self::default());
        }
        let left_format = IntFormat::read(bits)?;
        let offset_format = IntFormat::read(bits)?;
        Self::read_with_formats(bits, &left_format, &offset_format, limits)
    }

    pub(super) fn read_with_formats(
        bits: &mut Bits<'_>,
        left_format: &IntFormat,
        offset_format: &IntFormat,
        limits: &Limits,
    ) -> Result<Self> {
        let count =
            usize::try_from(bits.number(16)?).map_err(|_| Error::Limit("PA30 rift entry count"))?;
        check_count(count, limits)?;
        if count > (bits.end - bits.position) / 2 {
            return Err(Error::Invalid("PA30 truncated rift entries"));
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        let mut left = 0i64;
        let mut offset = 0i64;
        for _ in 0..count {
            left = left
                .checked_add(left_format.number(bits)?)
                .ok_or(Error::Invalid("PA30 rift position overflow"))?;
            offset = offset
                .checked_add(offset_format.number(bits)?)
                .ok_or(Error::Invalid("PA30 rift offset overflow"))?;
            let right = left.wrapping_add(offset);
            if entries.last().is_some_and(|&(previous, _)| previous > left) {
                return Err(Error::Invalid("PA30 unsorted rift entries"));
            }
            entries.push((left, right));
        }
        Ok(Self { entries })
    }

    pub(super) fn entries(&self) -> &[(i64, i64)] {
        &self.entries
    }

    pub(super) fn from_entries(mut entries: Vec<(i64, i64)>, limits: &Limits) -> Result<Self> {
        check_count(entries.len(), limits)?;
        // Stable ordering matters: duplicate native breakpoints resolve to the
        // last entry during mapping, preserving input order among equal keys.
        entries.sort_by_key(|&(left, _)| left);
        Ok(Self { entries })
    }

    pub(super) fn source_shift(size: usize, limits: &Limits) -> Result<Self> {
        let size = i64::try_from(size).map_err(|_| Error::Limit("PA30 source shift"))?;
        Self::from_entries(vec![(size, 0)], limits)
    }

    /// Merge maps, giving the first map priority at equal breakpoints unless
    /// `second_priority` is set. This combines entries rather than translations.
    pub(super) fn sum(
        first: &Self,
        second: &Self,
        second_priority: bool,
        limits: &Limits,
    ) -> Result<Self> {
        let mut entries = Vec::new();
        let mut i = 0;
        let mut j = 0;
        while i < first.entries.len() || j < second.entries.len() {
            let take_first = j == second.entries.len()
                || i < first.entries.len() && first.entries[i].0 <= second.entries[j].0;
            if take_first {
                let left = first.entries[i].0;
                while i < first.entries.len() && first.entries[i].0 == left {
                    push_pair(&mut entries, first.entries[i], limits)?;
                    i += 1;
                }
                if !second_priority {
                    while j < second.entries.len() && second.entries[j].0 == left {
                        j += 1;
                    }
                }
            } else {
                push_pair(&mut entries, second.entries[j], limits)?;
                j += 1;
            }
        }
        Ok(Self { entries })
    }

    pub(super) fn map(&self, address: i64) -> i64 {
        address.wrapping_add(self.rift(address).0)
    }

    /// Native decompression narrows valid interval starts and backward offsets
    /// to uint32. PE address transforms continue to use the full signed map.
    pub(super) fn compression_rift(&self, address: i64) -> (i64, i64) {
        let (delta, end) = self.rift(address);
        let following = self.entries.partition_point(|&(left, _)| left <= address);
        let left = if following == 0 {
            0
        } else {
            self.entries[following - 1].0
        };
        if u32::try_from(left).is_err() || u32::try_from(delta.wrapping_neg()).is_err() {
            (0, end)
        } else {
            (delta, end)
        }
    }

    /// Return the translation and inclusive end of its current signed interval.
    pub(super) fn rift(&self, address: i64) -> (i64, i64) {
        if self.entries.is_empty() {
            return (0, i64::MAX);
        }
        let following = self.entries.partition_point(|&(left, _)| left <= address);
        let index = if following == 0 {
            self.entries.len() - 1
        } else {
            following - 1
        };
        let (left, right) = self.entries[index];
        let end = if following < self.entries.len() {
            self.entries[following].0 - 1
        } else {
            i64::MAX
        };
        (right.wrapping_sub(left), end)
    }

    /// Reverse the map with native first-covered-segment priority, starting at
    /// address zero. Gaps keep the preceding inverse translation.
    pub(super) fn reverse(&self, limits: &Limits) -> Result<Self> {
        if self.entries.len() <= 1 {
            return Self::from_entries(
                self.entries
                    .iter()
                    .map(|&(left, right)| (0, right.wrapping_sub(left)))
                    .collect(),
                limits,
            );
        }
        if self
            .entries
            .len()
            .checked_mul(256)
            .is_none_or(|bytes| bytes > limits.max_parameter_bytes)
        {
            return Err(Error::Limit("PA30 rift reversal workspace"));
        }
        const MIN: i128 = i64::MIN as i128;
        const END: i128 = i64::MAX as i128 + 1;
        const CIRCLE: i128 = 1i128 << 64;
        let mut starts = Vec::new();
        starts
            .try_reserve_exact(self.entries.len() + 2)
            .map_err(|_| Error::Allocation)?;
        starts.extend([i64::MIN, 0]);
        starts.extend(self.entries.iter().map(|&(left, _)| left));
        starts.sort_unstable();
        starts.dedup();
        let pivot = starts.partition_point(|&x| x < 0);
        let mut events = Vec::new();
        events
            .try_reserve_exact(starts.len() * 4)
            .map_err(|_| Error::Allocation)?;
        for priority in 0..starts.len() {
            let index = (pivot + priority) % starts.len();
            let start = starts[index];
            let end = starts.get(index + 1).copied().map_or(END, i128::from);
            let delta = self.rift(start).0;
            let mapped = (i128::from(start) + i128::from(delta) - MIN).rem_euclid(CIRCLE) + MIN;
            let length = end - i128::from(start);
            let stop = (mapped + length).min(END);
            events.push((mapped, true, priority, delta.wrapping_neg()));
            events.push((stop, false, priority, delta.wrapping_neg()));
            if mapped + length > END {
                events.push((MIN, true, priority, delta.wrapping_neg()));
                events.push((
                    MIN + (mapped + length - END),
                    false,
                    priority,
                    delta.wrapping_neg(),
                ));
            }
        }
        events.sort_unstable();
        let mut active = std::collections::BTreeMap::new();
        let mut output = Vec::new();
        let mut previous = None;
        let mut index = 0;
        while index < events.len() {
            let position = events[index].0;
            while index < events.len() && events[index].0 == position {
                let (_, insert, priority, delta) = events[index];
                if insert {
                    active.insert(priority, delta);
                } else {
                    active.remove(&priority);
                }
                index += 1;
            }
            if position == END {
                break;
            }
            if let Some((&priority, &delta)) = active.first_key_value()
                && previous != Some((priority, delta))
            {
                let position =
                    i64::try_from(position).map_err(|_| Error::Invalid("PA30 reverse position"))?;
                push_pair(
                    &mut output,
                    (position, position.wrapping_add(delta)),
                    limits,
                )?;
                // Native Reverse retains newly covered segment boundaries even
                // when their translations coincide. Sum can later overlay a
                // different map between them, making these reset keys matter.
                previous = Some((priority, delta));
            }
        }
        Self::from_entries(output, limits)
    }

    /// Compose address maps as `second(first(address))` with bounded breakpoints.
    pub(super) fn compose(first: &Self, second: &Self, limits: &Limits) -> Result<Self> {
        check_count(first.entries.len(), limits)?;
        check_count(second.entries.len(), limits)?;
        if first
            .entries
            .len()
            .checked_mul(second.entries.len())
            .is_none_or(|count| count > limits.max_parameter_bytes / 16)
        {
            return Err(Error::Limit("PA30 rift composition work"));
        }
        if first.entries.is_empty() {
            return Self::from_entries(second.entries.clone(), limits);
        }
        if second.entries.is_empty() {
            return Self::from_entries(first.entries.clone(), limits);
        }
        let mut boundaries = Vec::new();
        push_pair(
            &mut boundaries,
            (i64::MIN, second.map(first.map(i64::MIN))),
            limits,
        )?;
        for &(left, _) in &first.entries {
            push_pair(&mut boundaries, (left, second.map(first.map(left))), limits)?;
        }
        // An outer map changes either when the first translation changes, or
        // when that translation crosses a breakpoint in the second map. Offset
        // subtraction wraps because the native address domain is a 64-bit ring.
        let mut starts = Vec::new();
        starts
            .try_reserve_exact(first.entries.len() + 1)
            .map_err(|_| Error::Allocation)?;
        starts.push(i64::MIN);
        starts.extend(first.entries.iter().map(|&(left, _)| left));
        starts.dedup();
        for (index, &start) in starts.iter().enumerate() {
            let end = starts.get(index + 1).copied().map_or(i64::MAX, |x| x - 1);
            let offset = first.rift(start).0;
            for &(boundary, _) in &second.entries {
                let translated = boundary.wrapping_sub(offset);
                if translated >= start && translated <= end {
                    push_pair(
                        &mut boundaries,
                        (translated, second.map(first.map(translated))),
                        limits,
                    )?;
                }
            }
            // Signed overflow changes which circular segment is active even
            // without a second-map breakpoint at MIN.
            let wrapped = i64::MIN.wrapping_sub(offset);
            if wrapped >= start && wrapped <= end {
                push_pair(
                    &mut boundaries,
                    (wrapped, second.map(first.map(wrapped))),
                    limits,
                )?;
            }
        }
        Self::from_entries(boundaries, limits)
    }
}

fn check_count(count: usize, limits: &Limits) -> Result<()> {
    if count
        .checked_mul(std::mem::size_of::<(i64, i64)>())
        .is_none_or(|bytes| bytes > limits.max_parameter_bytes)
    {
        return Err(Error::Limit("PA30 rift table memory"));
    }
    Ok(())
}
fn push_pair(entries: &mut Vec<(i64, i64)>, pair: (i64, i64), limits: &Limits) -> Result<()> {
    check_count(entries.len() + 1, limits)?;
    entries.try_reserve(1).map_err(|_| Error::Allocation)?;
    entries.push(pair);
    Ok(())
}

pub(super) struct IntFormat {
    code: Huffman,
}
impl IntFormat {
    pub(super) fn read(bits: &mut Bits<'_>) -> Result<Self> {
        let positive = bits.read(8)? as usize;
        let negative = bits.read(8)? as usize;
        let long = bits.read(8)? as usize;
        if positive > 126 || negative > 126 || long > 252 - positive - negative {
            return Err(Error::Invalid("PA30 rift integer format"));
        }
        let mut lengths = [0u8; 252];
        for length in &mut lengths[..positive] {
            *length = bits.read(4)? as u8 + 1;
        }
        for length in &mut lengths[126..126 + negative] {
            *length = bits.read(4)? as u8 + 1;
        }
        let long_length = bits.read(4)? as u8 + 1;
        let (positive_lengths, negative_lengths) = lengths.split_at_mut(126);
        for (index, length) in positive_lengths[positive..]
            .iter_mut()
            .chain(negative_lengths[negative..].iter_mut())
            .enumerate()
        {
            *length = long_length - u8::from(index >= long);
        }
        Ok(Self {
            code: Huffman::new(&lengths, 16)?,
        })
    }
    fn number(&self, bits: &mut Bits<'_>) -> Result<i64> {
        let symbol = self.code.decode(bits)?;
        let slot = symbol % 126;
        let magnitude = if slot < 4 {
            slot as u64
        } else {
            let width = (slot >> 1) - 1;
            ((2 | (slot & 1)) as u64) << width | bits.read(width)?
        };
        let value =
            i64::try_from(magnitude).map_err(|_| Error::Invalid("PA30 rift integer range"))?;
        Ok(if symbol < 126 { value } else { !value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Writer {
        bits: Vec<u8>,
    }
    impl Writer {
        fn new() -> Self {
            Self { bits: vec![0; 3] }
        }
        fn put(&mut self, value: u64, count: usize) {
            for shift in 0..count {
                self.bits.push(((value >> shift) & 1) as u8);
            }
        }
        fn code(&mut self, value: u64, count: usize) {
            for shift in (0..count).rev() {
                self.bits.push(((value >> shift) & 1) as u8);
            }
        }
        fn format(&mut self) {
            self.put(0, 8);
            self.put(0, 8);
            self.put(248, 8);
            self.put(7, 4);
        }
        fn finish(mut self) -> Vec<u8> {
            let padding = (8 - self.bits.len() % 8) % 8;
            for index in 0..3 {
                self.bits[index] = ((padding >> index) & 1) as u8;
            }
            self.bits.resize(self.bits.len() + padding, 0);
            self.bits
                .chunks(8)
                .map(|word| {
                    word.iter()
                        .enumerate()
                        .fold(0, |byte, (i, &bit)| byte | (bit << i))
                })
                .collect()
        }
    }
    #[test]
    fn wire_rift_decodes_signed_integer_formats_and_cumulative_offsets() {
        let mut writer = Writer::new();
        writer.put(1, 1);
        writer.format();
        writer.format();
        writer.put(1, 1);
        writer.put(2, 4); // nibble-coded entry count two.
        writer.code(2, 8);
        writer.code(3, 8); // left2,delta3 -> pair(2,5).
        writer.code(3, 8);
        writer.code(126, 8); // leftdelta3,offsetdelta-1 -> pair(5,7).
        let encoded = writer.finish();
        let mut bits = Bits::new(&encoded).unwrap();
        let table = RiftTable::read(&mut bits, &Limits::default()).unwrap();
        bits.finish().unwrap();
        assert_eq!(table.entries, vec![(2, 5), (5, 7)]);
        for length in 0..encoded.len() {
            if let Ok(mut bits) = Bits::new(&encoded[..length]) {
                assert!(RiftTable::read(&mut bits, &Limits::default()).is_err());
            }
        }
    }
    #[test]
    fn native_map_before_first_breakpoint_uses_last_translation() {
        let table =
            RiftTable::from_entries(vec![(100, 150), (200, 200)], &Limits::default()).unwrap();
        assert_eq!(table.map(0), 0);
        assert_eq!(table.map(100), 150);
        assert_eq!(table.map(199), 249);
        assert_eq!(table.map(200), 200);
        assert_eq!(table.rift(0), (0, 99));
        assert_eq!(table.rift(100), (50, 199));
    }
    #[test]
    fn composition_agrees_with_direct_native_style_mapping_at_boundaries() {
        let limits = Limits::default();
        for first_pairs in [
            vec![(0, 0), (100, 150), (200, 200)],
            vec![(200, 0)],
            vec![(0, 1), (100, 100)],
            vec![(0, -5), (100, 100)],
        ] {
            let first = RiftTable::from_entries(first_pairs, &limits).unwrap();
            let second =
                RiftTable::from_entries(vec![(100, 200), (200, 100), (300, 300)], &limits).unwrap();
            let composed = RiftTable::compose(&first, &second, &limits).unwrap();
            for position in [
                i64::MIN,
                i64::MIN + 1,
                -1000,
                -1,
                0,
                1,
                49,
                50,
                99,
                100,
                149,
                150,
                199,
                200,
                249,
                250,
                299,
                300,
                499,
                500,
                i64::MAX - 1,
                i64::MAX,
            ] {
                assert_eq!(
                    composed.map(position),
                    second.map(first.map(position)),
                    "{position}"
                );
            }
        }
    }
    #[test]
    fn reversal_matches_independent_private_native_function_oracles() {
        let limits = Limits::default();
        for (input, expected) in [
            (
                vec![(0, 0), (100, 150), (200, 200)],
                vec![(i64::MIN, i64::MIN), (0, 0), (150, 100), (250, 250)],
            ),
            (
                vec![(0, 0), (100, 50), (200, 200)],
                vec![(i64::MIN, i64::MIN), (0, 0), (100, 150), (200, 200)],
            ),
            (vec![(0, 100)], vec![(0, 100)]),
            (
                vec![(0, 0), (100, 200), (200, 100), (300, 300)],
                vec![
                    (i64::MIN, i64::MIN),
                    (0, 0),
                    (100, 200),
                    (200, 100),
                    (300, 300),
                ],
            ),
        ] {
            let reversed = RiftTable::from_entries(input, &limits)
                .unwrap()
                .reverse(&limits)
                .unwrap();
            let expected = RiftTable::from_entries(expected, &limits).unwrap();
            assert_eq!(reversed.entries(), expected.entries());
            for position in [
                i64::MIN,
                -1,
                0,
                49,
                50,
                99,
                100,
                149,
                150,
                199,
                200,
                249,
                250,
                299,
                300,
                i64::MAX,
            ] {
                assert_eq!(reversed.map(position), expected.map(position));
            }
        }
    }
    #[test]
    fn reversed_identity_boundaries_reset_overlaid_metadata_translation() {
        let limits = Limits::default();
        let geometry =
            RiftTable::from_entries(vec![(0, 0), (512, 512), (2048, 2048)], &limits).unwrap();
        let reversed = geometry.reverse(&limits).unwrap();
        assert_eq!(
            reversed.entries(),
            &[(i64::MIN, i64::MIN), (0, 0), (512, 512), (2048, 2048)]
        );
        let metadata = RiftTable::from_entries(vec![(1024, 1020)], &limits).unwrap();
        let combined = RiftTable::sum(&metadata, &reversed, false, &limits).unwrap();
        assert_eq!(combined.map(1500), 1496);
        assert_eq!(combined.map(2048), 2048);
    }

    #[test]
    fn sum_collision_priority_and_source_shift_match_native_graph_semantics() {
        let limits = Limits::default();
        let first = RiftTable::from_entries(vec![(0, 100), (100, 100)], &limits).unwrap();
        let second = RiftTable::from_entries(vec![(0, 200), (200, 200)], &limits).unwrap();
        assert_eq!(
            RiftTable::sum(&first, &second, false, &limits)
                .unwrap()
                .map(0),
            100
        );
        assert_eq!(
            RiftTable::sum(&first, &second, true, &limits)
                .unwrap()
                .map(0),
            200
        );
        assert_eq!(RiftTable::source_shift(100, &limits).unwrap().map(120), 20);
    }
    #[test]
    fn compression_intervals_clip_native_invalid_starts_and_backward_offsets() {
        let limits = Limits::default();
        for entries in [
            vec![(-1, -2)],
            vec![(i64::from(u32::MAX) + 1, 0)],
            vec![(0, 1)],
            vec![(0, -i64::from(u32::MAX) - 1)],
        ] {
            let table = RiftTable::from_entries(entries.clone(), &limits).unwrap();
            assert_eq!(table.compression_rift(entries[0].0).0, 0);
            assert_ne!(table.rift(entries[0].0).0, 0);
        }
        let table = RiftTable::source_shift(100, &limits).unwrap();
        assert_eq!(table.compression_rift(120), (-100, i64::MAX));
        // Native initialization uses implicit left zero before the first key.
        assert_eq!(table.compression_rift(50), (-100, 99));
        assert_eq!(RiftTable::default().compression_rift(0), (0, i64::MAX));
    }

    #[test]
    fn oversized_tables_and_composition_work_are_rejected() {
        let limit = Limits {
            max_parameter_bytes: 16,
            ..Limits::default()
        };
        assert!(RiftTable::from_entries(vec![(0, 0), (1, 1)], &limit).is_err());
        let a = RiftTable::from_entries(vec![(0, 0)], &limit).unwrap();
        assert!(a.reverse(&limit).is_ok());
    }
}
