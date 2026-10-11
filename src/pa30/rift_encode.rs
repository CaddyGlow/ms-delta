//! Bounded serialization of PA30 signed piecewise address maps.
use super::{encode::Writer, rift::RiftTable};
use crate::{Error, Limits, Result};

/// Write the native standalone table envelope and two complete integer codes.
pub(super) fn write(table: &RiftTable, writer: &mut Writer, limits: &Limits) -> Result<()> {
    let entries = table.entries();
    if entries
        .len()
        .checked_mul(16)
        .is_none_or(|bytes| bytes > limits.max_parameter_bytes)
    {
        return Err(Error::Limit("PA30 rift encoder entries"));
    }
    // Validate the entire signed cumulative representation before emitting it.
    let mut previous_left = 0i64;
    let mut previous_offset = 0i64;
    for (index, &(left, right)) in entries.iter().enumerate() {
        if index != 0 && left < previous_left {
            return Err(Error::Invalid("PA30 unsorted encoded rift"));
        }
        left.checked_sub(previous_left)
            .ok_or(Error::Invalid("PA30 encoded rift position overflow"))?;
        let offset = right
            .checked_sub(left)
            .ok_or(Error::Invalid("PA30 encoded rift offset overflow"))?;
        offset
            .checked_sub(previous_offset)
            .ok_or(Error::Invalid("PA30 encoded rift offset delta overflow"))?;
        previous_left = left;
        previous_offset = offset;
    }
    writer.bits(u64::from(!entries.is_empty()), 1)?;
    if entries.is_empty() {
        return Ok(());
    }
    write_format(writer)?;
    write_format(writer)?;
    write_with_formats(table, writer, limits)
}

pub(super) fn write_format(writer: &mut Writer) -> Result<()> {
    writer.bits(0, 8)?;
    writer.bits(0, 8)?;
    writer.bits(248, 8)?;
    writer.bits(7, 4)
}

/// CLI maps share their four integer formats outside individual table bodies.
pub(super) fn write_with_formats(
    table: &RiftTable,
    writer: &mut Writer,
    limits: &Limits,
) -> Result<()> {
    let entries = table.entries();
    if entries
        .len()
        .checked_mul(16)
        .is_none_or(|size| size > limits.max_parameter_bytes)
    {
        return Err(Error::Limit("PA30 rift encoder entries"));
    }
    let mut previous_left = 0i64;
    let mut previous_offset = 0i64;
    for (index, &(left, right)) in entries.iter().enumerate() {
        if index != 0 && left < previous_left {
            return Err(Error::Invalid("PA30 unsorted encoded rift"));
        }
        left.checked_sub(previous_left)
            .ok_or(Error::Invalid("PA30 encoded rift position overflow"))?;
        let offset = right
            .checked_sub(left)
            .ok_or(Error::Invalid("PA30 encoded rift offset overflow"))?;
        offset
            .checked_sub(previous_offset)
            .ok_or(Error::Invalid("PA30 encoded rift offset delta overflow"))?;
        previous_left = left;
        previous_offset = offset;
    }
    writer.number(entries.len() as u64)?;
    previous_left = 0;
    previous_offset = 0;
    for &(left, right) in entries {
        let offset = right - left;
        integer(writer, left - previous_left)?;
        integer(writer, offset - previous_offset)?;
        previous_left = left;
        previous_offset = offset;
    }
    Ok(())
}

fn integer(writer: &mut Writer, value: i64) -> Result<()> {
    // Negative values encode the complement magnitude: -1 shares magnitude
    // zero with +0; this is the native signed convention, not zigzag.
    let magnitude = if value < 0 {
        !value as u64
    } else {
        value as u64
    };
    let (slot, width, tail) = if magnitude < 4 {
        (magnitude as usize, 0, 0)
    } else {
        let width = magnitude.ilog2() as usize - 1;
        let slot = 2 * (width + 1) + ((magnitude >> width) as usize & 1);
        (slot, width, magnitude & ((1u64 << width) - 1))
    };
    let symbol = slot + if value < 0 { 126 } else { 0 };
    let (code, length) = if symbol < 248 {
        (symbol as u64, 8)
    } else {
        ((symbol - 248 + 124) as u64, 7)
    };
    writer.bits(code.reverse_bits() >> (64 - length), length)?;
    writer.bits(tail, width)
}

#[cfg(test)]
mod tests {
    use super::super::Bits;
    use super::*;
    #[test]
    fn empty_and_signed_rifts_roundtrip_with_existing_reader() {
        for entries in [
            vec![],
            vec![(0, 0)],
            vec![(0, 0), (512, 4096), (2048, 8192)],
            vec![(-100, -200), (0, 500), (300, -400), (300, 300)],
            vec![(0, i64::MIN), (1, i64::MIN + 1)],
            vec![(0, i64::MAX)],
        ] {
            let limits = Limits::default();
            let table = RiftTable::from_entries(entries.clone(), &limits).unwrap();
            let mut writer = Writer::new(limits.max_patch_bytes).unwrap();
            write(&table, &mut writer, &limits).unwrap();
            let bytes = writer.finish();
            let mut reader = Bits::new(&bytes).unwrap();
            let decoded = RiftTable::read(&mut reader, &limits).unwrap();
            reader.finish().unwrap();
            assert_eq!(decoded.entries(), entries);
        }
    }
    #[test]
    fn integer_slot_boundaries_and_extremes_roundtrip() {
        for width in 0..63 {
            for value in [1i64 << width, (1i64 << width) - 1, !(1i64 << width)] {
                let limits = Limits::default();
                let table = RiftTable::from_entries(vec![(0, value)], &limits).unwrap();
                let mut writer = Writer::new(limits.max_patch_bytes).unwrap();
                write(&table, &mut writer, &limits).unwrap();
                let bytes = writer.finish();
                let mut reader = Bits::new(&bytes).unwrap();
                assert_eq!(
                    RiftTable::read(&mut reader, &limits).unwrap().entries(),
                    [(0, value)]
                );
                reader.finish().unwrap();
            }
        }
    }
    #[test]
    fn overflow_and_workspace_excess_are_rejected() {
        let limits = Limits::default();
        let table = RiftTable::from_entries(vec![(i64::MIN, i64::MAX)], &limits).unwrap();
        let mut writer = Writer::new(100).unwrap();
        assert!(write(&table, &mut writer, &limits).is_err());
        let table = RiftTable::from_entries(vec![(0, 0)], &limits).unwrap();
        assert!(
            write(
                &table,
                &mut writer,
                &Limits {
                    max_parameter_bytes: 0,
                    ..limits
                }
            )
            .is_err()
        );
    }
}
