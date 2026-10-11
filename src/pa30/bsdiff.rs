//! Bounded PA31 interleaved binary-difference reconstruction.
//!
//! This is the three-control interleaved stream, not a BSDIFF40 file with
//! three separately compressed sections. Each signed control is little-endian
//! magnitude with the sign in bit 63. Diff bytes add to source bytes modulo 256.
use crate::{Error, Limits, Result};

pub(super) fn apply(
    source: &[u8],
    patch: &[u8],
    target_size: usize,
    limits: &Limits,
) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA31 BsDiff source"));
    }
    if target_size > limits.max_output_bytes {
        return Err(Error::Limit("PA31 BsDiff target"));
    }
    let stream_limit = limits
        .max_output_bytes
        .checked_add(limits.max_parameter_bytes)
        .ok_or(Error::Limit("PA31 BsDiff stream budget"))?;
    if patch.len() > stream_limit {
        return Err(Error::Limit("PA31 BsDiff stream"));
    }
    let control_bytes = patch
        .len()
        .checked_sub(target_size)
        .ok_or(Error::Invalid("PA31 BsDiff stream shorter than target"))?;
    if control_bytes > limits.max_parameter_bytes {
        return Err(Error::Limit("PA31 BsDiff control budget"));
    }
    if !control_bytes.is_multiple_of(24) || (target_size != 0 && control_bytes == 0) {
        return Err(Error::Invalid("PA31 BsDiff control framing"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(target_size)
        .map_err(|_| Error::Allocation)?;
    let mut cursor = 0usize;
    let mut source_cursor = 0i64;
    while output.len() < target_size {
        let diff = control(patch, &mut cursor)?;
        let extra = control(patch, &mut cursor)?;
        let seek = control(patch, &mut cursor)?;
        if !(0..=i64::from(i32::MAX)).contains(&diff) || !(0..=i64::from(i32::MAX)).contains(&extra)
        {
            return Err(Error::Invalid("PA31 BsDiff run length"));
        }
        let diff = diff as usize;
        let extra = extra as usize;
        let total = diff
            .checked_add(extra)
            .ok_or(Error::Invalid("PA31 BsDiff run overflow"))?;
        if total > target_size - output.len() {
            return Err(Error::Invalid("PA31 BsDiff run exceeds target"));
        }
        let bytes = take(patch, &mut cursor, diff)?;
        for (index, &delta) in bytes.iter().enumerate() {
            let old = source_cursor
                .checked_add(index as i64)
                .ok_or(Error::Invalid("PA31 BsDiff source cursor overflow"))?;
            let reference = usize::try_from(old)
                .ok()
                .and_then(|index| source.get(index))
                .copied()
                .unwrap_or(0);
            output.push(delta.wrapping_add(reference));
        }
        output.extend_from_slice(take(patch, &mut cursor, extra)?);
        source_cursor = source_cursor
            .checked_add(diff as i64)
            .and_then(|value| value.checked_add(seek))
            .ok_or(Error::Invalid("PA31 BsDiff source cursor overflow"))?;
    }
    if cursor != patch.len() {
        return Err(Error::Invalid("PA31 BsDiff trailing bytes"));
    }
    Ok(output)
}

fn take<'a>(patch: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or(Error::Invalid("PA31 BsDiff input overflow"))?;
    let bytes = patch
        .get(*cursor..end)
        .ok_or(Error::Invalid("PA31 BsDiff truncated stream"))?;
    *cursor = end;
    Ok(bytes)
}
fn control(patch: &[u8], cursor: &mut usize) -> Result<i64> {
    let bytes: [u8; 8] = take(patch, cursor, 8)?
        .try_into()
        .map_err(|_| Error::Invalid("PA31 BsDiff control"))?;
    let raw = u64::from_le_bytes(bytes);
    let magnitude = (raw & i64::MAX as u64) as i64;
    Ok(if raw >> 63 == 0 {
        magnitude
    } else {
        -magnitude
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn append(patch: &mut Vec<u8>, diff: &[u8], extra: &[u8], seek: i64) {
        for value in [diff.len() as i64, extra.len() as i64, seek] {
            let raw = value.unsigned_abs() | if value < 0 { 1 << 63 } else { 0 };
            patch.extend_from_slice(&raw.to_le_bytes());
        }
        patch.extend_from_slice(diff);
        patch.extend_from_slice(extra);
    }
    #[test]
    fn source_addition_backward_seek_and_literal_runs() {
        let mut patch = Vec::new();
        append(&mut patch, &[1, 255, 3], b"xyz", -3);
        append(&mut patch, &[0, 0, 0], b"!", 0);
        assert_eq!(
            apply(&[10, 20, 30], &patch, 10, &Limits::default()).unwrap(),
            [11, 19, 33, b'x', b'y', b'z', 10, 20, 30, b'!']
        );
    }
    #[test]
    fn source_outside_bounds_contributes_zero_and_zero_length_seek_is_finite() {
        let mut patch = Vec::new();
        append(&mut patch, &[], &[], -2);
        append(&mut patch, &[1, 2, 3, 4, 5], &[], 0);
        assert_eq!(
            apply(&[10], &patch, 5, &Limits::default()).unwrap(),
            [1, 2, 13, 4, 5]
        );
    }
    #[test]
    fn all_truncations_invalid_runs_trailing_and_limits_fail_closed() {
        let mut patch = Vec::new();
        append(&mut patch, &[0, 0, 0], b"a", 0);
        for length in 0..patch.len() {
            assert!(apply(b"abc", &patch[..length], 4, &Limits::default()).is_err());
        }
        let mut trailing = patch.clone();
        trailing.push(0);
        assert!(apply(b"abc", &trailing, 4, &Limits::default()).is_err());
        let mut negative = patch.clone();
        negative[7] |= 128;
        assert!(apply(b"abc", &negative, 4, &Limits::default()).is_err());
        assert!(apply(b"abc", &patch, 3, &Limits::default()).is_err());
        assert!(
            apply(
                b"abc",
                &patch,
                4,
                &Limits {
                    max_output_bytes: 3,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        assert!(
            apply(
                b"abc",
                &patch,
                4,
                &Limits {
                    max_source_bytes: 2,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        assert!(apply(&[], &[], 0, &Limits::default()).unwrap().is_empty());
        assert!(apply(&[], &[0], 0, &Limits::default()).is_err());
    }
    #[test]
    fn old_cursor_overflow_and_signed_negative_zero_are_handled() {
        let mut patch = Vec::new();
        append(&mut patch, &[], &[], i64::MAX);
        append(&mut patch, &[0], &[], 1);
        assert!(apply(b"a", &patch, 1, &Limits::default()).is_err());
        let mut patch = Vec::new();
        append(&mut patch, &[], b"a", 0);
        patch[7] = 128;
        assert_eq!(apply(&[], &patch, 1, &Limits::default()).unwrap(), b"a");
    }
}
