//! PA30 target E8 restoration. This is distinct from WIM's E8 translation.

/// Restore relative operands in the first GiB, including a final complete call.
pub(super) fn restore(target: &mut [u8]) {
    let size = target.len().min(1 << 30);
    let mut position = 0;
    while position + 5 <= size {
        if target[position] != 0xe8 {
            position += 1;
            continue;
        }
        let bytes = &mut target[position + 1..position + 5];
        let value = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let position_i32 = position as i32;
        if value.wrapping_add(position_i32) >= 0 && value < size as i32 {
            let relative = if value < 0 {
                value + size as i32
            } else {
                value - position_i32
            };
            bytes.copy_from_slice(&relative.to_le_bytes());
        }
        position += 5;
    }
}

#[cfg(test)]
mod tests {
    use super::restore;

    #[test]
    fn native_e8_flag_fixtures_reconstruct_exact_targets() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa30-pe-native/e8");
        for name in [
            "final-five",
            "incomplete-tail",
            "negative-out-of-range",
            "negative",
            "nested-operand",
            "out-of-range",
            "positive",
            "zero",
        ] {
            let delta = std::fs::read(root.join(format!("{name}.delta"))).unwrap();
            let target = std::fs::read(root.join(format!("{name}.target"))).unwrap();
            let actual = crate::pa30::apply_pa30(&[], &delta, &crate::Limits::default()).unwrap();
            assert_eq!(actual, target, "{name}");
        }
    }

    #[test]
    fn final_complete_operand_is_restored_and_incomplete_tail_preserved() {
        let mut target = [0, 0, 0xe8, 4, 0, 0, 0];
        restore(&mut target);
        assert_eq!(target, [0, 0, 0xe8, 2, 0, 0, 0]);
        let mut tail = [0xe8, 1, 2, 3];
        restore(&mut tail);
        assert_eq!(tail, [0xe8, 1, 2, 3]);
    }

    #[test]
    fn negative_and_out_of_range_operands_follow_signed_bounds() {
        let mut target = vec![0; 32];
        target[4] = 0xe8;
        target[5..9].copy_from_slice(&(-3i32).to_le_bytes());
        target[12] = 0xe8;
        target[13..17].copy_from_slice(&32i32.to_le_bytes());
        target[20] = 0xe8;
        target[21..25].copy_from_slice(&(-21i32).to_le_bytes());
        restore(&mut target);
        assert_eq!(&target[5..9], &29i32.to_le_bytes());
        assert_eq!(&target[13..17], &32i32.to_le_bytes());
        assert_eq!(&target[21..25], &(-21i32).to_le_bytes());
    }

    #[test]
    fn operand_bytes_are_not_rescanned_as_instructions() {
        let mut target = vec![0; 300];
        target[0] = 0xe8;
        target[1..5].copy_from_slice(&232i32.to_le_bytes());
        restore(&mut target);
        assert_eq!(&target[..6], &[0xe8, 0xe8, 0, 0, 0, 0]);
    }
}
