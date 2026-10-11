//! Synthetic PA19 tests. They build containers around MS-PATCH LZX streams made by
//! `create_lzxd`; they need no Microsoft files and do not model PE transforms.

use ms_delta::{
    Error, Limits, create_lzxd,
    pa19::{apply_pa19, inspect_pa19},
};

fn crc32(data: &[u8]) -> u32 {
    let mut register = 0xffff_ffffu32;
    for byte in data {
        register ^= u32::from(*byte);
        for _ in 0..8 {
            register = if register & 1 != 0 {
                0xedb8_8320 ^ (register >> 1)
            } else {
                register >> 1
            };
        }
    }
    !register
}

fn uvar(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let group = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(group | 0x80);
            return;
        }
        out.push(group);
    }
}

fn svar(value: i32, out: &mut Vec<u8>) {
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let sign = if negative { 0x40 } else { 0 };
    let first = (magnitude & 0x3f) as u8 | sign;
    magnitude >>= 6;
    if magnitude == 0 {
        out.push(first | 0x80);
        return;
    }
    out.push(first);
    uvar(magnitude, out);
}

struct Source {
    old_size: usize,
    old_crc: u32,
    ignore: Vec<(u32, u32)>,
    retain: Vec<(u32, u32, u32)>,
    stream: Vec<u8>,
}

/// Flags: no time, no COFF fields, no resource time; low bits select LZX.
const FLAGS: u32 = 0x00c4_0001;

fn build(flags: u32, new_size: usize, new_crc: u32, sources: &[Source]) -> Vec<u8> {
    let mut out = b"PA19".to_vec();
    out.extend_from_slice(&(flags ^ 0x0080_0000).to_le_bytes());
    uvar(new_size as u32, &mut out);
    out.extend_from_slice(&new_crc.to_le_bytes());
    out.push(sources.len() as u8);
    for source in sources {
        svar(source.old_size as i32 - new_size as i32, &mut out);
        out.extend_from_slice(&source.old_crc.to_le_bytes());
        out.push(source.ignore.len() as u8);
        let mut previous = 0u32;
        for (offset, length) in &source.ignore {
            svar(*offset as i32 - previous as i32, &mut out);
            uvar(*length, &mut out);
            previous = offset + length;
        }
        out.push(source.retain.len() as u8);
        let mut previous = 0u32;
        for (old, length, new) in &source.retain {
            svar(*old as i32 - previous as i32, &mut out);
            svar(*new as i32 - *old as i32, &mut out);
            uvar(*length, &mut out);
            previous = old + length;
        }
        uvar(0, &mut out);
        uvar(source.stream.len() as u32, &mut out);
    }
    for source in sources {
        out.extend_from_slice(&source.stream);
    }
    let trailer = !crc32(&out);
    out.extend_from_slice(&trailer.to_le_bytes());
    out
}

/// The default window `mspatcha.dll` picks for these small files (flag 0x4 clear).
fn stream(old: &[u8], new: &[u8]) -> Vec<u8> {
    let wanted = new.len() + ((old.len() + 0x7fff) & !0x7fff);
    let mut window = 0x2_0000usize;
    while window < wanted {
        window <<= 1;
    }
    create_lzxd(old, new, window.trailing_zeros() as u8, &Limits::default()).unwrap()
}

fn sample(seed: u32, length: usize) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 3) as u8
        })
        .collect()
}

fn simple_case() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let old = sample(7, 70_000);
    let mut new = old.clone();
    new[1000..1100].fill(0x5a);
    new.extend_from_slice(b"appended tail bytes");
    let stream = stream(&old, &new);
    let patch = build(
        FLAGS,
        new.len(),
        crc32(&new),
        &[Source {
            old_size: old.len(),
            old_crc: crc32(&old),
            ignore: vec![],
            retain: vec![],
            stream,
        }],
    );
    (old, new, patch)
}

#[test]
fn inspect_reports_header_fields_and_alternatives() {
    let (old, new, patch) = simple_case();
    let info = inspect_pa19(&patch, &Limits::default()).unwrap();
    assert_eq!(info.flags, FLAGS);
    assert_eq!(info.options, 0);
    assert_eq!(info.target_time, None);
    assert_eq!(info.target_size, new.len());
    assert_eq!(info.target_crc32, crc32(&new));
    assert_eq!(info.window_size, None);
    assert_eq!(info.sources.len(), 1);
    assert_eq!(info.sources[0].old_size, old.len());
    assert_eq!(info.sources[0].old_crc32, crc32(&old));
    assert_eq!(info.sources[0].rift_entries, 0);
    assert_eq!(
        info.header_size + info.sources[0].patch_size + 4,
        patch.len()
    );
}

#[test]
fn raw_patch_reconstructs_target() {
    let (old, new, patch) = simple_case();
    assert_eq!(apply_pa19(&old, &patch, &Limits::default()).unwrap(), new);
}

#[test]
fn second_alternative_is_selected_by_old_file_size_and_crc() {
    let (old, new, _) = simple_case();
    let other = sample(99, 5000);
    let stream_other = stream(&other, &new);
    let stream = stream(&old, &new);
    let patch = build(
        FLAGS,
        new.len(),
        crc32(&new),
        &[
            Source {
                old_size: other.len(),
                old_crc: crc32(&other),
                ignore: vec![],
                retain: vec![],
                stream: stream_other,
            },
            Source {
                old_size: old.len(),
                old_crc: crc32(&old),
                ignore: vec![],
                retain: vec![],
                stream,
            },
        ],
    );
    assert_eq!(apply_pa19(&old, &patch, &Limits::default()).unwrap(), new);
    assert_eq!(apply_pa19(&other, &patch, &Limits::default()).unwrap(), new);
}

#[test]
fn wrong_old_file_is_rejected() {
    let (mut old, _, patch) = simple_case();
    old[10] ^= 1;
    assert!(matches!(
        apply_pa19(&old, &patch, &Limits::default()),
        Err(Error::Integrity(_))
    ));
    assert!(matches!(
        apply_pa19(&old[..100], &patch, &Limits::default()),
        Err(Error::Integrity(_))
    ));
}

#[test]
fn corrupt_patch_trailer_and_payload_are_rejected() {
    let (old, _, patch) = simple_case();
    for position in [patch.len() - 1, patch.len() / 2, 9, 5] {
        let mut broken = patch.clone();
        broken[position] ^= 0x10;
        assert!(inspect_pa19(&broken, &Limits::default()).is_err());
        assert!(apply_pa19(&old, &broken, &Limits::default()).is_err());
    }
}

#[test]
fn corrupt_payload_with_valid_trailer_fails_the_target_crc() {
    let (old, _, patch) = simple_case();
    let mut broken = patch[..patch.len() - 4].to_vec();
    let middle = broken.len() * 3 / 4;
    broken[middle] ^= 0x04;
    let trailer = !crc32(&broken);
    broken.extend_from_slice(&trailer.to_le_bytes());
    assert!(apply_pa19(&old, &broken, &Limits::default()).is_err());
}

#[test]
fn truncation_and_foreign_magic_never_panic() {
    let (old, _, patch) = simple_case();
    for length in 0..patch.len().min(200) {
        let _ = inspect_pa19(&patch[..length], &Limits::default());
        let _ = apply_pa19(&old, &patch[..length], &Limits::default());
    }
    let mut foreign = patch.clone();
    foreign[..4].copy_from_slice(b"PA30");
    assert!(inspect_pa19(&foreign, &Limits::default()).is_err());
    assert!(inspect_pa19(&[], &Limits::default()).is_err());
}

#[test]
fn every_header_byte_mutation_with_a_fixed_trailer_never_panics() {
    let (old, _, patch) = simple_case();
    let header = inspect_pa19(&patch, &Limits::default())
        .unwrap()
        .header_size;
    for position in 0..header {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut mutated = patch[..patch.len() - 4].to_vec();
            mutated[position] ^= flip;
            let trailer = !crc32(&mutated);
            mutated.extend_from_slice(&trailer.to_le_bytes());
            let _ = inspect_pa19(&mutated, &Limits::default());
            let limits = Limits {
                max_output_bytes: 1 << 20,
                ..Limits::default()
            };
            let _ = apply_pa19(&old, &mutated, &limits);
        }
    }
}

#[test]
fn resource_limits_fail_closed() {
    let (old, new, patch) = simple_case();
    for limits in [
        Limits {
            max_patch_bytes: patch.len() - 1,
            ..Limits::default()
        },
        Limits {
            max_output_bytes: new.len() - 1,
            ..Limits::default()
        },
        Limits {
            max_source_bytes: old.len() - 1,
            ..Limits::default()
        },
        Limits {
            max_window_bytes: 0x1_0000,
            ..Limits::default()
        },
    ] {
        assert!(apply_pa19(&old, &patch, &limits).is_err());
    }
}

#[test]
fn ignore_ranges_are_zeroed_before_the_old_file_crc_test() {
    let mut old = sample(3, 40_000);
    old[100..200].fill(0);
    let new = {
        let mut new = old.clone();
        new[5000] ^= 0xff;
        new
    };
    let stream = stream(&old, &new);
    let patch = build(
        FLAGS,
        new.len(),
        crc32(&new),
        &[Source {
            old_size: old.len(),
            old_crc: crc32(&old),
            ignore: vec![(100, 100)],
            retain: vec![],
            stream,
        }],
    );
    let mut dirty = old.clone();
    dirty[100..200].fill(0xaa);
    assert_eq!(apply_pa19(&dirty, &patch, &Limits::default()).unwrap(), new);
    let info = inspect_pa19(&patch, &Limits::default()).unwrap();
    assert_eq!(info.sources[0].ignore_ranges.len(), 1);
    assert_eq!(info.sources[0].ignore_ranges[0].offset, 100);
}

#[test]
fn retain_ranges_move_old_bytes_into_the_new_file_after_the_crc_test() {
    let old = sample(11, 40_000);
    let mut decoded = old.clone();
    decoded[2000..2050].fill(0);
    decoded[7000] ^= 1;
    let mut zeroed_old = old.clone();
    zeroed_old[3000..3050].fill(0);
    let stream = stream(&zeroed_old, &decoded);
    let patch = build(
        FLAGS,
        decoded.len(),
        crc32(&decoded),
        &[Source {
            old_size: old.len(),
            old_crc: crc32(&zeroed_old),
            ignore: vec![],
            retain: vec![(3000, 50, 2000)],
            stream,
        }],
    );
    let mut expected = decoded.clone();
    expected[2000..2050].copy_from_slice(&old[3000..3050]);
    assert_eq!(
        apply_pa19(&old, &patch, &Limits::default()).unwrap(),
        expected
    );
}

#[test]
fn already_current_file_is_returned_without_a_stream() {
    let new = sample(5, 9000);
    let other = sample(6, 3000);
    let patch = build(
        FLAGS,
        new.len(),
        crc32(&new),
        &[Source {
            old_size: other.len(),
            old_crc: crc32(&other),
            ignore: vec![],
            retain: vec![],
            stream: stream(&other, &new),
        }],
    );
    assert_eq!(apply_pa19(&new, &patch, &Limits::default()).unwrap(), new);
}

#[test]
fn invalid_flags_and_options_are_rejected() {
    let (_, _, patch) = simple_case();
    let body = &patch[..patch.len() - 4];
    for bad in [FLAGS | 0x8, FLAGS | 0x0100_0000, FLAGS | 0x2000_0000] {
        let mut mutated = body.to_vec();
        mutated[4..8].copy_from_slice(&(bad ^ 0x0080_0000).to_le_bytes());
        let trailer = !crc32(&mutated);
        mutated.extend_from_slice(&trailer.to_le_bytes());
        assert!(inspect_pa19(&mutated, &Limits::default()).is_err());
    }
}

#[test]
fn rift_tables_on_non_pe_sources_are_parsed_and_leave_the_source_unchanged() {
    let old = sample(21, 20_000);
    let mut new = old.clone();
    new[0] ^= 1;
    let stream = stream(&old, &new);
    let mut out = b"PA19".to_vec();
    out.extend_from_slice(&(FLAGS ^ 0x0080_0000).to_le_bytes());
    uvar(new.len() as u32, &mut out);
    out.extend_from_slice(&crc32(&new).to_le_bytes());
    out.push(1);
    svar(0, &mut out);
    out.extend_from_slice(&crc32(&old).to_le_bytes());
    out.push(0);
    out.push(0);
    uvar(2, &mut out);
    uvar(4096, &mut out);
    svar(16, &mut out);
    uvar(100, &mut out);
    svar(-32, &mut out);
    uvar(stream.len() as u32, &mut out);
    out.extend_from_slice(&stream);
    let trailer = !crc32(&out);
    out.extend_from_slice(&trailer.to_le_bytes());
    let info = inspect_pa19(&out, &Limits::default()).unwrap();
    assert_eq!(info.sources[0].rift_entries, 2);
    assert_eq!(apply_pa19(&old, &out, &Limits::default()).unwrap(), new);
}
