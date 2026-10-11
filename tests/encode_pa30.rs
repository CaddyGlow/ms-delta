use ms_delta::{
    Error, Limits,
    pa30::{apply_pa30, create_pa30, inspect_pa30},
};

#[test]
fn native_apply_verified_created_patches_regenerate_exactly() {
    use sha2::{Digest, Sha256};
    use std::{fs, path::Path};

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-created-native");
    let cases: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 22);
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let source = if case.get("source_generator").is_some() {
            let size = case["source_size"].as_u64().unwrap() as usize;
            assert!(matches!(size, 2_000_000 | 20_000_000));
            let mut source = vec![0; size];
            source[..8].copy_from_slice(b"DISTANCE");
            source
        } else {
            fs::read(root.join(case["source_path"].as_str().unwrap())).unwrap()
        };
        let target = fs::read(root.join(format!("{name}.target"))).unwrap();
        let native = &case["native_oracle"];
        assert_eq!(native["success"], true, "{name}");
        assert_eq!(native["native_target_matches"], true, "{name}");
        assert_eq!(native["native_file_type"], 1);
        assert_eq!(native["native_flags"], 0);
        assert_eq!(native["source_sha256_after"], case["source_sha256"]);
        assert_eq!(native["native_target_sha256"], case["target_sha256"]);
        assert_eq!(
            format!("{:x}", Sha256::digest(&source)),
            case["source_sha256"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&target)),
            case["target_sha256"].as_str().unwrap()
        );
        let patch = create_pa30(&source, &target, &Limits::default()).unwrap();
        assert_eq!(
            patch,
            fs::read(root.join(format!("{name}.delta"))).unwrap(),
            "{name}"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&patch)),
            case["delta_sha256"].as_str().unwrap()
        );
        assert_eq!(
            apply_pa30(&source, &patch, &Limits::default()).unwrap(),
            target,
            "{name}"
        );
    }
}

#[test]
fn created_raw_pa30_is_deterministic_and_carries_sha1_without_a_timestamp() {
    let limits = Limits::default();
    for target in [
        &[][..],
        b"abc",
        b"\0\xff\0\xff",
        b"a deterministic RAW patch",
    ] {
        let delta = create_pa30(&[], target, &limits).unwrap();
        assert_eq!(delta, create_pa30(&[], target, &limits).unwrap());
        assert_eq!(apply_pa30(&[], &delta, &limits).unwrap(), target);
        let info = inspect_pa30(&delta, &limits).unwrap();
        assert_eq!(info.file_type_set, 1);
        assert_eq!(info.file_type, 1);
        assert_eq!(info.flags, 0);
        assert_eq!(info.target_file_time, 0);
        assert_eq!(info.target_hash_algorithm, 0x8004);
        assert_eq!(info.target_hash.len(), 20);
    }
}

#[test]
fn created_pa30_uses_source_and_overlapping_output_matches() {
    let limits = Limits::default();
    let source: Vec<u8> = (0..65536)
        .map(|i| ((i * 109 + i / 251) & 255) as u8)
        .collect();
    let mut target = source.clone();
    target[100] ^= 0x80;
    target.extend_from_slice(&source[1000..10000]);
    let delta = create_pa30(&source, &target, &limits).unwrap();
    assert_eq!(apply_pa30(&source, &delta, &limits).unwrap(), target);
    assert!(delta.len() < target.len() / 8, "{} bytes", delta.len());
    assert!(apply_pa30(&vec![0; source.len()], &delta, &limits).is_err());
    let target = vec![b'a'; 16384];
    let delta = create_pa30(&[], &target, &limits).unwrap();
    assert_eq!(apply_pa30(&[], &delta, &limits).unwrap(), target);
    assert!(delta.len() < 128);
}

#[test]
fn created_pa30_extended_source_offsets_are_compact_and_obey_window_limit() {
    let mut source = vec![0u8; 600000];
    source[..16].copy_from_slice(b"0123456789abcdef");
    let target = &source[..16];
    let limits = Limits::default();
    let delta = create_pa30(&source, target, &limits).unwrap();
    assert_eq!(apply_pa30(&source, &delta, &limits).unwrap(), target);
    assert!(delta.len() < 64);
    let bounded = Limits {
        max_window_bytes: 16,
        ..limits
    };
    let literals = create_pa30(&source, target, &bounded).unwrap();
    assert_eq!(apply_pa30(&source, &literals, &bounded).unwrap(), target);
    assert!(literals.len() > delta.len());
}

#[test]
fn created_pa30_long_lengths_and_every_truncation_are_checked() {
    let limits = Limits::default();
    for length in [4, 8, 9, 263, 264, 520, 65536, (1 << 20) + 7] {
        let target = vec![b'Q'; length];
        let delta = create_pa30(&[], &target, &limits).unwrap();
        assert_eq!(
            apply_pa30(&[], &delta, &limits).unwrap(),
            target,
            "length {length}"
        );
        for truncated in 0..delta.len() {
            assert!(apply_pa30(&[], &delta[..truncated], &limits).is_err());
        }
    }
}

#[test]
fn created_pa30_respects_source_target_patch_parameter_and_window_bounds() {
    for limits in [
        Limits {
            max_source_bytes: 2,
            ..Limits::default()
        },
        Limits {
            max_output_bytes: 2,
            ..Limits::default()
        },
        Limits {
            max_patch_bytes: 2,
            ..Limits::default()
        },
        Limits {
            max_parameter_bytes: 2,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            create_pa30(b"abc", b"abc", &limits),
            Err(Error::Limit(_))
        ));
    }
    let limits = Limits {
        max_window_bytes: 0,
        ..Limits::default()
    };
    let delta = create_pa30(b"abcdefgh", b"abcdefghabcdefgh", &limits).unwrap();
    assert_eq!(
        apply_pa30(b"abcdefgh", &delta, &limits).unwrap(),
        b"abcdefghabcdefgh"
    );
}

#[test]
fn random_created_pa30_roundtrips_source_mutations_and_reordering() {
    let limits = Limits::default();
    let mut state = 0x5041_3330_2026_u64;
    for size in [0, 1, 3, 7, 31, 257, 4096, 65536] {
        let mut source = vec![0; size];
        for byte in &mut source {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let mut target = source.clone();
        if size > 0 {
            target[size / 2] ^= 0x40;
            target.rotate_left(size / 3);
        }
        target.extend_from_slice(b"new suffix new suffix");
        let delta = create_pa30(&source, &target, &limits).unwrap();
        assert_eq!(
            apply_pa30(&source, &delta, &limits).unwrap(),
            target,
            "size {size}"
        );
    }
}
