use ms_delta::{Limits, apply_lzxd, create_lzxd};

fn roundtrip(source: &[u8], target: &[u8], order: u8) -> Vec<u8> {
    let patch = create_lzxd(source, target, order, &Limits::default()).unwrap();
    assert_eq!(
        apply_lzxd(source, &patch, target.len(), order, &Limits::default()).unwrap(),
        target
    );
    patch
}

#[test]
fn frame_boundaries_random_and_repeated_roundtrip() {
    let mut state = 5071u32;
    let random: Vec<u8> = (0..70000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    for size in [0, 1, 3, 255, 256, 257, 32767, 32768, 32769, 65536, 70000] {
        roundtrip(&[], &random[..size], 17);
        let repeated = vec![b'a'; size];
        let patch = roundtrip(&[], &repeated, 17);
        if size > 10000 {
            assert!(patch.len() < size / 4);
        }
    }
}

#[test]
fn reference_matches_cover_all_windows_and_distant_offsets() {
    for order in 17..=25 {
        let mut state = 19u32;
        let source: Vec<u8> = (0..(1usize << order) - 3)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let mut target = source[..4096].to_vec();
        target.extend_from_slice(&source[source.len() - 4096..]);
        roundtrip(&source, &target, order);
    }
}

#[test]
fn resource_limits_and_reference_bounds_fail_closed() {
    for limits in [
        Limits {
            max_source_bytes: 0,
            ..Limits::default()
        },
        Limits {
            max_output_bytes: 0,
            ..Limits::default()
        },
        Limits {
            max_patch_bytes: 1,
            ..Limits::default()
        },
        Limits {
            max_parameter_bytes: 1,
            ..Limits::default()
        },
    ] {
        assert!(create_lzxd(b"a", b"b", 17, &limits).is_err());
    }
    assert!(create_lzxd(&vec![0; (1 << 17) - 2], b"b", 17, &Limits::default()).is_err());
    assert!(create_lzxd(&[], b"b", 16, &Limits::default()).is_err());
}

/// Independent decoder is built externally from pinned libmspack source.
#[test]
#[ignore = "requires LZXD_ORACLE pointing to independent libmspack wrapper"]
fn independent_libmspack_decodes_created_streams() {
    let oracle = std::env::var_os("LZXD_ORACLE").expect("LZXD_ORACLE");
    let directory = std::env::temp_dir().join(format!("ms-delta-encoder-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source: Vec<u8> = (0..120000)
        .map(|i| ((i * 197 + i / 17) & 255) as u8)
        .collect();
    let mut target = source[1234..3334].to_vec();
    target.extend_from_slice(&vec![b'z'; 70000]);
    target.extend((0..40000).map(|i| ((i * 139 + i / 31) & 255) as u8));
    let patch_path = directory.join("delta");
    let source_path = directory.join("source");
    let output_path = directory.join("output");
    for order in 17..=25 {
        let patch = roundtrip(&source, &target, order);
        std::fs::write(&patch_path, patch).unwrap();
        std::fs::write(&source_path, &source).unwrap();
        let status = std::process::Command::new(&oracle)
            .arg(&patch_path)
            .arg(&source_path)
            .arg(&output_path)
            .arg(order.to_string())
            .arg(target.len().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read(&output_path).unwrap(), target);
    }
    let mut distant_source = vec![0; 20_000_000];
    let mut state = 5071u32;
    for value in &mut distant_source[..4096] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *value = state as u8;
    }
    let distant_target = &distant_source[..4096];
    let patch = roundtrip(&distant_source, distant_target, 25);
    assert!(patch.len() < distant_target.len());
    std::fs::write(&patch_path, patch).unwrap();
    std::fs::write(&source_path, &distant_source).unwrap();
    let status = std::process::Command::new(&oracle)
        .arg(&patch_path)
        .arg(&source_path)
        .arg(&output_path)
        .arg("25")
        .arg("4096")
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read(&output_path).unwrap(), distant_target);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn retained_independent_oracle_vectors_regenerate_exactly() {
    use sha2::{Digest, Sha256};
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/fixtures/lzxd-created-libmspack");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("oracle-results.json")).unwrap())
            .unwrap();
    for case in manifest["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let order = case["window_order"].as_u64().unwrap() as u8;
        let source = std::fs::read(directory.join(format!("{name}.source"))).unwrap();
        let target = std::fs::read(directory.join(format!("{name}.target"))).unwrap();
        let patch = std::fs::read(directory.join(format!("{name}-{order}.delta"))).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&target)),
            case["target_sha256"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&patch)),
            case["delta_sha256"].as_str().unwrap()
        );
        assert_eq!(roundtrip(&source, &target, order), patch);
    }
}
