use ms_delta::{
    Limits,
    pa30::{apply_pa31, create_pa31, create_pa31_pe, inspect_pa31},
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[test]
fn native_pa31_vectors_reconstruct_exact_targets_and_enforce_bounds() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa31-native");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let cases = manifest.as_array().unwrap();
    assert!(cases.len() >= 16);
    for case in cases {
        let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
        let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
        let patch = fs::read(root.join(case["delta"].as_str().unwrap())).unwrap();
        assert_eq!(case["success"], true);
        assert_eq!(
            format!("{:x}", Sha256::digest(&target)),
            case["target_sha256"]
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&source)),
            case["source_sha256_after"]
        );
        let info = inspect_pa31(&patch, &Limits::default()).unwrap();
        assert_eq!(info.metadata.target_size, target.len());
        assert_eq!(
            apply_pa31(&source, &patch, &Limits::default()).unwrap(),
            target,
            "{}",
            case["name"]
        );
        let limits = Limits {
            max_patch_bytes: patch.len() - 1,
            ..Limits::default()
        };
        assert!(apply_pa31(&source, &patch, &limits).is_err());
        if !target.is_empty() {
            let limits = Limits {
                max_output_bytes: target.len() - 1,
                ..Limits::default()
            };
            assert!(apply_pa31(&source, &patch, &limits).is_err());
        }
    }
}

#[test]
fn pa31_creation_is_deterministic_and_rejects_wrong_sources_and_truncated_headers() {
    let source = b"original source words and a retained reference";
    let target = b"updated source words and a retained reference";
    let patch = create_pa31(source, target, &Limits::default()).unwrap();
    assert!(patch.starts_with(b"PA31"));
    assert_eq!(
        patch,
        create_pa31(source, target, &Limits::default()).unwrap()
    );
    assert_eq!(
        apply_pa31(source, &patch, &Limits::default()).unwrap(),
        target
    );
    assert!(apply_pa31(b"wrong source", &patch, &Limits::default()).is_err());
    for length in 0..patch.len() {
        assert!(apply_pa31(source, &patch[..length], &Limits::default()).is_err());
    }
}

#[test]
fn rust_created_pa31_native_vectors_regenerate_exactly_with_source_integrity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa31-created-native");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let cases = manifest.as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for case in cases {
        let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
        let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
        let native = &case["native_oracle"];
        assert_eq!(native["success"], true);
        assert_eq!(native["native_target_matches"], true);
        assert_eq!(native["source_sha256_after"], case["source_sha256"]);
        let patch = if case["pe"].as_bool().unwrap() {
            create_pa31_pe(&source, &target, &Limits::default()).unwrap()
        } else {
            create_pa31(&source, &target, &Limits::default()).unwrap()
        };
        assert_eq!(
            patch,
            fs::read(root.join(case["delta"].as_str().unwrap())).unwrap()
        );
        let info = inspect_pa31(&patch, &Limits::default()).unwrap();
        assert_eq!(info.metadata.target_hash_algorithm, 0x800c);
        assert_eq!(info.source_hash, Sha256::digest(&source).as_slice());
        assert_eq!(
            info.metadata.flags,
            native["native_flags"].as_u64().unwrap()
        );
        assert_eq!(
            apply_pa31(&source, &patch, &Limits::default()).unwrap(),
            target
        );
    }
}
