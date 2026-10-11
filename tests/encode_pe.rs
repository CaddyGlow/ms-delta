use ms_delta::{
    Limits,
    pa30::{apply_pa30, create_pa30_pe, inspect_pa30},
};
use std::{fs, path::Path};

fn originals() -> [(Vec<u8>, Vec<u8>, u64); 2] {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures");
    [
        (
            fs::read(root.join("pa30-pe32-native/native-i386/source.exe")).unwrap(),
            fs::read(root.join("pa30-pe32-native/native-i386/target.exe")).unwrap(),
            2,
        ),
        (
            fs::read(root.join("pa30-pe-native/source.exe")).unwrap(),
            fs::read(root.join("pa30-pe-native/shifted.exe")).unwrap(),
            8,
        ),
    ]
}

#[test]
fn pe_creation_selects_architecture_and_reconstructs_shifted_images_in_both_directions() {
    for (source, target, graph) in originals() {
        for (basis, expected) in [(&source, &target), (&target, &source)] {
            let delta = create_pa30_pe(basis, expected, &Limits::default()).unwrap();
            let info = inspect_pa30(&delta, &Limits::default()).unwrap();
            assert_eq!(info.file_type, graph);
            assert_ne!(info.preprocessing_size, 0);
            assert_eq!(info.target_hash_algorithm, 0x8004);
            assert_eq!(
                apply_pa30(basis, &delta, &Limits::default()).unwrap(),
                *expected
            );
            assert_eq!(
                delta,
                create_pa30_pe(basis, expected, &Limits::default()).unwrap()
            );
        }
    }
}

#[test]
fn native_verified_pe_patches_regenerate_exactly_and_relocations_reduce_pointer_heavy_cases() {
    use sha2::{Digest, Sha256};
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-created-pe-native");
    let cases: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 14);
    let mut improvements = 0;
    for case in cases.as_array().unwrap() {
        let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
        let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
        let native = &case["native_oracle"];
        assert_eq!(native["success"], true);
        assert_eq!(native["native_target_matches"], true);
        assert_eq!(native["native_file_type_set"], 15);
        assert_eq!(native["source_sha256_after"], case["source_sha256"]);
        assert_eq!(
            format!("{:x}", Sha256::digest(&source)),
            case["source_sha256"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&target)),
            case["target_sha256"].as_str().unwrap()
        );
        let delta = create_pa30_pe(&source, &target, &Limits::default()).unwrap();
        assert_eq!(
            delta,
            fs::read(root.join(case["delta"].as_str().unwrap())).unwrap()
        );
        let info = inspect_pa30(&delta, &Limits::default()).unwrap();
        assert_eq!(info.file_type, native["native_file_type"].as_u64().unwrap());
        assert_eq!(info.flags, native["native_flags"].as_u64().unwrap());
        assert_eq!(
            apply_pa30(&source, &delta, &Limits::default()).unwrap(),
            target
        );
        if case["saved_bytes"].as_i64().unwrap() > 0 {
            improvements += 1;
            let raw = ms_delta::pa30::create_pa30(&source, &target, &Limits::default()).unwrap();
            assert_eq!(
                raw,
                fs::read(root.join(case["raw_delta"].as_str().unwrap())).unwrap()
            );
            assert!(delta.len() < raw.len());
        }
    }
    assert!(improvements >= 4);
}

#[test]
fn pe_creation_rejects_invalid_architecture_mixed_inputs_and_resource_limits() {
    let [(source32, target32, _), (source64, target64, _)] = originals();
    assert!(create_pa30_pe(&source32, &target64, &Limits::default()).is_err());
    assert!(create_pa30_pe(&source64, &target32, &Limits::default()).is_err());
    assert!(create_pa30_pe(b"not PE", &target32, &Limits::default()).is_err());
    let managed = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa30-pe32-native/basic/anycpu/source.dll"),
    )
    .unwrap();
    assert!(create_pa30_pe(&managed, &target32, &Limits::default()).is_err());
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
        assert!(create_pa30_pe(&source32, &target32, &limits).is_err());
    }
    for length in (0..source32.len()).step_by(31) {
        assert!(create_pa30_pe(&source32[..length], &target32, &Limits::default()).is_err());
        assert!(
            create_pa30_pe(
                &source32,
                &target32[..length.min(target32.len())],
                &Limits::default()
            )
            .is_err()
        );
    }
}
