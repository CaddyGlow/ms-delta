#![cfg(feature = "pa30")]

use ms_delta::{
    Limits,
    pa30::{apply_pa30, inspect_pa30},
};
use std::{fs, path::Path};

#[test]
fn native_pe32_anycpu_and_legacy_managed_graphs_reconstruct_exact_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-pe32-native");
    let cases: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    let mut count = 0;
    for case in cases.as_array().unwrap() {
        assert_eq!(case["success"], true);
        assert_eq!(case["native_roundtrip"], true);
        let directory = root
            .join(case["family"].as_str().unwrap())
            .join(case["platform"].as_str().unwrap());
        let source = fs::read(directory.join("source.dll")).unwrap();
        let target = fs::read(directory.join("target.dll")).unwrap();
        let delta = fs::read(root.join(case["path"].as_str().unwrap())).unwrap();
        let info = inspect_pa30(&delta, &Limits::default()).unwrap();
        assert_eq!(info.file_type, case["file_type"].as_u64().unwrap());
        assert_eq!(info.flags, case["flags"].as_u64().unwrap());
        let (basis, expected) = if case["direction"] == "reverse" {
            (&target, &source)
        } else {
            (&source, &target)
        };
        let actual = apply_pa30(basis, &delta, &Limits::default());
        if !matches!(&actual, Ok(bytes) if bytes == expected) {
            failures.push(format!(
                "{}: {:?}",
                case["path"],
                actual.as_ref().map(Vec::len)
            ));
        }
        count += 1;
    }
    assert_eq!(count, 250);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn pe32_truncations_and_mutations_fail_or_reproduce_the_target() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-pe32-native/basic/anycpu");
    let source = fs::read(root.join("source.dll")).unwrap();
    let target = fs::read(root.join("target.dll")).unwrap();
    for graph in ["legacy", "cli4"] {
        let delta = fs::read(root.join(graph).join("forward-default.delta")).unwrap();
        for length in 0..delta.len() {
            assert!(apply_pa30(&source, &delta[..length], &Limits::default()).is_err());
        }
        for index in (0..delta.len()).step_by(3) {
            let mut mutated = delta.clone();
            mutated[index] ^= 0x80;
            if let Ok(bytes) = apply_pa30(&source, &mutated, &Limits::default()) {
                assert_eq!(bytes, target);
            }
        }
        for length in (0..source.len()).step_by(31) {
            assert!(apply_pa30(&source[..length], &delta, &Limits::default()).is_err());
        }
    }
}

#[test]
fn native_i386_transforms_and_five_column_legacy_metadata_reconstruct_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-pe32-native");
    let mut failures = Vec::new();
    for (manifest, directory, extension, count) in [
        ("unmanaged-manifest.json", "native-i386", "exe", 28),
        ("legacy-schema/manifest.json", "legacy-schema", "dll", 10),
    ] {
        let source = fs::read(root.join(directory).join(format!("source.{extension}"))).unwrap();
        let target = fs::read(root.join(directory).join(format!("target.{extension}"))).unwrap();
        let cases: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join(manifest)).unwrap()).unwrap();
        assert_eq!(cases.as_array().unwrap().len(), count);
        for case in cases.as_array().unwrap() {
            assert_eq!(case["success"], true);
            assert_eq!(case["native_roundtrip"], true);
            let delta = fs::read(root.join(case["path"].as_str().unwrap())).unwrap();
            let info = inspect_pa30(&delta, &Limits::default()).unwrap();
            assert_eq!(info.file_type, 2);
            assert_eq!(info.flags, case["flags"].as_u64().unwrap());
            let (basis, expected) = if case["direction"] == "reverse" {
                (&target, &source)
            } else {
                (&source, &target)
            };
            let actual = apply_pa30(basis, &delta, &Limits::default());
            if !matches!(&actual, Ok(bytes) if bytes == expected) {
                failures.push(format!(
                    "{}: {:?}",
                    case["path"],
                    actual.as_ref().map(Vec::len)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
