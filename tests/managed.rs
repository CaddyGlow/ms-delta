#![cfg(feature = "pa30")]

use ms_delta::{Limits, pa30::apply_pa30};
use std::{fs, path::Path};

#[test]
fn native_cli4_managed_flag_matrix_reconstructs_exact_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-cli-native");
    let mut failures = Vec::new();
    for directory in [
        root.clone(),
        root.join("rich"),
        root.join("signatures"),
        root.join("attributes"),
        root.join("wide"),
    ] {
        let source = fs::read(directory.join("source.dll")).unwrap();
        let target = fs::read(directory.join("target.dll")).unwrap();
        for basis in ["empty", "managed"] {
            for flag in [0, 0x200000, 0x400000, 0x600000] {
                let name = format!("{basis}-{flag}");
                let delta = fs::read(directory.join(format!("{name}.delta"))).unwrap();
                let actual = apply_pa30(
                    if basis == "empty" { &[] } else { &source },
                    &delta,
                    &Limits::default(),
                );
                if !matches!(&actual, Ok(bytes) if bytes == &target) {
                    failures.push(format!(
                        "{} {name}: {:?}",
                        directory.display(),
                        actual.as_ref().map(Vec::len)
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn native_cli4_reverse_and_default_flag_matrices_reconstruct_exact_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-cli-native");
    let mut failures = Vec::new();
    let cases: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("extended-manifest.json")).unwrap()).unwrap();
    for case in cases.as_array().unwrap() {
        let family = case["family"].as_str().unwrap();
        let directory = if family == "oracle" {
            root.clone()
        } else {
            root.join(family)
        };
        let source = fs::read(directory.join("source.dll")).unwrap();
        let target = fs::read(directory.join("target.dll")).unwrap();
        let name = case["name"].as_str().unwrap();
        let reverse = case["direction"] == "reverse";
        let delta = fs::read(directory.join(format!("{name}.delta"))).unwrap();
        let actual = apply_pa30(
            if reverse { &target } else { &source },
            &delta,
            &Limits::default(),
        );
        let expected = if reverse { &source } else { &target };
        if !matches!(&actual, Ok(bytes) if bytes == expected) {
            failures.push(format!(
                "{} {name}: {:?}",
                directory.display(),
                actual.as_ref().map(Vec::len)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn managed_fixture_truncations_and_mutations_fail_or_reproduce_target() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-cli-native");
    let source = fs::read(root.join("source.dll")).unwrap();
    let target = fs::read(root.join("target.dll")).unwrap();
    let delta = fs::read(root.join("managed-6291456.delta")).unwrap();
    for length in 0..delta.len() {
        assert!(apply_pa30(&source, &delta[..length], &Limits::default()).is_err());
    }
    for index in (0..delta.len()).step_by(3) {
        let mut mutated = delta.clone();
        mutated[index] ^= 0x80;
        if let Ok(actual) = apply_pa30(&source, &mutated, &Limits::default()) {
            assert_eq!(actual, target);
        }
    }
    for length in (0..source.len()).step_by(31) {
        assert!(apply_pa30(&source[..length], &delta, &Limits::default()).is_err());
    }
}
