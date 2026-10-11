#![cfg(feature = "pa30")]

use ms_delta::{Limits, pa30::apply_pa30};
use std::{fs, path::Path};

#[test]
fn native_amd64_pe_flag_matrices_reconstruct_exact_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-pe-native");
    let source = fs::read(root.join("source.exe")).unwrap();
    let target = fs::read(root.join("target.exe")).unwrap();
    let shifted = fs::read(root.join("shifted.exe")).unwrap();
    let mut failures = Vec::new();
    for manifest in [
        "manifest.json",
        "shifted-manifest.json",
        "legacy-manifest.json",
    ] {
        let content = fs::read_to_string(root.join(manifest)).unwrap();
        let cases: serde_json::Value =
            serde_json::from_str(content.trim_start_matches('\u{feff}')).unwrap();
        for case in cases
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["success"] == true)
        {
            let name = case["name"].as_str().unwrap();
            let basis = if case["basis"] == "empty" {
                &[][..]
            } else {
                &source
            };
            let expected = if manifest == "manifest.json" {
                &target
            } else {
                &shifted
            };
            let delta = fs::read(root.join(format!("{name}.delta"))).unwrap();
            match apply_pa30(basis, &delta, &Limits::default()) {
                Ok(actual) if actual == *expected => {}
                result => failures.push(format!("{name}: {:?}", result.as_ref().map(Vec::len))),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn native_apply_oracle_confirms_duplicate_offsets_do_not_displace_lru_history() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-pe-native/lru");
    let source = fs::read(root.join("deduplicated.source")).unwrap();
    let delta = fs::read(root.join("deduplicated.delta")).unwrap();
    let expected = fs::read(root.join("deduplicated.target")).unwrap();
    assert_eq!(
        apply_pa30(&source, &delta, &Limits::default()).unwrap(),
        expected
    );
}
