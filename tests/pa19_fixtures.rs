#![cfg(feature = "pa19")]

//! PA19 patches created by the real `mspatchc.dll` from synthetic files (see
//! `tests/fixtures/pa19/README.md`) must be reconstructed byte for byte.

use ms_delta::Limits;
use ms_delta::pa19::{apply_pa19, inspect_pa19};
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pa19")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn cases() -> Vec<(String, String, Vec<String>, String)> {
    let manifest: serde_json::Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    manifest
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let text = |key: &str| case[key].as_str().unwrap().to_string();
            let olds = case["olds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|old| old.as_str().unwrap().to_string())
                .collect();
            (text("name"), text("patch"), olds, text("new"))
        })
        .collect()
}

#[test]
fn mspatchc_patches_reconstruct_the_target_from_every_old_file() {
    let limits = Limits::default();
    for (name, patch, olds, new) in cases() {
        let (patch, new) = (read(&patch), read(&new));
        for old in olds {
            let output = apply_pa19(&read(&old), &patch, &limits)
                .unwrap_or_else(|error| panic!("{name} from {old}: {error}"));
            assert!(output == new, "{name} from {old}: output differs");
        }
    }
}

#[test]
fn headers_expose_the_option_sets_that_created_them() {
    let limits = Limits::default();
    let info = |name: &str| inspect_pa19(&read(name), &limits).unwrap();
    let ignore = info("fx_ignore.pa19");
    assert_eq!(ignore.sources[0].ignore_ranges.len(), 2);
    assert_eq!(ignore.sources[0].ignore_ranges[0].offset, 1000);
    assert_eq!(ignore.sources[0].ignore_ranges[1].length, 300);
    let retain = info("fx_retain.pa19");
    assert_eq!(retain.sources[0].retain_ranges.len(), 1);
    assert_eq!(
        (
            retain.sources[0].retain_ranges[0].old_offset,
            retain.sources[0].retain_ranges[0].new_offset,
            retain.sources[0].retain_ranges[0].length
        ),
        (2000, 7000, 400)
    );
    assert_eq!(info("fx_multi.pa19").sources.len(), 3);
    let interleaved = info("fx_ilv_two.pa19");
    assert_eq!(interleaved.flags & 0x4000_0000, 0x4000_0000);
    let groups = &interleaved.sources[0].interleave;
    assert_eq!(groups.len(), 2);
    assert_eq!(
        (
            groups[0].old_offset,
            groups[0].old_length,
            groups[0].new_length
        ),
        (0, 40000, 32768)
    );
    assert_eq!(groups[1].old_offset, 5000);
    assert_eq!(
        u64::from(groups[0].new_length) + u64::from(groups[1].new_length),
        interleaved.target_size as u64
    );
}

#[test]
fn a_wrong_old_file_is_rejected_by_the_old_file_checks() {
    let limits = Limits::default();
    let patch = read("fx_default.pa19");
    // same size, different bytes: the old-file CRC does not match
    let mut wrong = read("fx_old.bin");
    wrong[100] ^= 0xff;
    assert!(apply_pa19(&wrong, &patch, &limits).is_err());
    // a different size matches no alternative
    assert!(apply_pa19(&read("fx_old2.bin"), &patch, &limits).is_err());
    // damage inside the patch is caught by the trailer CRC
    let mut damaged = patch.clone();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    assert!(apply_pa19(&read("fx_old.bin"), &damaged, &limits).is_err());
}
