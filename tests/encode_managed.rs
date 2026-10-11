#![cfg(feature = "pa30")]

use ms_delta::{
    Limits,
    pa30::{apply_pa30, create_pa30_pe, inspect_pa30},
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[test]
fn native_verified_managed_creation_regenerates_exact_bytes_and_preserves_architecture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-created-cli-native");
    let cases: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let cases = cases.as_array().unwrap();
    assert!(cases.len() >= 36);
    let mut graphs = std::collections::BTreeSet::new();
    for case in cases {
        let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
        let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
        let native = &case["native_oracle"];
        assert_eq!(native["success"], true, "{}", case["name"]);
        assert_eq!(native["native_target_matches"], true);
        assert_eq!(native["native_file_type_set"], 245);
        assert_eq!(native["source_sha256_after"], case["source_sha256"]);
        assert_eq!(
            format!("{:x}", Sha256::digest(&source)),
            case["source_sha256"]
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&target)),
            case["target_sha256"]
        );
        let delta = create_pa30_pe(&source, &target, &Limits::default()).unwrap();
        assert_eq!(
            delta,
            fs::read(root.join(case["delta"].as_str().unwrap())).unwrap(),
            "{}",
            case["name"]
        );
        let info = inspect_pa30(&delta, &Limits::default()).unwrap();
        assert_eq!(info.file_type, native["native_file_type"].as_u64().unwrap());
        assert_eq!(info.flags, native["native_flags"].as_u64().unwrap());
        assert_eq!(info.target_hash_algorithm, 0x8004);
        graphs.insert(info.file_type);
        assert_eq!(
            apply_pa30(&source, &delta, &Limits::default()).unwrap(),
            target
        );
    }
    assert_eq!(graphs, [16, 32].into_iter().collect());
}

#[test]
fn managed_creation_rejects_unbacked_native_headers_and_entry_points() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/fixtures/pa30-created-cli-native/basic/anycpu");
    let source = fs::read(root.join("source.dll")).unwrap();
    let target = fs::read(root.join("target.dll")).unwrap();
    let word = |offset| u32::from_le_bytes(source[offset..offset + 4].try_into().unwrap()) as usize;
    let nt = word(60);
    let optional = nt + 24;
    let rva = word(optional + 96 + 14 * 8);
    let count = u16::from_le_bytes(source[nt + 6..nt + 8].try_into().unwrap()) as usize;
    let optional_size = u16::from_le_bytes(source[nt + 20..nt + 22].try_into().unwrap()) as usize;
    let header = (0..count)
        .find_map(|index| {
            let section = optional + optional_size + index * 40;
            let start = word(section + 12);
            let size = word(section + 16);
            (rva >= start && rva - start < size).then(|| word(section + 20) + rva - start)
        })
        .unwrap();
    for (offset, value) in [(header + 64, 1u32), (header + 68, 1)] {
        let mut invalid = source.clone();
        invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(create_pa30_pe(&invalid, &target, &Limits::default()).is_err());
    }
    let mut invalid = source;
    invalid[header + 16..header + 20].copy_from_slice(&0x11u32.to_le_bytes());
    invalid[header + 20..header + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(create_pa30_pe(&invalid, &target, &Limits::default()).is_err());
}
