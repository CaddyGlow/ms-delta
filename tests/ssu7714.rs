//! Genuine native oracle regressions; external evidence is intentionally retained
//! separately rather than embedding multi-megabyte Microsoft binaries in tests.
use ms_delta::{Limits, pa30::apply_pa30};
use sha2::{Digest, Sha256};
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[test]
#[ignore = "requires independently pinned native SSU7714 evidence at WINDOWS_DELTA_SSU7714_ROOT"]
fn exact_ssu7714_oracles_match_intrinsic_hash_and_native_bytes() {
    let root = std::path::PathBuf::from(
        std::env::var_os("WINDOWS_DELTA_SSU7714_ROOT").expect("set M4 evidence root"),
    );
    for (target, patch, basis, patch_hash, basis_hash, target_hash) in [
        (
            "63",
            "31",
            "70",
            "ef1ccf8951a326d1fa6efc1f6307cf731ca337948c13f0c032c6a0190fd1b5be",
            "033a44ba21a42af8e0fac45d59ce45b15e6643a2314e174756a6af92fb410c89",
            "7d743dd2fb312ff38c7d053f5d25aabecb8ab2559e84f604b0bda052ca92f06c",
        ),
        (
            "122",
            "98",
            "106",
            "5dbac0cec1c45ae456c862e96ed92ac81caaf2d24f95f0a84555ddeabc486183",
            "11166c5b21700b31c7e77964164b26c579059b81c9195e9c28a90334974a4202",
            "23a6f7f4ed9c644a12bfc01ee696c5d3f6274ef70c2ce397ecfe9ce7a4892971",
        ),
    ] {
        let patch = std::fs::read(
            root.join("admission/raw-deltas")
                .join(format!("{patch}.pa30")),
        )
        .unwrap();
        let basis = std::fs::read(
            root.join("admission/authenticated-payloads")
                .join(format!("{basis}.bin")),
        )
        .unwrap();
        let native = std::fs::read(
            root.join("native-stage-probe/oracles/native-delta")
                .join(format!("target-{target}.dll")),
        )
        .unwrap();
        assert_eq!(hash(&patch), patch_hash);
        assert_eq!(hash(&basis), basis_hash);
        assert_eq!(hash(&native), target_hash);
        let actual = apply_pa30(&basis, &patch, &Limits::default()).unwrap();
        assert_eq!(actual, native, "native oracle {target}");
        assert_eq!(hash(&actual), target_hash);
    }
}
