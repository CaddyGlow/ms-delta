use ms_delta::{
    Limits,
    pa30::{apply_pa30, apply_pa31, create_pa30_pe, create_pa31_pe},
};
use std::{fs, path::Path};

#[test]
fn native_binary_difference_vectors_decode_pa30_and_pa31_with_nonempty_sources() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures");
    for directory in ["pa30-bsdiff-native", "pa31-native/bsdiff"] {
        let root = base.join(directory);
        let cases: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        for case in cases.as_array().unwrap() {
            if case["success"] != true {
                continue;
            }
            let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
            let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
            let delta = fs::read(root.join(case["delta"].as_str().unwrap())).unwrap();
            let output = if delta.starts_with(b"PA31") {
                apply_pa31(&source, &delta, &Limits::default())
            } else {
                apply_pa30(&source, &delta, &Limits::default())
            };
            assert_eq!(output.unwrap(), target, "{}", case["name"]);
        }
    }
}

#[test]
fn original_mixed_and_ready_to_run_assemblies_reconstruct_across_native_graphs_and_creation() {
    let base =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-managed-native-images");
    for family in ["readytorun", "mixed"] {
        let root = base.join(family);
        let cases: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let mut accepted = 0;
        for case in cases.as_array().unwrap() {
            if case["success"] != true {
                continue;
            }
            let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
            let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
            let delta = fs::read(root.join(case["delta"].as_str().unwrap())).unwrap();
            let output = if delta.starts_with(b"PA31") {
                apply_pa31(&source, &delta, &Limits::default())
            } else {
                apply_pa30(&source, &delta, &Limits::default())
            };
            assert_eq!(output.unwrap(), target, "{}", case["name"]);
            accepted += 1;
        }
        assert_eq!(accepted, 40);
        let source = fs::read(root.join("source.dll")).unwrap();
        let target = fs::read(root.join("target.dll")).unwrap();
        let delta = create_pa30_pe(&source, &target, &Limits::default()).unwrap();
        assert_eq!(
            apply_pa30(&source, &delta, &Limits::default()).unwrap(),
            target
        );
    }
}

#[test]
fn native_verified_managed_and_architecture_creation_regenerates_exact_patches() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures");
    for (directory, count) in [
        ("pa30-managed-native-images/created", 8),
        ("pa30-arm-native/created", 12),
    ] {
        let root = base.join(directory);
        let cases: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(cases.as_array().unwrap().len(), count);
        for case in cases.as_array().unwrap() {
            let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
            let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
            assert_eq!(case["native_oracle"]["success"], true);
            assert_eq!(
                case["native_oracle"]["source_sha256_after"],
                case["source_sha256"]
            );
            let delta = if case["format"] == "pa31" {
                create_pa31_pe(&source, &target, &Limits::default()).unwrap()
            } else {
                create_pa30_pe(&source, &target, &Limits::default()).unwrap()
            };
            assert_eq!(
                delta,
                fs::read(root.join(case["delta"].as_str().unwrap())).unwrap()
            );
        }
    }
}

#[test]
fn native_pa31_arm_and_ia64_transforms_reconstruct_exact_images() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-arm-native");
    for family in ["arm", "arm64", "ia64"] {
        let root = base.join(family).join("pa31");
        let cases: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(cases.as_array().unwrap().len(), 12);
        for case in cases.as_array().unwrap() {
            let source = fs::read(root.join(case["source"].as_str().unwrap())).unwrap();
            let target = fs::read(root.join(case["target"].as_str().unwrap())).unwrap();
            let delta = fs::read(root.join(case["delta"].as_str().unwrap())).unwrap();
            assert_eq!(
                apply_pa31(&source, &delta, &Limits::default()).unwrap(),
                target,
                "{}",
                case["name"]
            );
        }
    }
}
