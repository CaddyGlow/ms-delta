#![cfg(feature = "cli")]
use sha2::{Digest, Sha256};
use std::{fs, process::Command};

const PA30: &[u8] = include_bytes!("../docs/fixtures/pa30-native/empty-literal.delta");
const LZXD: &[u8] = include_bytes!("../docs/fixtures/dependencies/ms-compress/official-abc.lzxd");

#[test]
fn pe_creation_cli_selects_a_pe_graph_and_rejects_lzxd_before_publication() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/fixtures/pa30-pe32-native/native-i386");
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("patch.pa30");
    let missing_source = Command::new(env!("CARGO_BIN_EXE_ms-delta"))
        .args(["create", "--pe", "--format", "pa30", "--target"])
        .arg(root.join("target.exe"))
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!missing_source.status.success());
    assert!(!output.exists());
    let run = |format| {
        Command::new(env!("CARGO_BIN_EXE_ms-delta"))
            .args(["create", "--pe", "--format", format, "--source"])
            .arg(root.join("source.exe"))
            .arg("--target")
            .arg(root.join("target.exe"))
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
    };
    assert!(!run("lzxd").status.success());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    let result = run("pa30");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let patch = fs::read(&output).unwrap();
    let info = ms_delta::pa30::inspect_pa30(&patch, &ms_delta::Limits::default()).unwrap();
    assert_eq!(info.file_type, 2);
    assert_eq!(
        ms_delta::pa30::apply_pa30(
            &fs::read(root.join("source.exe")).unwrap(),
            &patch,
            &ms_delta::Limits::default()
        )
        .unwrap(),
        fs::read(root.join("target.exe")).unwrap()
    );
    assert!(!run("pa30").status.success());
    assert_eq!(fs::read(&output).unwrap(), patch);
}

#[test]
fn created_patches_reconstruct_all_formats_and_preserve_inputs() {
    for format in ["pa30", "pa31", "lzxd"] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let target = dir.path().join("target.bin");
        let patch = dir.path().join("created.delta");
        let output = dir.path().join("reconstructed.bin");
        let original: Vec<u8> = (0..32768).map(|index| (index * 29) as u8).collect();
        let mut expected = original.repeat(2);
        expected[100] ^= 0x80;
        expected.push(0x39);
        fs::write(&source, &original).unwrap();
        fs::write(&target, &expected).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_ms-delta"))
            .args(["create", "--format", format, "--source"])
            .arg(&source)
            .arg("--target")
            .arg(&target)
            .arg("--output")
            .arg(&patch)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_ms-delta"));
        command
            .args(["apply", "--format", format, "--source"])
            .arg(&source)
            .arg("--delta")
            .arg(&patch)
            .arg("--output")
            .arg(&output);
        if format == "lzxd" {
            command.args(["--target-size", "65537", "--window-order", "17"]);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&output).unwrap(), expected);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(&target).unwrap(), expected);
        assert!(fs::metadata(patch).unwrap().len() < expected.len() as u64);
    }
}

#[test]
fn create_refuses_existing_outputs_and_invalid_limits_without_partial_files() {
    for format in ["pa30", "lzxd"] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.bin");
        let output = dir.path().join("patch.delta");
        fs::write(&target, b"target").unwrap();
        fs::write(&output, b"preserve").unwrap();
        let run = || {
            Command::new(env!("CARGO_BIN_EXE_ms-delta"))
                .args(["create", "--format", format, "--target"])
                .arg(&target)
                .arg("--output")
                .arg(&output)
                .args(["--max-output-bytes", "1"])
                .output()
                .unwrap()
        };
        assert!(!run().status.success());
        assert_eq!(fs::read(&output).unwrap(), b"preserve");
        fs::remove_file(&output).unwrap();
        assert!(!run().status.success());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(fs::read(&target).unwrap(), b"target");
    }
}

#[test]
fn both_cli_formats_reconstruct_independent_abc_and_preserve_patch() {
    for (format, bytes) in [("pa30", PA30), ("lzxd", LZXD)] {
        let dir = tempfile::tempdir().unwrap();
        let patch = dir.path().join("input.delta");
        let output = dir.path().join("target.bin");
        fs::write(&patch, bytes).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ms-delta"));
        cmd.args(["apply", "--format", format, "--delta"])
            .arg(&patch)
            .arg("--output")
            .arg(&output)
            .args([
                "--expected-sha256",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ]);
        if format == "lzxd" {
            cmd.args(["--target-size", "3", "--window-order", "17"]);
        }
        let result = cmd.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(output).unwrap(), b"abc");
        assert_eq!(fs::read(patch).unwrap(), bytes);
    }
}

#[test]
fn wrong_expected_hash_never_publishes_output_or_temporary_files() {
    let dir = tempfile::tempdir().unwrap();
    let patch = dir.path().join("input.delta");
    let output = dir.path().join("target.bin");
    fs::write(&patch, PA30).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ms-delta"))
        .args(["apply", "--format", "pa30", "--delta"])
        .arg(&patch)
        .arg("--output")
        .arg(&output)
        .arg("--expected-sha256")
        .arg("00".repeat(32))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    assert_eq!(fs::read(patch).unwrap(), PA30);
}

#[test]
fn existing_output_is_preserved_and_input_limit_prevents_publication() {
    let dir = tempfile::tempdir().unwrap();
    let patch = dir.path().join("input.delta");
    let output = dir.path().join("target.bin");
    fs::write(&patch, PA30).unwrap();
    fs::write(&output, b"retain").unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ms-delta"))
            .args(["apply", "--format", "pa30", "--delta"])
            .arg(&patch)
            .arg("--output")
            .arg(&output)
            .args(["--max-input-bytes", "1"])
            .output()
            .unwrap()
    };
    assert!(!run().status.success());
    assert_eq!(fs::read(&output).unwrap(), b"retain");
    fs::remove_file(&output).unwrap();
    assert!(!run().status.success());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn inspection_reports_intrinsic_pa30_hash_without_creating_files() {
    let dir = tempfile::tempdir().unwrap();
    let patch = dir.path().join("input.delta");
    fs::write(&patch, PA30).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ms-delta"))
        .arg("inspect")
        .arg("--delta")
        .arg(&patch)
        .output()
        .unwrap();
    assert!(result.status.success());
    let info: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(info["target_size"], 3);
    assert_eq!(info["file_type"], 1);
    assert_eq!(info["target_hash_algorithm"], 0x8003);
    assert_eq!(
        Sha256::digest(fs::read(patch).unwrap()),
        Sha256::digest(PA30)
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn dangling_output_symlink_is_not_replaced_or_followed() {
    let dir = tempfile::tempdir().unwrap();
    let patch = dir.path().join("input.delta");
    let referent = dir.path().join("absent.bin");
    let output = dir.path().join("target.bin");
    fs::write(&patch, PA30).unwrap();
    std::os::unix::fs::symlink(&referent, &output).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ms-delta"))
        .args(["apply", "--format", "pa30", "--delta"])
        .arg(&patch)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!referent.exists());
    assert_eq!(fs::read_link(output).unwrap(), referent);
}

#[test]
fn pa19_pe_and_e8_creation_cli_round_trips_and_validates_flags() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/fixtures/pa30-pe32-native/native-i386");
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("patch.pa19");
    let create = |extra: &[&str], format: &str| {
        Command::new(env!("CARGO_BIN_EXE_ms-delta"))
            .args(["create", "--format", format])
            .args(extra)
            .arg("--source")
            .arg(root.join("source.exe"))
            .arg("--target")
            .arg(root.join("target.exe"))
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
    };
    // PA19 flags are rejected for other formats before anything is written.
    assert!(!create(&["--e8", "on"], "pa30").status.success());
    assert!(!create(&["--e8", "auto"], "lzxd").status.success());
    assert!(!output.exists());
    for extra in [&["--pe"][..], &["--pe", "--e8", "auto"], &["--e8", "on"]] {
        let _ = fs::remove_file(&output);
        let result = create(extra, "pa19");
        assert!(
            result.status.success(),
            "{extra:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let patch = fs::read(&output).unwrap();
        assert_eq!(
            ms_delta::pa19::apply_pa19(
                &fs::read(root.join("source.exe")).unwrap(),
                &patch,
                &ms_delta::Limits::default()
            )
            .unwrap(),
            fs::read(root.join("target.exe")).unwrap(),
            "{extra:?}"
        );
    }
}
