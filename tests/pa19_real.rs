//! Real PA19 patches, gated on `WINDOWS_DELTA_PA19_DIR`.
//!
//! The directory holds one subdirectory per case with `patch.pa19` and `new.bin`
//! (the shipped target), plus optionally `old.bin` (the real source, applied and
//! compared byte for byte) and/or `old_current.bin` (a file that already is the
//! target, which exercises the already-current shortcut rather than a decode).
//! Cases without either old file are only inspected. Run with `--release`.

use ms_delta::{
    Error, Limits,
    pa19::{apply_pa19, inspect_pa19},
};
use sha1::{Digest, Sha1};
use std::{fs, path::Path};

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *entry = value;
    }
    let mut register = 0xffff_ffffu32;
    for byte in data {
        register = table[usize::from((register as u8) ^ byte)] ^ (register >> 8);
    }
    !register
}

fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

#[test]
fn real_engine_patches_inspect_and_apply_byte_identically() {
    let Some(root) = std::env::var_os("WINDOWS_DELTA_PA19_DIR") else {
        eprintln!("WINDOWS_DELTA_PA19_DIR is not set; skipping real PA19 patches");
        return;
    };
    let mut cases: Vec<_> = fs::read_dir(Path::new(&root))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    cases.sort();
    assert!(!cases.is_empty(), "no case directories under the root");
    let limits = Limits::default();
    let (mut inspected, mut applied, mut shortcut) = (0, 0, 0);
    for case in cases {
        let name = case.file_name().unwrap().to_string_lossy().into_owned();
        let patch = fs::read(case.join("patch.pa19")).unwrap();
        let new = fs::read(case.join("new.bin")).unwrap();
        let info = inspect_pa19(&patch, &limits).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(info.target_size, new.len(), "{name}");
        assert_eq!(info.target_crc32, crc32(&new), "{name}");
        assert_eq!(
            info.header_size + info.sources.iter().map(|s| s.patch_size).sum::<usize>() + 4,
            patch.len(),
            "{name}: header, streams and trailer must cover the patch"
        );
        inspected += 1;
        let mut broken = patch.clone();
        let middle = broken.len() / 2;
        broken[middle] ^= 1;
        assert!(inspect_pa19(&broken, &limits).is_err(), "{name}");
        if let Ok(old) = fs::read(case.join("old.bin")) {
            assert!(
                info.sources.iter().any(|s| s.old_size == old.len()),
                "{name}"
            );
            let output =
                apply_pa19(&old, &patch, &limits).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(sha1(&output), sha1(&new), "{name}");
            assert_eq!(output, new, "{name}");
            let mut wrong = old.clone();
            let last = wrong.len() - 1;
            wrong[last] ^= 0x40;
            assert!(
                matches!(
                    apply_pa19(&wrong, &patch, &limits),
                    Err(Error::Integrity(_))
                ),
                "{name}: a modified source must be rejected"
            );
            applied += 1;
        }
        if let Ok(current) = fs::read(case.join("old_current.bin")) {
            assert_eq!(current, new, "{name}");
            assert_eq!(
                apply_pa19(&current, &patch, &limits).unwrap(),
                new,
                "{name}"
            );
            shortcut += 1;
        }
    }
    eprintln!("inspected {inspected}, applied {applied}, already-current {shortcut}");
}

/// Patches created by the real `mspatchc.dll` on a Windows guest, gated on
/// `WINDOWS_DELTA_PA19_ORACLE`: a directory with `jobs*.json` (the jobs that were run), the inputs
/// next to them, and `up/` holding the created `<job>.pa19`, the guest-side `old_*` copies and
/// `results_<jobs file>.csv`. Every created patch must reconstruct the new file from each old file
/// byte for byte, whatever options (pass order, interleave, ranges, windows) created it.
#[test]
fn mspatchc_created_patches_reconstruct_the_target() {
    let Some(root) = std::env::var_os("WINDOWS_DELTA_PA19_ORACLE") else {
        eprintln!("WINDOWS_DELTA_PA19_ORACLE is not set; skipping mspatchc oracle patches");
        return;
    };
    let root = Path::new(&root);
    let limits = Limits::default();
    let resolve = |spec: &str| -> std::path::PathBuf {
        let (kind, name) = spec.split_once(':').unwrap();
        if kind == "h" {
            root.join(name)
        } else {
            root.join("up")
                .join(format!("old_{}", name.replace(['\\', '/'], "_")))
        }
    };
    let (mut patches, mut applications, mut skipped) = (0, 0, 0);
    let mut files: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("jobs") && name.ends_with(".json"))
        })
        .collect();
    files.sort();
    for file in files {
        let jobs: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        let csv = root.join("up").join(format!(
            "results_{}.csv",
            file.file_name().unwrap().to_string_lossy()
        ));
        let Ok(results) = fs::read_to_string(&csv) else {
            continue;
        };
        for job in jobs.as_array().unwrap() {
            let name = job["name"].as_str().unwrap();
            let created = results
                .lines()
                .find(|line| line.starts_with(&format!("\"{name}\",\"0\"")))
                .is_some();
            let patch_path = root.join("up").join(format!("{name}.pa19"));
            if !created || !patch_path.exists() {
                skipped += 1;
                continue;
            }
            let patch = fs::read(&patch_path).unwrap();
            let new = fs::read(resolve(job["new"].as_str().unwrap())).unwrap();
            inspect_pa19(&patch, &limits).unwrap_or_else(|e| panic!("{name}: {e}"));
            for old in job["olds"].as_array().unwrap() {
                let old = fs::read(resolve(old.as_str().unwrap())).unwrap();
                let output =
                    apply_pa19(&old, &patch, &limits).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(output == new, "{name}: output differs");
                applications += 1;
            }
            patches += 1;
        }
    }
    eprintln!("oracle patches {patches}, applications {applications}, skipped {skipped}");
    assert!(patches > 0, "no oracle patches found");
}

/// Creation on real file pairs, gated on `WINDOWS_DELTA_PA19_ORACLE`: every job of an
/// `ours_*.json` file in the oracle directory carries `host_old` and `host_new` (paths relative to
/// the directory). Each pair is created with PE and `E8` automatic modes and applied by this crate;
/// the patch must not be larger than the raw patch, and for PE32 pairs most patches must be
/// strictly smaller. (The real `mspatcha.dll` applied the same patches on the guest, see the
/// `pa19` module docs; that cannot run here.)
#[test]
fn created_patches_for_real_pairs_round_trip_and_beat_raw() {
    use ms_delta::pa19::{Pa19CreateOptions, Pa19E8, Pa19Pe, create_pa19, create_pa19_with};
    let Some(root) = std::env::var_os("WINDOWS_DELTA_PA19_ORACLE") else {
        eprintln!("WINDOWS_DELTA_PA19_ORACLE is not set; skipping created-patch pairs");
        return;
    };
    let root = Path::new(&root);
    let limits = Limits::default();
    let mut files: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("ours_pe") && name.ends_with(".json"))
        })
        .collect();
    files.sort();
    let (mut pairs, mut smaller, mut not_larger) = (0, 0, 0);
    for file in files {
        let jobs: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        for job in jobs.as_array().unwrap() {
            let name = job["name"].as_str().unwrap();
            if !name.starts_with("x86_") || !name.ends_with("_peauto") {
                continue;
            }
            let old = fs::read(root.join(job["host_old"].as_str().unwrap())).unwrap();
            let new = fs::read(root.join(job["host_new"].as_str().unwrap())).unwrap();
            let options = Pa19CreateOptions {
                pe: Pa19Pe::Auto,
                e8: Pa19E8::Auto,
                ..Default::default()
            };
            let patch = create_pa19_with(&old, &new, &options, &limits)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(apply_pa19(&old, &patch, &limits).unwrap() == new, "{name}");
            let raw = create_pa19(&old, &new, &limits).unwrap();
            not_larger += usize::from(patch.len() <= raw.len());
            smaller += usize::from(patch.len() < raw.len());
            pairs += 1;
        }
    }
    eprintln!("pairs {pairs}, not larger than raw {not_larger}, smaller {smaller}");
    assert!(pairs > 0, "no ours_pe*.json x86 pairs found");
    assert_eq!(not_larger, pairs);
    assert!(
        smaller * 4 >= pairs * 3,
        "PE32 patches should usually beat raw"
    );
}
