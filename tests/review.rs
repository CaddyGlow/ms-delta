#![cfg(all(feature = "pa30", feature = "lzxd"))]

//! Independent API review regressions using Windows-generated PA30 fixtures.
use ms_delta::{Error, Limits, apply_lzxd, pa30::apply_pa30};
use std::path::Path;

fn fixture(name: &str, suffix: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("docs/fixtures/pa30-native/{name}.{suffix}")),
    )
    .unwrap()
}

#[test]
fn every_pa30_match_kind_obeys_caller_window_limit() {
    let limits = Limits {
        max_window_bytes: 0,
        ..Limits::default()
    };
    for name in [
        "source-copy",
        "source-offset",
        "source-reordered",
        "extended-offset",
        "empty-repeated",
        "long-repeated",
    ] {
        let result = apply_pa30(&fixture(name, "source"), &fixture(name, "delta"), &limits);
        assert!(matches!(result, Err(Error::Limit(_))), "{name}: {result:?}");
    }
    assert_eq!(
        apply_pa30(&[], &fixture("empty-literal", "delta"), &limits).unwrap(),
        b"abc"
    );
}

#[test]
fn corrupted_native_pa30_inputs_either_reject_or_return_exact_target() {
    for name in [
        "empty-literal",
        "empty-random",
        "source-copy",
        "source-offset",
        "source-reordered",
        "extended-offset",
        "long-repeated",
    ] {
        let delta = fixture(name, "delta");
        let source = fixture(name, "source");
        let expected = fixture(name, "target");
        let limits = Limits {
            max_output_bytes: expected.len(),
            max_patch_bytes: delta.len(),
            max_source_bytes: source.len(),
            ..Limits::default()
        };
        for index in (0..delta.len()).step_by((delta.len() / 128).max(1)) {
            for bit in 0..8 {
                let mut changed = delta.clone();
                changed[index] ^= 1 << bit;
                if let Ok(actual) = apply_pa30(&source, &changed, &limits) {
                    assert_eq!(actual, expected, "{name}: byte{index} bit{bit}");
                }
            }
        }
    }
}

#[test]
fn corrupted_native_pe_inputs_either_reject_or_return_exact_target() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa30-pe-native");
    let source = std::fs::read(root.join("source.exe")).unwrap();
    let target = std::fs::read(root.join("target.exe")).unwrap();
    let shifted = std::fs::read(root.join("shifted.exe")).unwrap();
    for manifest in [
        "manifest.json",
        "shifted-manifest.json",
        "legacy-manifest.json",
    ] {
        let text = std::fs::read_to_string(root.join(manifest)).unwrap();
        let cases: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        for case in cases
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["success"] == true)
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
            let delta = std::fs::read(root.join(format!("{name}.delta"))).unwrap();
            let limits = Limits {
                max_output_bytes: expected.len(),
                max_patch_bytes: delta.len(),
                max_source_bytes: basis.len(),
                max_parameter_bytes: 64 * 1024,
                ..Limits::default()
            };
            for index in (0..delta.len()).step_by((delta.len() / 128).max(1)) {
                for bit in 0..8 {
                    let mut changed = delta.clone();
                    changed[index] ^= 1 << bit;
                    if let Ok(actual) = apply_pa30(basis, &changed, &limits) {
                        assert_eq!(&actual, expected, "{name}: byte {index}, bit {bit}");
                    }
                }
            }
            for index in (0..basis.len()).step_by((basis.len() / 64).max(1)) {
                for bit in 0..8 {
                    let mut changed = basis.to_vec();
                    changed[index] ^= 1 << bit;
                    if let Ok(actual) = apply_pa30(&changed, &delta, &limits) {
                        assert_eq!(&actual, expected, "{name}: source byte {index}, bit {bit}");
                    }
                }
            }
        }
    }
}

#[test]
fn lzxd_resource_bounds_reject_inputs_before_decode() {
    let input = include_bytes!("../docs/fixtures/dependencies/ms-compress/official-abc.lzxd");
    for limits in [
        Limits {
            max_output_bytes: 2,
            ..Limits::default()
        },
        Limits {
            max_patch_bytes: input.len() - 1,
            ..Limits::default()
        },
        Limits {
            max_window_bytes: (1 << 17) - 1,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            apply_lzxd(&[], input, 3, 17, &limits),
            Err(Error::Limit(_))
        ));
    }
    assert!(matches!(
        apply_lzxd(
            b"x",
            input,
            3,
            17,
            &Limits {
                max_source_bytes: 0,
                ..Limits::default()
            }
        ),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        apply_lzxd(&[], input, 3, 16, &Limits::default()),
        Err(Error::Invalid(_))
    ));
}
