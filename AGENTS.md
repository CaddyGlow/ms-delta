# Repository guidelines

This standalone Rust 2024 package provides PA19, PA30, PA31, and MS-PATCH LZX
Delta creation and reconstruction. The library uses `std`; `cli` enables the
optional command-line tool and CLI argument types. Dependencies resolve from
crates.io. Preserve codec attribution, license texts, original fixture bytes,
and historical validation evidence.

Use rustfmt defaults. Run `cargo test --all-features --locked`,
`cargo test --no-default-features --locked`, and
`cargo clippy --all-targets --all-features --locked -- -D warnings`.
Run `cargo fmt --all -- --check`. Native Windows oracle replay and
cache-dependent SSU/PA19 tests require separate gates; host tests do not
establish Windows servicing or boot correctness.
