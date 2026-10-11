# Independently decoded original MS-PATCH encoder vectors

These original deterministic vectors are created by the Rust encoder and decoded
by an external libmspack LZX Delta wrapper, pinned to upstream commit
`55d501976171397ccd5d5a7a1ca7da065b1d9a06`. The external decoder source and binary
are not redistributed here. `oracle-results.json` records its binary SHA-256,
input/output hashes, sizes and successful exit codes for all 36 cases.

Cases cover pseudo-random odd-length literals, reference copies, overlapping
output copies, and a 32769-byte frame boundary. Every case runs with window
orders 17 through 25. The final target byte is included in the independent exact
output comparison. Sources and targets are shared between window orders.

Reproduce with a separately built wrapper that accepts arguments
`delta reference output window_order target_size`:

```sh
cargo run --locked -p windows-delta --example create_lzxd_fixtures -- \
  /tmp/lzxd-oracle/oracle docs/fixtures/lzxd-created-libmspack
cargo test --locked -p windows-delta --test encode_lzxd
LZXD_ORACLE=/tmp/lzxd-oracle/oracle cargo test --locked -p windows-delta \
  --test encode_lzxd independent_libmspack -- --ignored
```

The ignored independent test additionally regenerates a 20 MB reference and
checks a distant reference match with window order 25; large inputs are not
stored here. The ordinary regression regenerates every retained patch exactly,
checks hashes, and reconstructs its target with the Rust decoder.

This establishes MS-PATCH stream interoperability with a separate decoder. It
does not establish PA30 envelope interoperability, PSFX packaging, or Windows
servicing correctness. The Rust encoder is independently written MIT code;
no LGPL decoder implementation was copied into it.
