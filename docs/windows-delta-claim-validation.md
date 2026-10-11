# Delta claim validation — 2026-10-04

Fresh host checks confirm the scoped claims below. Windows application evidence
was audited from retained native results; no new Windows guest replay was run.

| Claim | Result |
| --- | --- |
| Mixed IL/native and ReadyToRun decode | 40 successful native-generated cases per family reconstruct exactly; 40 rejected native creation probes per family remain recorded. |
| Rust-created patches apply on Windows | All eight retained native results report exact application. Fresh host tests regenerate every PA30/PA31 patch byte-for-byte. All 24 source, target and patch SHA-256 hashes match their manifest. |
| Compressed reverse playback | `native_playback_restores_pe_cli_and_compressed_deleted_bytes` passes, including `compressed-delete`. The Windows XPRESS path implements the zero-u16 escape followed by a u32 length. |
| ARM32 | All 12 PA30 flag-matrix cases pass; all 12 PA31 cases pass. ARM64 matrices pass too. |
| IA64 | Recheck after the fix: the native PA30 flag matrix, including `ia64-forward-2048`, passes exact reconstruction. The PA31 architecture regression also passes. |

`cargo test -p windows-delta --locked --test modern_paths` passes all four
integration tests. `cargo test -p ms-compress --locked` passes. The full
initial windows-delta test invocation stopped at the IA64 library failure
(87 pass, one fail). After the fix, all 91 library tests pass; the earlier
failure is superseded by this fresh host replay.
The complete `cargo test -p windows-delta --locked` recheck exits successfully,
including integration and documentation tests; ignored tests remain excluded.

Workspace Clippy with all targets/features and warnings denied fails in current
windows-uup code, including an unused `Tagged` import in `catalog.rs` and
`possible_missing_else` findings. This validation is not a clean workspace gate.

Evidence: `fixtures/pa30-managed-native-images/{mixed,readytorun,created}`,
`fixtures/pa30-arm-native/{arm,arm64,ia64}`, and
`fixtures/pa31-native/reverse-extended`. Inputs were preserved.
