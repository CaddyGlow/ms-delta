# Rust-created PA30 patches checked by native Windows

These 22 patches were created by the project's Rust `windows-delta create`
command, independently applied by native Windows `ApplyDeltaB`, and compared byte
for byte with their original targets. They validate encoding, rather than merely
a Rust encoder/decoder roundtrip. Every native output SHA-256 matched, every
source SHA-256 remained unchanged, and native `GetDeltaInfoB` confirmed RAW
file-type set/type 1, flags 0, SHA-1 algorithm 0x8004 and zero FILETIME.

`manifest.json` pins source, target and patch hashes plus native facts per case.
`native-results.json` and `execution.json` retain the successful native run;
`apply.ps1` is the exact original P/Invoke harness. The Windows/DLL oracle is the
same pinned isolated build in `../pa30-pe32-native/oracle-platform.json`.
No Microsoft update/implementation payloads are included. The managed PE32 input
is an original C# test assembly treated as opaque RAW bytes, not transformed or
executed.

Cases include empty target, abc, all byte values, deterministic random literals,
short and 80,000-byte repetition, identical/changed/reversed/reordered sources,
source prefix/suffix copying, tiny and binary sources, lengths 8/9/255/65,536,
original managed PE32 files, and source references at 600,000/2,000,000/20,000,000
byte distances. Long-distance sources start with ASCII `DISTANCE` and then zero
bytes; this avoids a hash-bucket collision hiding the initial match candidate.

Checked-in source paths are relative fixture names. The two largest `.source`
files are cache-only under `/data/cache/pa30-created-native`; reconstruct them as:

```python
source = b'DISTANCE' + bytes(source_size - 8)
```

Their compact target/delta and hashes are retained here. The 600,000-byte source
is included. `generate.py` describes every input and the exact CLI calls. To
reproduce in a clean copy of this directory, set `WINDOWS_DELTA_CLI` to a freshly
built standalone binary and run:

```sh
cargo build --locked -p windows-delta --features cli
WINDOWS_DELTA_CLI=/path/to/windows-delta python3 generate.py
```

The CLI intentionally refuses to overwrite existing patches; remove only copied
`.delta` outputs before regenerating. Regeneration should use the pinned source
snapshot captured by the parent validation report. Changed encoder output may
require fresh native validation even if its Rust roundtrip succeeds.

The first harness run reported 21/22 because native empty-target application
returned a valid null output buffer, and .NET Marshal.Copy rejected that null
pointer even for a zero-byte copy. The corrected harness skips Marshal.Copy for
zero-sized outputs. All 22 then passed native application; the original harness
failure is retained in `harness-zero-output-rejection.*.json`. It was a harness
failure, not native rejection of the empty patch.

The public native API contract is
[ApplyDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab).
This gate proves bounded RAW PA30 creation for these original cases, not native
creation of transformed PE/managed patches, PSFX package assembly or CBS servicing.
