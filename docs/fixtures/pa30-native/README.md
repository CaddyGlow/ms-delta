# Independently generated PA30 decoder fixtures

These thirteen `source` / `delta` / `target` triplets contain generated test data, not
Microsoft update payloads. `generate.ps1` was executed in the disposable
`cbs-psfx-pre-esu-1004` Windows VM on 2026-10-04. It calls the native
`CreateDeltaB` with RAW-only file types (1), set/reset flags zero, a fixed
FILETIME, and MD5 (`CALG_MD5`, 32771), or SHA-1 (`CALG_SHA1`, 32772).
It independently applies every resulting
patch with `ApplyDeltaB`, checks byte equality, and records `GetDeltaInfoB`.
`manifest.json` pins all three files using SHA-256. `oracle-platform.json` pins
the oracle DLL and Windows build. `execution.json` records the successful run.

Cases cover an empty-source literal, empty-source repetition, copying a nonempty
source with an inserted literal, deterministic random input with modifications,
random literals, source slices at nonzero offsets, reordered source slices,
80,000 bytes of repetition, distant source copies at 600,000, 2,000,000 and
20,000,000-byte backward distances, SHA-1, and a separate short literal.
The two largest `.source` buffers are retained only in
`/data/cache/pa30-native-generated`; regenerate them using the exact xorshift32
algorithm recorded in `manifest.json` and `generate.ps1`. Their compact delta
and target files are included. The random source was
generated with Python `random.Random(5071)` and is embedded in the script, so
reproduction does not depend on cross-language random generators.

The native oracle accepted MD5 and SHA-1. An initial call requesting SHA-256 algorithm
32780 returned Win32 error 13 (`ERROR_INVALID_DATA`) on this pinned platform;
that failure does not establish support for SHA-256 PA30 generation. The
explicit three-algorithm probe is retained in `hash-probe.execution.json`.

The PA30 format research source is
<https://github.com/smilingthax/msdelta-pa30-format>. Its format notes were used
as research, not copied implementation. Official API contracts are documented at
<https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-createdeltab>
and <https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab>.
The research repository does not expose a root license file; do not copy its
source into this workspace without resolving permissions. These generated
fixtures and the oracle script are original project test material.

## Real SSU comparison, metadata only

`ssu-oracle.json` records four PA30 streams extracted by the native Rust `caby`
reader from retained SSU-19041.5071-x64.cab. Each input SHA-256 matched the CIX
source record. Native `ApplyDeltaB` reconstructed members 0, 1, 2, and 10; every
result size and SHA-256 matched the independently supplied CIX target record.
The dependency chain is empty source -> member0/id33 -> member1/id44 -> member10;
member2 also uses id33. Patches and reconstructed Microsoft DLLs are retained
only in `/data/cache/pa30-ssu5071-inputs`, not included in the repository.

Member0 has RAW file type1 and flags0x60000: SDK
`DELTA_FLAG_IGNORE_FILE_SIZE_LIMIT | DELTA_FLAG_IGNORE_OPTIONS_SIZE_LIMIT`.
Members1/2/10 use file type32 and executable transformation flags0x66263e.
Their native success does not establish portable Rust support for those
transformations. Likewise, synthetic RAW decoder success does not establish
CBS installation correctness or complete PSFX support.
