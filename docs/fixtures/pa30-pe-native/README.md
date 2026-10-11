# Native AMD64 PE transform research

These fixtures use original tiny AMD64 PE executables compiled from `tiny.c`.
They contain no Microsoft implementation or update binaries. Source revision1,
target revision2, and shifted revision2 with an extra exported leading function
are 3,584 bytes each. `inputs.json` pins their hashes and compiler/linker versions.
They are test data: the guest never executes these PEs.

Build using clang-cl and lld-link:

```sh
clang-cl /c /O1 /GS- /DREVISION=1 /Fotarget/source.obj tiny.c
clang-cl /c /O1 /GS- /DREVISION=2 /Fotarget/target.obj tiny.c
clang-cl /c /O1 /GS- /DREVISION=2 /DSHIFT=1 /Fotarget/shifted.obj tiny.c
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /dynamicbase /fixed:no /timestamp:0 /out:source.exe target/source.obj
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /dynamicbase /fixed:no /timestamp:0 /out:target.exe target/target.obj
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /dynamicbase /fixed:no /timestamp:0 /out:shifted.exe target/shifted.obj
```

`pe-layout.txt` records the source headers and sections, including exports,
exception/pdata, relocations, and executable instructions. No import or resource
payload is present, so successful flags for those features do not exercise actual
import/resource transformations.

## Native oracle

The isolated Windows10 build19045.5073 amd64 VM and native msdelta DLL are pinned
in `../pa30-native/oracle-platform.json`. The selected-owned VM is
`cbs-psfx-pre-esu-1004`, networking disabled. Every successful fixture was generated
with `CreateDeltaB`, immediately applied with native `ApplyDeltaB`, compared byte
for byte with the original target, and inspected with native `GetDeltaInfoB`.
All use fixed FILETIME132537600000000000 and MD5 algorithm32771.

`generate.ps1` and `manifest.json` record 110 calls: empty or PE basis, requested
file-type sets8,9,32,33,245, and eleven isolated selected flags. Default CLI4
AMD64 flags0x66263e were reset except the selected flag. Only the22 type-set245
calls succeeded under those exact arguments. Empty basis selected RAW type1;
nonempty AMD64 basis selected CLI4AMD64 type32. Failures returned Win32error13.
This does not prove custom type sets are unsupported under other reset masks.

`generate-shifted.ps1` / `shifted-manifest.json` record eleven type-set245,
nonempty-basis calls with the shifted target. `generate-legacy.ps1` /
`legacy-manifest.json` use published executable type-set15 and legacy default
AMD64 reset-mask0xe63e; eleven calls succeeded, selecting AMD64 type8.

Isolated flags are NONE, MARK2, IMPORTS4, EXPORTS8, RESOURCES16, RELOCS32,
AMD64_DISASM512, AMD64_PDATA1024, UNBIND8192, HEADERS65536, and E8=1.
`*.delta` are native known-answer streams. `inspect_buffers.py` extracts their
outer preprocessing/patch buffers as research data; its parsing is not an
independent decoder oracle. `outer-buffers.json` pins extracted bytes.

`normalize.ps1` uses public `DeltaNormalizeProvidedB` with individual flags and
0x66263e. All captured source/target normalizations changed only image-base bytes
171/172 to zero. This API therefore does not expose the complete delta
preprocessing transformation on these inputs; do not treat normalized dumps as
patch-preprocessed source buffers.

## Additional independent checks

`e8/` contains eight original RAW target vectors with relative E8 instructions:
positive/negative offsets, positive/negative out-of-range offsets, a final complete
five-byte call, incomplete tail, nested E8 operand, and zero displacement. Native
CreateDeltaB type-set1/flags1 and ApplyDeltaB roundtripped each exactly.

`lru/` retains an independently encoded PA30 golden requested by the root agent.
Native ApplyDeltaB confirmed its target `NONONOONOO`; it distinguishes repeated
offset deduplication from an always-prepend offset queue.

`rift-reverse.ps1` calls a private native method at RVA0x4060 using a synthetic,
bounded RiftTable in an isolated process. This is research ABI evidence tied to
the exact pinned DLL, not a supported API or production dependency. It returned
new tables for four known inputs; source/return objects remain process-local and
are reclaimed at process exit. The experiment succeeded without a crash; full
execution results preserve sentinel coordinates and nontrivial inverse geometry.
`rift-reverse-starts.ps1` repeats the four inputs with starts -50, 50, and100;
its twelve captured outputs distinguish start-relative sentinel/tail behavior.

Native successes here establish known-answer evidence for original inputs.
They do not establish portable support for every selected PE transform, full
PSFX delta reconstruction, or CBS installation. Microsoft SSU members1/2/10 and
the cached oracle DLL remain outside the repository.

`real-isolated-metadata.json` records eleven additional native known-answer
experiments using the cached reconstructed SSU drupdate.dll as source and
httpai.dll as target. Each selected flag independently roundtripped the CIX
target hash. Their PA30 streams and extracted buffers remain cache-only under
`/data/cache/pa30-pe-research/real-isolated`; actual imports/resources are present
in these inputs, unlike the original tiny PEs.
