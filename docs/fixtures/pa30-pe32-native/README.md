# PE32 / AnyCPU and legacy managed native known answers

This new fixture tree preserves 288 independent native known answers and does not
replace the earlier 70 cases in `../pa30-cli-native`. Its inputs are original
C#/C/assembly test data; Microsoft implementation/update binaries are not included.
No generated assembly or executable was run in the guest.

The isolated Windows 10 AMD64 oracle is pinned by DLL hash/version, Windows build
and compiler version in `oracle-platform.json`. Native execution used owned
`cbs-psfx-pre-esu-1004`, resumed with networking disabled. Native CreateDeltaB
produced each patch; ApplyDeltaB independently reconstructed the exact retained
target, and GetDeltaInfoB confirmed the actual selected graph. Each call used MD5
algorithm 32771 and fixed FILETIME 132537600000000000. Resource use remained
bounded; no image servicing or installation took place.

## 250 managed cases

`sources/` copies the five original C# families from `../pa30-cli-native`: basic,
rich field/IL tokens, generics/signatures, custom attributes, and wide heaps.
Each was compiled separately for anycpu, x86 and x64 using Framework64
v4.0.30319 csc.exe 4.8.4084.0:

```text
csc.exe /nologo /target:library /platform:anycpu /optimize+ /debug- /out:source\fixture.dll source.cs
csc.exe /nologo /target:library /platform:anycpu /optimize+ /debug- /out:target\fixture.dll target.cs
```

Repeat with `/platform:x86` or `/platform:x64`. Both guest outputs were named
`fixture.dll`; `compile.json` pins the retained DLL hashes. Compiler regeneration
may change MVIDs, so captured bytes define the known answer rather than a promise
of deterministic C# compilation.

`metadata-layouts.json` confirms PE32 anycpu is I386/ILONLY, CLR flags 1; x86 is
I386/ILONLY/32BITREQUIRED, flags 3; x64 is AMD64/PE32+. The wide families cross
#Strings 46,228 bytes/two-byte indices to 76,928 bytes/four-byte indices and back.

`probe.ps1` records requested file-type sets 3 and 17 returning Win32 error 13 under
the exact tested reset masks. Published sets 15 and 245 work, selecting actual
legacy I386 2, CLI4 I386 16 and legacy AMD64 8. These failures do not prove every
custom set/mask combination is unsupported. RAW fallback was explicitly rejected
by the positive matrix.

`generate.ps1` uses file-type set 15 for legacy graphs, 245 for CLI4. Legacy
I386 default/reset mask is 0xe1fe; AMD64 is 0xe63e. CLI4 I386 mask is 0x6021fe.
Isolated legacy flags are 0, 0x4000, 0x8000, 0xc000; CLI4 flags are 0, 0x200000,
0x400000, 0x600000. Each has forward/reverse and native default cases. The matrix
covers anycpu/x86 legacy+CLI4 and x64 legacy: 50 cases per family, 250 total.

`manifest.json` provides relative patch path, direction, graph, platform,
actual native header and hashes of delta/preprocessing/patch buffers. DLLs are
`family/platform/{source,target}.dll`. Forward expected target is target.dll;
reverse expected target is source.dll. All 250 native roundtrips passed.

## 28 original unmanaged I386 cases

`native-i386/` contains original tiny C/assembly inputs, helper import DLL and
source/target PEs. `build.sh` records clang-cl/lld-link commands. It writes rebuilt
fixture binaries, so use a copy of this directory to preserve the pinned inputs.
`layout.txt`, `target-layout.txt` and `geometry.json` pin the relevant geometry:
source base 0x400000, target base 0x500000; .text virtual size 624 → 5,184 bytes;
.rdata RVA 0x2000 → 0x3000, .data RVA 0x3000 → 0x4000, and
.reloc RVA 0x4000 → 0x5000.

The target has 4500 added NOPs before a referenced function. Both PEs contain
actual HIGHLOW relocations and a 32-bit import table for original helper.dll.
A 72-byte LoadConfig structure lists a LockPrefixTable entry whose source byte is
0x90 and target byte 0xf0. Original executable-section vectors include E9/Jcc/E8
with displacement 200, making long relative references observable. This is parser
and normalization test data, not an assertion these intentionally synthetic code
paths should be executed.

`unmanaged-manifest.json` captures 28 native type 2 roundtrips: forward/reverse
for flags 0, E8 = 1, MARK 2, IMPORTS 4, EXPORTS 8, RESOURCES 16, RELOCS 32,
SMASHLOCK 64, JMPS 128, CALLS 256, UNBIND 8192, HEADERS 65536, full 0xe1fe and defaults.
The source byte 0x90 → target byte 0xf0 transition, changed image bases, and
changed section RVAs exercise combined
lock/relocation behavior. Patches are under native-i386/; expected files are
source.exe/target.exe according to direction.

## 10 true five-column legacy GenericParam cases

`legacy-schema/` retains an original controlled PE rewrite produced by
`generate_inputs.py`. Its source/target are 9216-byte PE32 libraries derived from
the original signatures family. The relocated metadata root has the true legacy
five-column GenericParam layout; nonzero Item TypeDef constraints are coded 24
(source RID 6) and 8 (target RID 2). These are intentionally legacy metadata inputs,
not modern CLR execution targets.

Its `manifest.json` captures ten strict native type 2 cases: four isolated legacy
CLI flag sets plus defaults, each direction. Native metadata preprocessing is
nonempty (464 forward/463 reverse bytes), unlike the small fallback preprocessing
seen when legacy graphs encounter modern four-column generic metadata. All ten
native applications matched the exact retained target.

`*.preprocessing` and `*.patch` are extracted by the earlier outer-buffer research
reader; extraction itself is not an independent decoder oracle. The public API
contracts are documented in Microsoft's
[CreateDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-createdeltab)
and [ApplyDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab)
reference. These known answers establish bounded format/transform checks, not
CBS installation correctness or support for every PE/managed assembly.
