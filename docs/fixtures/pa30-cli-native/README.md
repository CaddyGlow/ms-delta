# Independent native managed CLI4 PA30 fixtures

These fixtures contain original C# test assemblies and native MSDelta patches,
not Microsoft implementation/update binaries. The pinned disposable Windows10
AMD64 oracle, DLL hash and C# compiler version are in `oracle-platform.json`.
The VM was resumed with networking disabled; these assemblies were never executed.

The compiler was Framework64 v4.0.30319 `csc.exe`, file version4.8.4084.0.
Each `source.cs` and `target.cs` was compiled separately with:

```text
csc.exe /nologo /target:library /platform:x64 /optimize+ /debug- /out:source\fixture.dll source.cs
csc.exe /nologo /target:library /platform:x64 /optimize+ /debug- /out:target\fixture.dll target.cs
```

The exported assemblies are `source.dll` and `target.dll`. Both guest outputs
were named `fixture.dll` so assembly identity remains constant. The compiler can
emit different MVIDs on regeneration; the retained bytes/hashes, rather than a
claim of reproducible compiler output, define these known answers.

## Five controlled families

- Root pair reorders classes/methods/signatures and user strings, with tiny bodies,
  a fat switch/loop method and method calls.
- `rich/` adds instance/static field tokens, newobj constructor tokens,
  isinst/castclass, box/unbox.any, and field reads/writes.
- `signatures/` adds generic classes/methods and constraints, List<T>, TypeSpec/
  MethodSpec, enum value types, ref/out, vectors/multidimensional arrays, volatile
  modreq fields, interfaces, properties, events and delegates.
- `attributes/` adds original custom attributes on classes/methods/parameters,
  including named System.Type arguments for a constructed generic class.
- `wide/` uses generated long unique class names and row reordering. Its source
  #Strings heap is46,228 bytes with two-byte indices; its target heap is76,928
  bytes with four-byte indices. `wide/generate_sources.py` reproduces the C#.

`inspect_metadata.py` reports stream sizes, heap-width flags and table row counts
in `metadata-layouts.json`. It is a research layout reader, not an independent
metadata transform oracle.

## Native known answers

Each family's `generate.ps1` makes eight patches: empty or managed source, with
selected flags0, 0x200000, 0x400000, or0x600000. It uses file-type set245, MD5
algorithm32771, fixed FILETIME132537600000000000 and reset mask
`0x66263e & ~selected_flags` to isolate the selected bits. Every patch is applied
with native `ApplyDeltaB` and checked for exact equality with the retained target;
`GetDeltaInfoB` records the actual header. All40 cases succeeded natively.

Flags are named numerically to avoid a SDK/native label discrepancy: the pinned
native processing graph uses bit21(0x200000) for CLI4 IL disassembly and
bit22(0x400000) for CLI4 metadata. SDK header comments name those bits in the
opposite order. Empty sources select RAW type1 and empty preprocessing; managed
sources select CLI4AMD64 type32. Native acceptance of a flag is not, by itself,
a portable decoder support claim.

`extended-generate.ps1` captures30 additional patches across all five families:
forward native defaults and reverse patches for all four isolated flag sets plus
native defaults. Native default actual flags are0x60263e; source/target direction
is explicit in `extended-manifest.json`. These all roundtripped natively. The
wide reverse cases independently exercise four-byte to two-byte #Strings indices.
For forward cases the expected target is `target.dll`; for reverse it is
`source.dll`. Empty-source cases supply zero source bytes.

`inputs.json` pins C# and DLL hashes for each family. Manifests pin native header
facts and delta/preprocessing/patch hashes. Extracted `.preprocessing` and `.patch`
files use the existing outer-buffer research reader from `../pa30-pe-native`;
that extraction is not an independent transform oracle. Native generation and
application executions are retained alongside their scripts.

The API contracts are documented in Microsoft's
[CreateDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-createdeltab)
and [ApplyDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab)
reference. These fixtures validate bounded decoder research on original inputs;
they do not establish full managed-assembly support, complete PSFX reconstruction,
or CBS installation correctness.

The portable Rust decoder now reproduces all 70 retained native targets exactly.
[Rust validation](rust-validation.json) records source hashes, host regression
checks, the existing SSU chain gate, strict workspace Clippy and Windows x64
cross-compilation. The Rust binary was not executed on Windows in this gate.
