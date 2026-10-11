# Original legacy GenericParam schema fixtures

`generate_inputs.py` derives this synthetic PE32 pair from the original C#
`../signatures/x86/` fixtures. It adds the native legacy graph's fifth
GenericParam column (a TypeDefOrRef coded constraint) to all three rows. The
constraint names `Item`, whose TypeDef row moves from source RID 6 to target
RID 2. This exercises a nonzero legacy column beyond the modern-schema fallback.

The script copies the expanded metadata root into a new read-only `.climeta`
section, updates the CLR metadata RVA/size, expands PE headers and raw section
pointers, and preserves existing section RVAs and method bodies. `inputs.json`
pins original and resulting SHA-256 hashes, sizes, row counts and constraint
values. Both generated files are 9,216 bytes. They are parser test data; the
modern CLR uses a different GenericParam schema, and these DLLs are never run.

Reproduce the inputs with:

```sh
python3 docs/fixtures/pa30-pe32-native/legacy-schema/generate_inputs.py
```

Rust's complete legacy metadata parser validates both roots, all five columns,
and the following MethodSpec/GenericParamConstraint table offsets. Native delta
generation and application evidence, when present, lives in this directory's
separate oracle manifest and scripts.
