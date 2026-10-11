# PA19 fixtures

Patches in this directory were created by the real Windows `mspatchc.dll` (`CreatePatchFileExW`,
Windows 11 25H2 10.0.26100.7920, 2026-10-05) from the synthetic, deterministic files in this
directory (`fx_old*.bin`, `fx_new.bin`: pseudo-random text and binary blocks, no Microsoft data).
Each patch was also applied by the real `mspatcha.dll` and reproduced `fx_new.bin`. Option sets
(`PATCH_OPTION_*`, `PATCH_OPTION_DATA`):

- `default`, `nots` (no timestamp);
- `ignore`: ignore ranges `[1000,+500]` and `[5000,+300]` in the old file;
- `retain`: retain range old `[2000,+400]` to new `[7000,+400]`; `ignore_retain` combines `[100,+50]` ignore with it;
- `multi`: three old-file alternatives (`fx_old.bin`, `fx_old2.bin`, `fx_old3.bin`);
- `ilv_two`, `ilv_two_small`: explicit interleave maps with two groups
  (`PATCH_OPTION_INTERLEAVE_FILES` and `InterleaveMapArray`);
- `same`: old file equal to the new file.

`manifest.json` lists the cases for `tests/pa19_fixtures.rs`.
