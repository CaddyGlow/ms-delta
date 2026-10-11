# Native uncompressed BSDiff flag probes

These five controlled PA31 probes preserve the original header hashes and source/target inputs, decode the valid compressed BSDiff payload, substitute the resulting raw payload, and clear flag bit27. Resulting flags are `0x12000000`; this is stronger than leaving compressed bytes beneath a changed flag. Source-empty and source-dependent cases are represented.

Native GetDeltaInfoB accepts all five headers. Native ApplyDeltaB accepts the genuinely empty patch and reproduces its empty target; it rejects every nonempty raw-payload case with error 277252. The native results distinguish header inspection from application and preserve the empty behavior. These bounded negative controls support rejecting the represented nonempty uncompressed combination rather than treating header acceptance as codec support.

Inputs and patches are original, with no Microsoft payload. The public oracle, DLL hash and isolated guest provenance match the parent PA31 native fixtures. `apply.ps1`, manifests and execution proof retain reproduction details. The production API continues to require valid target integrity; no hashless output technique is used by this gate.
