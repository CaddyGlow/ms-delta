//! PA31 nested header and source-integrity envelope.
use super::{
    Bits, Pa30Info, Parsed, apply_parsed, encode::Writer, parse, validate_hash, verify_hash,
};
use crate::{Error, Limits, Result};
use sha2::{Digest, Sha256};

/// PA31 metadata including its extended header and optional source digest.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Pa31Info {
    /// Common delta metadata.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub metadata: Pa30Info,
    /// Three native extended header fields, commonly `[136, 1, 0]`.
    /// The first two are opaque; the third supports values zero and one.
    pub extra_header_fields: [u32; 3],
    /// Source digest using the same algorithm as the target, or empty.
    pub source_hash: Vec<u8>,
}

struct Parsed31<'a> {
    common: Parsed<'a>,
    fields: [u32; 3],
    source_hash: &'a [u8],
}

/// Inspects a bounded PA31 envelope without reconstructing its target.
pub fn inspect_pa31(delta: &[u8], limits: &Limits) -> Result<Pa31Info> {
    let parsed = parse31(delta, limits)?;
    Ok(Pa31Info {
        metadata: parsed.common.info,
        extra_header_fields: parsed.fields,
        source_hash: parsed.source_hash.to_vec(),
    })
}

/// Applies a forward or reverse-playback PA31 delta, validating its digests.
pub fn apply_pa31(source: &[u8], delta: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA31 source size"));
    }
    let parsed = parse31(delta, limits)?;
    let info = &parsed.common.info;
    validate_hash(info)?;
    if parsed.fields[2] > 1 {
        return Err(Error::Invalid("PA31 extended header version"));
    }
    if info.flags & !0x1bff_ffff != 0 {
        return Err(Error::Unsupported("PA31 unknown transform flag"));
    }
    if !parsed.source_hash.is_empty() {
        let source_info = Pa30Info {
            target_hash: parsed.source_hash.to_vec(),
            ..info.clone()
        };
        verify_hash(&source_info, source).map_err(|error| match error {
            Error::Integrity(_) => Error::Integrity("PA31 source hash mismatch"),
            other => other,
        })?;
    }
    if info.file_type_set & 0x100 != 0 {
        let output = super::reverse::apply(source, parsed.common.patch, info.target_size, limits)?;
        verify_hash(info, &output)?;
        Ok(output)
    } else {
        apply_parsed(source, &parsed.common, limits)
    }
}

fn parse31<'a>(delta: &'a [u8], limits: &Limits) -> Result<Parsed31<'a>> {
    if delta.len() > limits.max_patch_bytes {
        return Err(Error::Limit("PA31 patch size"));
    }
    if delta.len() < 13 || &delta[..4] != b"PA31" {
        return Err(Error::Invalid("PA31 signature"));
    }
    let mut outer = Bits::new(&delta[12..])?;
    let header = outer.buffer()?;
    if header.len() > limits.max_parameter_bytes {
        return Err(Error::Limit("PA31 header size"));
    }
    let mut bits = Bits::new(header)?;
    let file_type_set = bits.number(16)?;
    let file_type = bits.number(16)?;
    let flags = bits.number(16)?;
    let target_size =
        usize::try_from(bits.number(16)?).map_err(|_| Error::Limit("PA31 target size"))?;
    if target_size > limits.max_output_bytes {
        return Err(Error::Limit("PA31 target size"));
    }
    let target_hash_algorithm =
        u32::try_from(bits.number(8)?).map_err(|_| Error::Invalid("PA31 hash algorithm"))?;
    let target_hash = bits.buffer()?;
    if target_hash.len() > 32 {
        return Err(Error::Invalid("PA31 target hash length"));
    }
    let mut fields = [0u32; 3];
    for field in &mut fields {
        *field = u32::try_from(bits.number(8)?).map_err(|_| Error::Invalid("PA31 header field"))?;
    }
    let source_hash = bits.buffer()?;
    if source_hash.len() > 32 {
        return Err(Error::Invalid("PA31 source hash length"));
    }
    bits.finish()?;
    let preprocessing = if file_type_set & 0x100 == 0 {
        outer.buffer()?
    } else {
        &[]
    };
    if preprocessing.len() > limits.max_parameter_bytes {
        return Err(Error::Limit("PA31 preprocessing size"));
    }
    let patch = outer.buffer()?;
    outer.finish()?;
    Ok(Parsed31 {
        common: Parsed {
            info: Pa30Info {
                target_file_time: u64::from_le_bytes([
                    delta[4], delta[5], delta[6], delta[7], delta[8], delta[9], delta[10],
                    delta[11],
                ]),
                file_type_set,
                file_type,
                flags,
                target_size,
                target_hash_algorithm,
                target_hash: target_hash.to_vec(),
                preprocessing_size: preprocessing.len(),
                patch_size: patch.len(),
            },
            preprocessing,
            patch,
        },
        fields,
        source_hash,
    })
}

/// Creates a deterministic RAW PA31 delta with SHA-256 source/target digests.
pub fn create_pa31(source: &[u8], target: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    wrap(
        source,
        target,
        super::create_pa30(source, target, limits)?,
        limits,
    )
}

/// Creates a deterministic PE/CLI4 PA31 delta with SHA-256 integrity.
pub fn create_pa31_pe(source: &[u8], target: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    wrap(
        source,
        target,
        super::create_pa30_pe(source, target, limits)?,
        limits,
    )
}

fn wrap(source: &[u8], target: &[u8], pa30: Vec<u8>, limits: &Limits) -> Result<Vec<u8>> {
    let parsed = parse(&pa30, limits)?;
    let info = parsed.info;
    let mut header = Writer::new(limits.max_parameter_bytes)?;
    for value in [
        info.file_type_set,
        info.file_type,
        info.flags | 0x1000_0000,
        info.target_size as u64,
        0x800c,
    ] {
        header.number(value)?;
    }
    header.buffer(&Sha256::digest(target))?;
    for value in [136, 1, 0] {
        header.number(value)?;
    }
    header.buffer(&Sha256::digest(source))?;
    let mut outer = Writer::new(
        limits
            .max_patch_bytes
            .checked_sub(12)
            .ok_or(Error::Limit("PA31 patch size"))?,
    )?;
    outer.buffer(&header.finish())?;
    outer.buffer(parsed.preprocessing)?;
    outer.buffer(parsed.patch)?;
    let body = outer.finish();
    let mut result = Vec::new();
    result
        .try_reserve_exact(12 + body.len())
        .map_err(|_| Error::Allocation)?;
    result.extend_from_slice(b"PA31");
    result.extend_from_slice(&0u64.to_le_bytes());
    result.extend_from_slice(&body);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_uncompressed_bsdiff_flags_allow_only_an_empty_payload() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/fixtures/pa31-native/uncompressed-probes");
        for name in ["empty", "abc", "identical", "changed", "reverse"] {
            let source = std::fs::read(root.join(format!("{name}.source"))).unwrap();
            let target = std::fs::read(root.join(format!("{name}.target"))).unwrap();
            let patch = std::fs::read(root.join(format!("{name}.delta"))).unwrap();
            assert_eq!(
                inspect_pa31(&patch, &Limits::default())
                    .unwrap()
                    .metadata
                    .flags,
                0x1200_0000
            );
            let result = apply_pa31(&source, &patch, &Limits::default());
            if name == "empty" {
                assert_eq!(result.unwrap(), target);
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Invalid(
                        "delta nonempty BSDiff payload requires compression"
                    ))
                ));
            }
        }
    }

    #[test]
    fn unknown_flags_fail_before_payload_processing() {
        let source = b"source";
        let target = b"target";
        let patch = create_pa31(source, target, &Limits::default()).unwrap();
        let parsed = parse31(&patch, &Limits::default()).unwrap();
        let info = &parsed.common.info;
        for unknown in [0x0400_0000, 0x4000_0000, 1u64 << 63] {
            let mut header = Writer::new(4096).unwrap();
            for value in [
                info.file_type_set,
                info.file_type,
                info.flags | unknown,
                info.target_size as u64,
                u64::from(info.target_hash_algorithm),
            ] {
                header.number(value).unwrap();
            }
            header.buffer(&info.target_hash).unwrap();
            for field in parsed.fields {
                header.number(u64::from(field)).unwrap();
            }
            header.buffer(parsed.source_hash).unwrap();
            let mut outer = Writer::new(4096).unwrap();
            outer.buffer(&header.finish()).unwrap();
            outer.buffer(parsed.common.preprocessing).unwrap();
            outer.buffer(parsed.common.patch).unwrap();
            let mut malformed = patch[..12].to_vec();
            malformed.extend(outer.finish());
            assert!(matches!(
                apply_pa31(source, &malformed, &Limits::default()),
                Err(Error::Unsupported("PA31 unknown transform flag"))
            ));
        }
    }

    #[test]
    fn native_extended_headers_accept_opaque_fields_and_guard_the_third_field() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixtures/pa31-native");
        let source = std::fs::read(root.join("identical.source")).unwrap();
        let target = std::fs::read(root.join("identical.target")).unwrap();
        for fields in [
            [136, 1, 0],
            [136, 1, 1],
            [136, 2, 0],
            [80, 0, 0],
            [136, 1, 2],
        ] {
            let patch = std::fs::read(root.join(format!(
                "header-variants/fields-{}-{}-{}.delta",
                fields[0], fields[1], fields[2]
            )))
            .unwrap();
            assert_eq!(
                inspect_pa31(&patch, &Limits::default())
                    .unwrap()
                    .extra_header_fields,
                fields
            );
            let result = apply_pa31(&source, &patch, &Limits::default());
            if fields[2] <= 1 {
                assert_eq!(result.unwrap(), target, "{fields:?}");
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Invalid("PA31 extended header version"))
                ));
            }
        }
    }
}
