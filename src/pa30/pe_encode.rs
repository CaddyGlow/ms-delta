//! PE creation with source-only normalization and generic matches.
use super::{
    apply_pa30,
    cli::{CliMaps, MetadataInfo},
    cli_encode,
    encode::{Writer, create_with_dictionary},
    pe::{PeLayout, preprocess_cli},
    rift::RiftTable,
    rift_encode,
};
use crate::{Error, Limits, Result};

/// Creates a deterministic PA30 delta for matching supported PE architectures.
///
/// Chooses the smallest supported source-normalization variant. The target is
/// retained byte for byte, with a SHA-1 digest and zero target FILETIME.
pub fn create_pa30_pe(source: &[u8], target: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("PA30 source size"));
    }
    if target.len() > limits.max_output_bytes {
        return Err(Error::Limit("PA30 target size"));
    }
    let source_layout = PeLayout::parse(source)?;
    let target_layout = PeLayout::parse(target)?;
    if source_layout.machine() != target_layout.machine() {
        return Err(Error::Unsupported("PE creation architecture mismatch"));
    }
    let managed = source_layout.has_cli_directory();
    if managed != target_layout.has_cli_directory() {
        return Err(Error::Unsupported("PE creation managed graph mismatch"));
    }
    let (source_metadata, target_metadata) = if managed {
        validate_managed(source, &source_layout)?;
        validate_managed(target, &target_layout)?;
        (
            MetadataInfo::parse(source, &source_layout, limits)?,
            MetadataInfo::parse(target, &target_layout, limits)?,
        )
    } else {
        (MetadataInfo::default(), MetadataInfo::default())
    };
    let maps = if managed {
        cli_encode::maps(source, target, &source_metadata, &target_metadata, limits)?
    } else {
        CliMaps {
            strings: RiftTable::default(),
            user_strings: RiftTable::default(),
            blob: RiftTable::default(),
            guid: RiftTable::default(),
            tables: std::array::from_fn(|_| RiftTable::default()),
        }
    };
    let target_info = target_layout.target_info(target, limits)?;
    let used = source_layout.section_map(&target_layout, source, target, limits)?;
    let mut parameters = Writer::new(limits.max_parameter_bytes)?;
    parameters.bits(target_info.image_base, 64)?;
    parameters.bits(u64::from(target_info.global_pointer), 32)?;
    parameters.bits(u64::from(target_info.time_stamp), 32)?;
    rift_encode::write(&target_info.rva_to_offset, &mut parameters, limits)?;
    if managed {
        cli_encode::write_metadata(&target_metadata, &mut parameters)?;
    } else {
        parameters.bits(0, 1)?;
    }
    rift_encode::write(&used, &mut parameters, limits)?;
    if managed {
        cli_encode::write_maps(&maps, &mut parameters, limits)?;
    } else {
        parameters.bits(0, 1)?;
    }
    let parameters = parameters.finish();
    let file_type = match (source_layout.machine(), managed) {
        (0x14c, false) => 2,
        (0x8664, false) => 8,
        (0x14c, true) => 16,
        (0x8664, true) => 32,
        (0x1c4, _) => 64,
        (0xaa64, _) => 128,
        (0x200, false) => 4,
        _ => return Err(Error::Unsupported("PE creation architecture")),
    };
    let supported = match source_layout.machine() {
        0x14c => 0x21fe,
        0x8664 => 0x263e,
        0x1c4 => 0x18203e,
        0xaa64 => 0x180203e,
        0x200 => 0x383e,
        _ => return Err(Error::Unsupported("PE creation architecture")),
    };
    let mut best: Option<Vec<u8>> = None;
    let mut first_error = None;
    let candidates: &[u64] = if managed {
        &[
            0,
            0x20,
            supported,
            0x200000,
            0x400000,
            0x600000,
            supported | 0x600000,
        ]
    } else if source_layout.machine() == 0x200 {
        // Current UpdateCompression ignores IA64 instruction/pdata flags,
        // unlike older MSDelta. These candidates interoperate with both.
        &[0, 0x20]
    } else {
        &[0, 0x20, supported]
    };
    for &flags in candidates {
        let candidate = (|| {
            let normalized = preprocess_cli(
                source,
                flags,
                &target_info,
                &used,
                &source_metadata,
                &target_metadata,
                &maps,
                limits,
            )?;
            let patch =
                create_with_dictionary(&normalized, target, file_type, flags, &parameters, limits)?;
            if apply_pa30(source, &patch, limits)? != target {
                return Err(Error::Invalid("PE creation normalization mismatch"));
            }
            Ok(patch)
        })();
        match candidate {
            Ok(patch)
                if best
                    .as_ref()
                    .is_none_or(|previous| patch.len() < previous.len()) =>
            {
                best = Some(patch);
            }
            Ok(_) => {}
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    best.ok_or_else(|| first_error.unwrap_or(Error::Invalid("PE creation candidates")))
}

fn validate_managed(bytes: &[u8], layout: &PeLayout) -> Result<()> {
    let (rva, size) = layout
        .directory(14)
        .ok_or(Error::Invalid("CLI header directory"))?;
    if size < 72 {
        return Err(Error::Invalid("CLI header size"));
    }
    let offset = layout.offset(rva, 72)?;
    let header = &bytes[offset..offset + 72];
    let header_size = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if header_size < 72 || header_size > size {
        return Err(Error::Invalid("CLI header declared size"));
    }
    let flags = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let native_rva = u32::from_le_bytes([header[64], header[65], header[66], header[67]]);
    let native_size = u32::from_le_bytes([header[68], header[69], header[70], header[71]]) as usize;
    if (native_rva == 0) != (native_size == 0) {
        return Err(Error::Invalid("CLI native header directory"));
    }
    if native_size != 0 {
        layout.offset(native_rva, native_size)?;
    }
    if flags & 0x10 != 0 {
        let entry_point = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
        if entry_point != 0 {
            layout.offset(entry_point, 1)?;
        }
    }
    Ok(())
}
