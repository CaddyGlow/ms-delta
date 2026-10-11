//! File commands shared by the standalone CLI and `windows-uup`.
use crate::{Error, Limits, Result};
use clap::{Args, ValueEnum};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Encoded delta format; LZXD has no self-identifying file header.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// MSDelta PA30, with a target header and hash.
    Pa30,
    /// UpdateCompression PA31, with source and target integrity metadata.
    Pa31,
    /// MS-PATCH LZX Delta, with two-byte chunk prefixes.
    Lzxd,
    /// Legacy PatchAPI PA19, read by `mspatcha.dll`.
    Pa19,
}

/// Intel `E8` call translation policy for PA19 creation.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum E8Mode {
    /// No translation.
    #[default]
    Off,
    /// Always translate (the new file size is the translation size).
    On,
    /// Try both and keep the smaller patch.
    Auto,
}

/// Resource limits for file commands.
#[derive(Debug, Args)]
pub struct LimitArgs {
    /// Maximum size of each source, target or patch input, in bytes.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub max_input_bytes: usize,
    /// Maximum reconstructed target size, in bytes.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub max_output_bytes: usize,
    /// Maximum LZX Delta history window size, in bytes.
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    pub max_window_bytes: usize,
    /// Maximum each codec parameter/table/encoder workspace, in bytes.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub max_parameter_bytes: usize,
}

impl LimitArgs {
    fn limits(&self) -> Limits {
        Limits {
            max_patch_bytes: self.max_input_bytes,
            max_source_bytes: self.max_input_bytes,
            max_output_bytes: self.max_output_bytes,
            max_window_bytes: self.max_window_bytes,
            max_parameter_bytes: self.max_parameter_bytes,
        }
    }
}

/// Arguments for inspecting one PA19, PA30 or PA31 header.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// PA19, PA30 or PA31 file to inspect.
    #[arg(long)]
    pub delta: PathBuf,
    /// Bounds on input, output and codec window sizes.
    #[command(flatten)]
    pub limits: LimitArgs,
}

/// Arguments for reconstructing one target file.
#[derive(Debug, Args)]
pub struct ApplyArgs {
    /// Encoded format of the patch input.
    #[arg(long, value_enum)]
    pub format: Format,
    /// Patch input; original bytes are never modified.
    #[arg(long)]
    pub delta: PathBuf,
    /// Source/reference file; omitting this supplies an empty source.
    #[arg(long)]
    pub source: Option<PathBuf>,
    /// New target file; existing files and symlinks are never overwritten.
    #[arg(long)]
    pub output: PathBuf,
    /// Exact LZXD target size; PA30/PA31 supply their own target size.
    #[arg(long)]
    pub target_size: Option<usize>,
    /// LZXD history window order (17 through 25), default 17.
    #[arg(long)]
    pub window_order: Option<u8>,
    /// Optional independently expected target SHA256, as 64 hexadecimal digits.
    #[arg(long)]
    pub expected_sha256: Option<String>,
    /// Bounds on input, output and codec window sizes.
    #[command(flatten)]
    pub limits: LimitArgs,
}

/// Arguments for creating a patch from an original and a target file.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Encoded format of the new patch.
    #[arg(long, value_enum)]
    pub format: Format,
    /// Optimize PA30/PA31 creation for PE or managed assembly pairs. For PA19 this tries the
    /// PE32 path (normalization and rift transform) next to raw data and keeps the smaller
    /// patch; PE32+ and other files stay raw because `mspatcha.dll` transforms only PE32.
    #[arg(long, requires = "source")]
    pub pe: bool,
    /// PA19 only: Intel E8 call translation of the LZX stream.
    #[arg(long, value_enum)]
    pub e8: Option<E8Mode>,
    /// Source/reference file; omitting this supplies an empty source.
    #[arg(long)]
    pub source: Option<PathBuf>,
    /// Target file whose exact bytes the patch will reconstruct.
    #[arg(long)]
    pub target: PathBuf,
    /// New patch file; existing files and symlinks are never overwritten.
    #[arg(long)]
    pub output: PathBuf,
    /// LZXD history window order (17 through 25), default 17. For PA19 an explicit window
    /// order is recorded in the patch; the default is derived from the file sizes.
    #[arg(long)]
    pub window_order: Option<u8>,
    /// PA19 only: split the target into interleaved LZX groups of this many output bytes, each
    /// with its own slice of the old file as history (for files larger than the window).
    #[arg(long)]
    pub interleave_bytes: Option<usize>,
    /// Bounds on input, output and codec window sizes.
    #[command(flatten)]
    pub limits: LimitArgs,
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() > u64::try_from(limit).map_err(|_| Error::Limit("input size"))? {
        return Err(Error::Limit("input size"));
    }
    let mut data = Vec::new();
    let mut chunk = [0u8; 32768];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            return Ok(data);
        }
        if data
            .len()
            .checked_add(count)
            .is_none_or(|length| length > limit)
        {
            return Err(Error::Limit("input size"));
        }
        data.try_reserve(count).map_err(|_| Error::Allocation)?;
        data.extend_from_slice(&chunk[..count]);
    }
}

fn sha256_argument(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(Error::Invalid(
            "expected SHA256 must contain 64 hexadecimal digits",
        ));
    }
    fn digit(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(Error::Invalid(
                "expected SHA256 contains a non-hexadecimal digit",
            )),
        }
    }
    let mut hash = [0u8; 32];
    for (output, pair) in hash.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(hash)
}

/// Prints a PA19, PA30 or PA31 header as JSON without reconstructing its payload.
pub fn inspect(args: &InspectArgs) -> Result<()> {
    let delta = read_bounded(&args.delta, args.limits.max_input_bytes)?;
    let limits = args.limits.limits();
    let json = if delta.starts_with(b"PA19") {
        serde_json::to_string_pretty(&crate::pa19::inspect_pa19(&delta, &limits)?)
    } else if delta.starts_with(b"PA31") {
        serde_json::to_string_pretty(&crate::pa30::inspect_pa31(&delta, &limits)?)
    } else {
        serde_json::to_string_pretty(&crate::pa30::inspect_pa30(&delta, &limits)?)
    }
    .map_err(|_| Error::Invalid("delta metadata could not be serialized"))?;
    println!("{json}");
    Ok(())
}

fn ensure_new_output(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::Invalid("output already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|error| Error::Io(error.error))?;
    Ok(())
}

/// Encodes and verifies a patch before atomically publishing a new file.
pub fn create(args: &CreateArgs) -> Result<()> {
    ensure_new_output(&args.output)?;
    if matches!(args.format, Format::Pa30 | Format::Pa31) && args.window_order.is_some() {
        return Err(Error::Invalid("window-order applies only to LZXD and PA19"));
    }
    if args.interleave_bytes.is_some() && !matches!(args.format, Format::Pa19) {
        return Err(Error::Invalid("interleave-bytes applies only to PA19"));
    }
    if args.pe && !matches!(args.format, Format::Pa19 | Format::Pa30 | Format::Pa31) {
        return Err(Error::Invalid("pe applies only to PA19/PA30/PA31 creation"));
    }
    if args.e8.is_some() && !matches!(args.format, Format::Pa19) {
        return Err(Error::Invalid("e8 applies only to PA19 creation"));
    }
    let limits = args.limits.limits();
    let source = args
        .source
        .as_deref()
        .map(|path| read_bounded(path, limits.max_source_bytes))
        .transpose()?
        .unwrap_or_default();
    let target = read_bounded(
        &args.target,
        args.limits.max_input_bytes.min(limits.max_output_bytes),
    )?;
    let (delta, reconstructed) = match args.format {
        Format::Pa30 => {
            let delta = if args.pe {
                crate::pa30::create_pa30_pe(&source, &target, &limits)?
            } else {
                crate::pa30::create_pa30(&source, &target, &limits)?
            };
            let reconstructed = crate::pa30::apply_pa30(&source, &delta, &limits)?;
            (delta, reconstructed)
        }
        Format::Pa31 => {
            let delta = if args.pe {
                crate::pa30::create_pa31_pe(&source, &target, &limits)?
            } else {
                crate::pa30::create_pa31(&source, &target, &limits)?
            };
            let reconstructed = crate::pa30::apply_pa31(&source, &delta, &limits)?;
            (delta, reconstructed)
        }
        Format::Pa19 => {
            let mut options = crate::pa19::Pa19CreateOptions {
                window_order: args.window_order,
                pe: if args.pe {
                    crate::pa19::Pa19Pe::Auto
                } else {
                    crate::pa19::Pa19Pe::Off
                },
                e8: match args.e8.unwrap_or_default() {
                    E8Mode::Off => crate::pa19::Pa19E8::Off,
                    E8Mode::On => crate::pa19::Pa19E8::On,
                    E8Mode::Auto => crate::pa19::Pa19E8::Auto,
                },
                ..Default::default()
            };
            if let Some(bytes) = args.interleave_bytes {
                let order = args.window_order.unwrap_or(23);
                options.window_order = Some(order);
                options.interleave =
                    crate::pa19::plan_interleave(source.len(), target.len(), order, bytes);
            }
            let delta = crate::pa19::create_pa19_with(&source, &target, &options, &limits)?;
            let reconstructed = crate::pa19::apply_pa19(&source, &delta, &limits)?;
            (delta, reconstructed)
        }
        Format::Lzxd => {
            let order = args.window_order.unwrap_or(17);
            let delta = crate::create_lzxd(&source, &target, order, &limits)?;
            let reconstructed = crate::apply_lzxd(&source, &delta, target.len(), order, &limits)?;
            (delta, reconstructed)
        }
    };
    if reconstructed != target {
        return Err(Error::Integrity(
            "created patch does not reconstruct target",
        ));
    }
    publish(&args.output, &delta)?;
    println!(
        "Created {} patch bytes for {} target bytes at {}",
        delta.len(),
        target.len(),
        args.output.display()
    );
    Ok(())
}

/// Decodes, checks integrity, and atomically publishes a new target file.
pub fn apply(args: &ApplyArgs) -> Result<()> {
    let expected = args
        .expected_sha256
        .as_deref()
        .map(sha256_argument)
        .transpose()?;
    ensure_new_output(&args.output)?;
    match args.format {
        Format::Pa19 | Format::Pa30 | Format::Pa31
            if args.target_size.is_some() || args.window_order.is_some() =>
        {
            return Err(Error::Invalid(
                "target-size and window-order apply only to LZXD",
            ));
        }
        Format::Lzxd if args.target_size.is_none() => {
            return Err(Error::Invalid("LZXD requires an exact target-size"));
        }
        _ => {}
    }
    let limits = args.limits.limits();
    let delta = read_bounded(&args.delta, limits.max_patch_bytes)?;
    let source = args
        .source
        .as_deref()
        .map(|path| read_bounded(path, limits.max_source_bytes))
        .transpose()?
        .unwrap_or_default();
    let output = match args.format {
        Format::Pa30 => crate::pa30::apply_pa30(&source, &delta, &limits)?,
        Format::Pa31 => crate::pa30::apply_pa31(&source, &delta, &limits)?,
        Format::Pa19 => crate::pa19::apply_pa19(&source, &delta, &limits)?,
        Format::Lzxd => crate::apply_lzxd(
            &source,
            &delta,
            args.target_size
                .ok_or(Error::Invalid("missing target-size"))?,
            args.window_order.unwrap_or(17),
            &limits,
        )?,
    };
    let hash = Sha256::digest(&output);
    if expected
        .as_ref()
        .is_some_and(|expected| expected.as_slice() != hash.as_slice())
    {
        return Err(Error::Integrity("independently expected target SHA256"));
    }
    publish(&args.output, &output)?;
    println!(
        "Reconstructed {} bytes to {}",
        output.len(),
        args.output.display()
    );
    Ok(())
}
