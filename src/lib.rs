//! Native Rust file patches using PA30, PA31 and MS-PATCH LZX Delta.
//!
//! These codecs reconstruct bytes. They do not install Windows packages, update
//! component-store state, establish catalog trust, or replace CBS servicing.
//!
//! Default features enable all formats and metadata serialization. Disable defaults
//! and select `lzxd`, `pa19`, `pa30`, or `pa31` for a smaller library. PA19 includes
//! LZX Delta; PA31 includes PA30. `serde` enables metadata serialization, and `cli`
//! enables the complete command-line tool. The library requires `std` in every build.
#![forbid(unsafe_code)]

use std::{fmt, io};

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "lzxd")]
mod lzxd_encode;
#[cfg(feature = "pa19")]
pub mod pa19;
#[cfg(feature = "pa30")]
pub mod pa30;

#[cfg(feature = "lzxd")]
pub use lzxd_encode::create_lzxd;

/// Resource bounds checked before reconstruction or untrusted-size allocation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum decoded target size.
    pub max_output_bytes: usize,
    /// Maximum encoded patch size.
    pub max_patch_bytes: usize,
    /// Maximum supplied reference/source size.
    pub max_source_bytes: usize,
    /// Maximum LZX Delta history window size.
    pub max_window_bytes: usize,
    /// Bound for each parameter/table/encoder workspace, not total process memory.
    pub max_parameter_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_output_bytes: 64 * 1024 * 1024,
            max_patch_bytes: 64 * 1024 * 1024,
            max_source_bytes: 64 * 1024 * 1024,
            max_window_bytes: 32 * 1024 * 1024,
            max_parameter_bytes: 8 * 1024 * 1024,
        }
    }
}

/// A malformed, unsupported, excessive, or corrupt delta input.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The input violates the encoded format.
    Invalid(&'static str),
    /// A recognized format feature has not been implemented and validated.
    Unsupported(&'static str),
    /// A caller-selected resource bound was exceeded.
    Limit(&'static str),
    /// Reconstructed bytes disagree with an expected hash or size.
    Integrity(&'static str),
    /// The allocator could not reserve a required buffer.
    Allocation,
    /// The underlying compression codec rejected its input.
    Codec(String),
    /// Input or output failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid delta: {reason}"),
            Self::Unsupported(reason) => write!(f, "unsupported delta feature: {reason}"),
            Self::Limit(reason) => write!(f, "delta limit exceeded: {reason}"),
            Self::Integrity(reason) => write!(f, "delta integrity check failed: {reason}"),
            Self::Allocation => f.write_str("delta buffer allocation failed"),
            Self::Codec(reason) => write!(f, "LZX Delta decode failed: {reason}"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Result of a bounded delta operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Applies framed MS-PATCH LZX Delta to a reference buffer.
///
/// The format does not identify its target length or window size. The caller
/// supplies both; `window_order` is the base-two logarithm of the history size.
/// A separate expected target hash should be checked when one is available.
#[cfg(feature = "lzxd")]
pub fn apply_lzxd(
    source: &[u8],
    delta: &[u8],
    target_size: usize,
    window_order: u8,
    limits: &Limits,
) -> Result<Vec<u8>> {
    if source.len() > limits.max_source_bytes {
        return Err(Error::Limit("source size"));
    }
    if delta.len() > limits.max_patch_bytes {
        return Err(Error::Limit("patch size"));
    }
    if target_size > limits.max_output_bytes {
        return Err(Error::Limit("target size"));
    }
    if !(17..=25).contains(&window_order) {
        return Err(Error::Invalid(
            "LZX Delta window order must be 17 through 25",
        ));
    }
    let window = 1usize
        .checked_shl(u32::from(window_order))
        .ok_or(Error::Limit("window size"))?;
    if window > limits.max_window_bytes {
        return Err(Error::Limit("window size"));
    }
    if source.len() > window - 3 {
        return Err(Error::Invalid(
            "LZX Delta reference exceeds history window minus three bytes",
        ));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(target_size)
        .map_err(|_| Error::Allocation)?;
    output.resize(target_size, 0);
    ms_compress::lzx::decompress_lzxd(delta, source, &mut output, window_order)
        .map_err(|error| Error::Codec(error.to_string()))?;
    Ok(output)
}
