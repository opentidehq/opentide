//! The datasets opentide compiles in, compressed at build time and decoded
//! once per process, on first use (#1743).
//!
//! A vocabulary, a language catalog or a template used to be `include_str!`d as
//! plain text. Plain text puts the words of every security vocabulary (stealer
//! names, injection API names, miner domains) into every binary, where antivirus
//! heuristics read them as the binary's own. Each dataset is now one blob,
//! written by its crate's build script (`build`) and decoded here:
//!
//! ```text
//! "OTD" | version (1) | kind (1) | raw length (u32, little endian) | zstd frame
//! ```
//!
//! - `kind` 0 is the dataset's text; kind 1 is its pre-parsed form, a model
//!   serialised with postcard (the build script parsed the TOML once).
//! - The frame is zstd at a high level, one dataset to a frame, so a command decodes only the datasets it reads.
//! - The decoder is `ruzstd`, pure Rust: `wasm32-unknown-unknown` and
//!   `wasm32-wasip1` build it with no C toolchain.
//!
//! This is compression, not obfuscation: no key, no XOR, no packer, and code is
//! never compressed. `docs/internal/datasets.md` describes the format, the
//! decoder and the measurements.
//!
//! A crate that compiles a dataset in has a `build.rs` that calls
//! `build::Datasets` (the `encode` feature, as a build dependency) and reads
//! the blob with [`text!`] or [`value!`], each decoded once and shared.

use serde::de::DeserializeOwned;
use std::io::Read;

#[cfg(feature = "encode")]
pub mod build;

/// The blob's first bytes.
pub const MAGIC: [u8; 3] = *b"OTD";

/// The container's version, the byte after the magic.
pub const VERSION: u8 = 1;

/// The most bytes [`decode`] reserves before it has decoded any: what the header says is taken
/// on trust no further.
const MAX_RESERVE: usize = 16 * 1024 * 1024;

/// The container's header: magic, version, kind, raw length.
pub const HEADER_LEN: usize = 9;

/// What a blob holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The dataset's own text (UTF-8).
    Text,
    /// A model, serialised with postcard.
    Postcard,
}

impl Kind {
    /// The byte the header holds for this kind.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Text => 0,
            Self::Postcard => 1,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Text),
            1 => Some(Self::Postcard),
            _ => None,
        }
    }
}

/// A blob that does not decode. Compiled-in blobs are written by the build
/// script that checks them, so this is for tools that read a blob from
/// elsewhere, and for the tests.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DatasetError {
    /// The blob is shorter than a header, or does not start with the magic.
    #[error("not a dataset blob")]
    NotABlob,
    /// A container version this decoder does not read.
    #[error("dataset container version {0}, this decoder reads {VERSION}")]
    Version(u8),
    /// The header's kind byte is none of the known kinds.
    #[error("unknown dataset kind {0}")]
    UnknownKind(u8),
    /// The blob holds another kind than the caller asked for.
    #[error("the blob holds {found:?}, not {wanted:?}")]
    WrongKind {
        /// What the caller asked for.
        wanted: Kind,
        /// What the header says.
        found: Kind,
    },
    /// The zstd frame is damaged or truncated.
    #[error("zstd frame: {0}")]
    Frame(String),
    /// The frame decoded to another length than the header's.
    #[error("decoded {actual} bytes, the header says {expected}")]
    Length {
        /// The header's raw length.
        expected: usize,
        /// What the frame decoded to.
        actual: usize,
    },
    /// A text blob that is not UTF-8.
    #[error("the text is not UTF-8")]
    Utf8,
    /// A postcard blob that does not read as the model asked for.
    #[error("postcard: {0}")]
    Postcard(String),
}

/// The raw length the header of `blob` states, without decoding it.
///
/// # Errors
///
/// `blob` is not a dataset blob.
pub fn raw_len(blob: &[u8]) -> Result<usize, DatasetError> {
    Ok(header(blob)?.1)
}

fn header(blob: &[u8]) -> Result<(Kind, usize), DatasetError> {
    let Some((head, _)) = blob.split_first_chunk::<HEADER_LEN>() else {
        return Err(DatasetError::NotABlob);
    };
    if head[..3] != MAGIC {
        return Err(DatasetError::NotABlob);
    }
    if head[3] != VERSION {
        return Err(DatasetError::Version(head[3]));
    }
    let kind = Kind::from_byte(head[4]).ok_or(DatasetError::UnknownKind(head[4]))?;
    let len = u32::from_le_bytes([head[5], head[6], head[7], head[8]]);
    let len = usize::try_from(len).map_err(|_| DatasetError::NotABlob)?;
    Ok((kind, len))
}

/// The bytes of `blob`, decoded; `kind` is what the caller expects it to hold.
///
/// # Errors
///
/// The blob is damaged, of another kind, or of another version.
pub fn decode(blob: &[u8], kind: Kind) -> Result<Vec<u8>, DatasetError> {
    let (found, len) = header(blob)?;
    if found != kind {
        return Err(DatasetError::WrongKind {
            wanted: kind,
            found,
        });
    }
    let mut frame = &blob[HEADER_LEN..];
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(&mut frame)
        .map_err(|error| DatasetError::Frame(error.to_string()))?;
    // The header's length is not trusted: a crafted one must not make a reservation that aborts
    // the process (or panics, on wasm32), nor let a frame decode past the length it states. The
    // largest dataset is 3.4 MB; the vector grows from the reservation if a blob is larger.
    let mut out = Vec::with_capacity(len.min(MAX_RESERVE));
    std::io::Read::take(&mut decoder, len as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|error| DatasetError::Frame(error.to_string()))?;
    if out.len() != len {
        return Err(DatasetError::Length {
            expected: len,
            actual: out.len(),
        });
    }
    Ok(out)
}

/// A text blob, decoded.
///
/// # Errors
///
/// As [`decode`], or the text is not UTF-8.
pub fn text(blob: &[u8]) -> Result<String, DatasetError> {
    String::from_utf8(decode(blob, Kind::Text)?).map_err(|_| DatasetError::Utf8)
}

/// A pre-parsed blob, read as the model `T` its build script serialised.
///
/// # Errors
///
/// As [`decode`], or the bytes are not a `T`.
pub fn value<T: DeserializeOwned>(blob: &[u8]) -> Result<T, DatasetError> {
    postcard::from_bytes(&decode(blob, Kind::Postcard)?)
        .map_err(|error| DatasetError::Postcard(error.to_string()))
}

/// What [`text!`] calls: the text of a blob the build script wrote and
/// decoded once already (a blob that does not decode fails that build, so
/// the panic is for a binary whose own bytes were damaged, never for a user's
/// document).
#[doc(hidden)]
#[must_use]
pub fn compiled_text(name: &str, blob: &[u8]) -> String {
    text(blob).unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// What [`value!`] calls: the model of a blob the build script wrote.
#[doc(hidden)]
#[must_use]
pub fn compiled_value<T: DeserializeOwned>(name: &str, blob: &[u8]) -> T {
    value(blob).unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// What a table of datasets holds for each: a function that decodes the text on its first call
/// (a closure that calls `opentide_dataset::text!` with its path).
pub type TextFn = fn() -> &'static str;

/// The text of the dataset `$name` that the calling crate's `build.rs` wrote
/// (`build::Datasets::text`): decoded on first use, once per process, and
/// shared for the life of the process (`&'static str`).
#[macro_export]
macro_rules! text {
    ($name:literal) => {{
        static CELL: ::std::sync::OnceLock<::std::string::String> = ::std::sync::OnceLock::new();
        CELL.get_or_init(|| {
            $crate::compiled_text(
                $name,
                include_bytes!(concat!(env!("OUT_DIR"), "/", $name, ".otd")),
            )
        })
        .as_str()
    }};
}

/// The text of the blob `$name` that the calling crate's `build.rs` wrote itself
/// (`build::Datasets::text_named`): a text the build derived from a dataset, not a file of the assets
/// root (`text!` names those, and `text_from_sources` finds them). Decoded on first use, once per
/// process, and shared (`&'static str`).
#[macro_export]
macro_rules! text_blob {
    ($name:literal) => {{
        static CELL: ::std::sync::OnceLock<::std::string::String> = ::std::sync::OnceLock::new();
        CELL.get_or_init(|| {
            $crate::compiled_text(
                $name,
                include_bytes!(concat!(env!("OUT_DIR"), "/", $name, ".otd")),
            )
        })
        .as_str()
    }};
}

/// The model `$ty` of the dataset `$name` that the calling crate's `build.rs`
/// wrote pre-parsed (`build::Datasets::value`): decoded on first use, once
/// per process, and shared (`&'static $ty`).
#[macro_export]
macro_rules! value {
    ($ty:ty, $name:literal) => {{
        static CELL: ::std::sync::OnceLock<$ty> = ::std::sync::OnceLock::new();
        CELL.get_or_init(|| {
            $crate::compiled_value::<$ty>(
                $name,
                include_bytes!(concat!(env!("OUT_DIR"), "/", $name, ".otd")),
            )
        })
    }};
}

/// The blob `$name` that the calling crate's `build.rs` wrote with
/// `build::Datasets::value`, as bytes, for [`compiled_value`].
#[macro_export]
macro_rules! blob {
    ($name:literal) => {
        include_bytes!(concat!(env!("OUT_DIR"), "/", $name, ".otd")).as_slice()
    };
}
