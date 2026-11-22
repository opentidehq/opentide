//! The encoder, for a crate's `build.rs` (feature `encode`, as a build
//! dependency: it runs on the host and ships in no artifact).
//!
//! ```ignore
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Every `opentide_dataset::text!` of a path under the assets root, in src/.
//!     opentide_dataset::build::Datasets::for_crate("data/catalogs")?.text_from_sources()?;
//!     Ok(())
//! }
//! ```
//!
//! Every blob is decoded again before the build goes on, and compared with its
//! input, so a blob that does not round-trip fails the build and never ships.

use crate::{HEADER_LEN, Kind, MAGIC, VERSION};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// zstd's level for a dataset: high, because the build pays once and every
/// process decodes at the same speed whatever the level. 22 gains under 2% on
/// the datasets here, for several times the build time.
pub const LEVEL: i32 = 19;

/// A build that failed to write a blob.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// A variable cargo sets for a build script is not set.
    #[error("{0} is not set: Datasets runs in a build script")]
    NoEnv(&'static str),
    /// A source file or the output directory.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// What failed.
        source: std::io::Error,
    },
    /// The dataset is larger than the header's length field.
    #[error("{0}: more than 4 GiB")]
    TooLarge(String),
    /// A model that does not serialise.
    #[error("{name}: {message}")]
    Serialize {
        /// The dataset.
        name: String,
        /// Postcard's message.
        message: String,
    },
    /// A blob that did not decode to its own input.
    #[error("{name}: the blob does not round-trip: {message}")]
    RoundTrip {
        /// The dataset.
        name: String,
        /// What differed.
        message: String,
    },
}

/// The blobs of one crate, written to its `OUT_DIR` as `<path>.otd`, where
/// `<path>` is the dataset's path under the assets root (the string
/// [`text!`](crate::text) is given), or a name the crate chose
/// ([`Datasets::value`]).
#[derive(Debug)]
pub struct Datasets {
    root: PathBuf,
    out: PathBuf,
}

impl Datasets {
    /// A crate's datasets: the files under the workspace root in a checkout
    /// (when `marker`, a path under it, is a directory there), or else under
    /// the `assets/` copy `scripts/engine/release.py vendor` puts inside a
    /// published crate. The checkout wins, so a copy left behind never
    /// shadows the real files. Also sets `OPENTIDE_ASSETS` to that root, which
    /// tests of the crate read their fixtures from.
    ///
    /// # Errors
    ///
    /// `OUT_DIR` or `CARGO_MANIFEST_DIR` is not set.
    pub fn for_crate(marker: &str) -> Result<Self, BuildError> {
        let var = |name: &'static str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .ok_or(BuildError::NoEnv(name))
        };
        let manifest = var("CARGO_MANIFEST_DIR")?;
        let workspace = manifest.join("../..");
        // A packaged crate builds under target/package/ or the registry, where
        // ../.. has no such directory.
        let root = if workspace.join(marker).is_dir() {
            workspace
        } else {
            manifest.join("assets")
        };
        println!("cargo:rustc-env=OPENTIDE_ASSETS={}", root.display());
        println!("cargo:rerun-if-changed=build.rs");
        Ok(Self {
            root,
            out: var("OUT_DIR")?,
        })
    }

    /// The directory the datasets are read from.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes the blob of every dataset the crate's sources name with
    /// `opentide_dataset::text!` of a path, and tells cargo to rerun the build
    /// when a source changes: a text added in the code is encoded by the next
    /// build, with no list to keep. Returns the number of datasets.
    ///
    /// # Errors
    ///
    /// A source does not read, or a named file does not exist.
    pub fn text_from_sources(&self) -> Result<usize, BuildError> {
        let manifest = std::env::var_os("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .ok_or(BuildError::NoEnv("CARGO_MANIFEST_DIR"))?;
        let src = manifest.join("src");
        println!("cargo:rerun-if-changed={}", src.display());
        let mut found = std::collections::BTreeSet::new();
        scan(&src, &mut found)?;
        for rel in &found {
            self.text(rel)?;
        }
        Ok(found.len())
    }

    /// Writes the text of `rel` (a path under the root) as the blob `rel`, and
    /// tells cargo to rerun the build when the file changes. Returns the
    /// compressed size.
    ///
    /// # Errors
    ///
    /// The file does not read, or the blob does not round-trip.
    pub fn text(&self, rel: &str) -> Result<usize, BuildError> {
        let source = self.root.join(rel);
        println!("cargo:rerun-if-changed={}", source.display());
        let bytes = std::fs::read(&source).map_err(|error| BuildError::Io {
            path: source.clone(),
            source: error,
        })?;
        // The file is stored as written; a catalog read with CRLF line endings
        // (a Windows checkout without `-text`) would differ by OS.
        self.write(rel, Kind::Text, &bytes)
    }

    /// Writes `text`, derived from the files `sources` (paths under the root, which cargo is told
    /// to watch), as the blob `name`, which [`text_blob!`](crate::text_blob) reads.
    ///
    /// # Errors
    ///
    /// The blob does not round-trip.
    pub fn text_named(
        &self,
        name: &str,
        sources: &[&str],
        text: &str,
    ) -> Result<usize, BuildError> {
        for source in sources {
            println!(
                "cargo:rerun-if-changed={}",
                self.root.join(source).display()
            );
        }
        self.write(name, Kind::Text, text.as_bytes())
    }

    /// Writes the pre-parsed form `model`, serialised with postcard, as the
    /// blob `name`. The caller read `model` from `sources` (paths under the
    /// root), which cargo is told to watch.
    ///
    /// # Errors
    ///
    /// The model does not serialise, or the blob does not round-trip.
    pub fn value<T: Serialize>(
        &self,
        name: &str,
        sources: &[&str],
        model: &T,
    ) -> Result<usize, BuildError> {
        for source in sources {
            println!(
                "cargo:rerun-if-changed={}",
                self.root.join(source).display()
            );
        }
        let bytes = postcard::to_stdvec(model).map_err(|error| BuildError::Serialize {
            name: name.to_owned(),
            message: error.to_string(),
        })?;
        self.write(name, Kind::Postcard, &bytes)
    }

    /// Writes `bytes` as the blob `name`.
    fn write(&self, name: &str, kind: Kind, bytes: &[u8]) -> Result<usize, BuildError> {
        let blob = encode(name, kind, bytes)?;
        let decoded = crate::decode(&blob, kind).map_err(|error| BuildError::RoundTrip {
            name: name.to_owned(),
            message: error.to_string(),
        })?;
        if decoded != bytes {
            return Err(BuildError::RoundTrip {
                name: name.to_owned(),
                message: "the bytes differ".to_owned(),
            });
        }
        let path = self.out.join(format!("{name}.otd"));
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|source| BuildError::Io {
                path: dir.to_owned(),
                source,
            })?;
        }
        std::fs::write(&path, &blob).map_err(|source| BuildError::Io { path, source })?;
        Ok(blob.len())
    }
}

/// The string literals that follow each `call` in `text` (rustfmt may put the
/// literal on a line of its own).
fn named(text: &str, call: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(call) {
        rest = rest[at + call.len()..].trim_start();
        if let Some(literal) = rest.strip_prefix('"')
            && let Some(end) = literal.find('"')
        {
            paths.push(literal[..end].to_owned());
        }
    }
    paths
}

/// The paths `opentide_dataset::text!` names in the `.rs` files under
/// `dir`.
fn scan(dir: &Path, found: &mut std::collections::BTreeSet<String>) -> Result<(), BuildError> {
    const CALL: &str = "opentide_dataset::text!(";
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| BuildError::Io { path, source }
    };
    for entry in std::fs::read_dir(dir).map_err(io(dir))? {
        let path = entry.map_err(io(dir))?.path();
        if path.is_dir() {
            scan(&path, found)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).map_err(io(&path))?;
            found.extend(named(&text, CALL));
        }
    }
    Ok(())
}

/// The blob for `bytes`: header, then one zstd frame, whose
/// window is no larger than the dataset (a decoder allocates the window).
///
/// # Errors
///
/// `bytes` is longer than the header's length field, or zstd fails.
pub fn encode(name: &str, kind: Kind, bytes: &[u8]) -> Result<Vec<u8>, BuildError> {
    let len = u32::try_from(bytes.len()).map_err(|_| BuildError::TooLarge(name.to_owned()))?;
    let io = |source| BuildError::Io {
        path: PathBuf::from(name),
        source,
    };
    let mut compressor = zstd::bulk::Compressor::new(LEVEL).map_err(io)?;
    compressor.include_checksum(false).map_err(io)?;
    compressor.include_contentsize(true).map_err(io)?;
    let window_log = bytes
        .len()
        .max(1 << 10)
        .next_power_of_two()
        .trailing_zeros();
    compressor
        .set_parameter(zstd::zstd_safe::CParameter::WindowLog(window_log.min(27)))
        .map_err(io)?;
    let frame = compressor.compress(bytes).map_err(io)?;
    let mut blob = Vec::with_capacity(HEADER_LEN + frame.len());
    blob.extend_from_slice(&MAGIC);
    blob.push(VERSION);
    blob.push(kind.byte());
    blob.extend_from_slice(&len.to_le_bytes());
    blob.extend_from_slice(&frame);
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scan_reads_a_literal_on_its_own_line() {
        let source = "a = opentide_dataset::text!(\"data/a.toml\");\n\
                      b = opentide_dataset::text!(\n    \"data/b.toml\"\n);\n\
                      c = opentide_dataset::text!(NAME);";
        assert_eq!(
            named(source, "opentide_dataset::text!("),
            ["data/a.toml", "data/b.toml"]
        );
    }

    #[test]
    fn a_blob_round_trips_and_is_smaller_than_its_text() {
        let text = "[[keys]]\nname = \"x\"\n".repeat(200);
        let blob = encode("t", Kind::Text, text.as_bytes()).unwrap();
        assert!(blob.len() < text.len() / 4);
        assert_eq!(crate::text(&blob).unwrap(), text);
        assert_eq!(crate::raw_len(&blob).unwrap(), text.len());
    }

    #[test]
    fn a_pre_parsed_model_round_trips() {
        let model = vec![("a".to_owned(), 1_u32), ("b".to_owned(), 2)];
        let bytes = postcard::to_stdvec(&model).unwrap();
        let blob = encode("m", Kind::Postcard, &bytes).unwrap();
        assert_eq!(crate::value::<Vec<(String, u32)>>(&blob).unwrap(), model);
        assert!(matches!(
            crate::text(&blob),
            Err(crate::DatasetError::WrongKind { .. })
        ));
    }

    #[test]
    fn damage_is_an_error_not_a_panic() {
        let blob = encode("t", Kind::Text, b"hello hello hello hello").unwrap();
        assert_eq!(crate::text(&blob[..4]), Err(crate::DatasetError::NotABlob));
        assert!(matches!(
            crate::text(&blob[..blob.len() - 3]),
            Err(crate::DatasetError::Frame(_) | crate::DatasetError::Length { .. })
        ));
        let mut wrong = blob.clone();
        wrong[3] = 9;
        assert_eq!(crate::text(&wrong), Err(crate::DatasetError::Version(9)));
    }

    /// A header that states 4 GiB is a length error, not a 4 GiB reservation (which aborts the
    /// process, and panics on wasm32): the reservation is capped and the decode stops at the
    /// stated length.
    #[test]
    fn a_crafted_length_is_an_error_not_an_allocation() {
        let blob = encode("t", Kind::Text, b"hello hello hello hello").unwrap();
        let mut huge = blob.clone();
        huge[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            crate::text(&huge),
            Err(crate::DatasetError::Length { .. })
        ));
        // And one that states less than the frame holds stops there, as a length error.
        let mut short = blob;
        short[5..9].copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            crate::text(&short),
            Err(crate::DatasetError::Length {
                expected: 3,
                actual: 4
            })
        ));
    }
}
