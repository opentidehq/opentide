//! Generation (UC-3.2, #824): the files `opentide generate exports` writes,
//! and what writing them takes.
//!
//! - [`relations`]: an object's parents and children (`generation/framework.py`
//!   `parents`, `childs`, `get_type`).
//! - [`exports`]: the ATT&CK Navigator layer, the objects table and the
//!   revisions snapshot (`export/`).
//! - [`json_text`]: JSON written as `json.dumps(..., indent=n)` lays it out
//!   (serde_json's pretty printer, non-ASCII escaped).
//! - [`files`]: writing [`Output`]s in parallel (rayon), and [`files::Snapshot`],
//!   the files a phase wrote found by modification time and size.
//!
//! Rendering is pure: a phase returns its [`Output`]s or a [`PhaseError`];
//! only [`files`] touches the disk.

pub mod exports;
pub mod files;
pub mod json_text;
pub mod relations;

use std::path::PathBuf;

/// One file a phase writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Where it goes.
    pub path: PathBuf,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

impl Output {
    /// A text file.
    pub fn text(path: PathBuf, text: String) -> Self {
        Self {
            path,
            bytes: text.into_bytes(),
        }
    }
}

/// Why a phase stopped: the message after the phase's name
/// (`KeyError: 'objective' while rendering <uuid>`), as the oracle's
/// `GenerationPhaseError` words it (`generation/errors.py`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct PhaseError {
    /// What went wrong.
    pub detail: String,
}

impl PhaseError {
    /// A failure not tied to one object.
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// A failure while rendering the object `uuid` (`ObjectGenerationError`).
    pub fn rendering(uuid: &str, cause: &Cause) -> Self {
        Self::new(format!("{cause} while rendering {uuid}"))
    }
}

/// What an object's rendering stopped on, named as the oracle names the
/// exception it raised: a missing key (`KeyError: 'tlp'`) or a broken
/// reference (`Exception: detection_model … does not exist in the catalogue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// A key the object must have.
    MissingKey(String),
    /// Anything else, with its message.
    Other(String),
}

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey(key) => write!(
                f,
                "KeyError: {}",
                opentide_schema::configuration::repr::quote(key)
            ),
            Self::Other(message) => write!(f, "Exception: {message}"),
        }
    }
}

impl From<crate::attack::MissingKey> for Cause {
    fn from(missing: crate::attack::MissingKey) -> Self {
        Self::MissingKey(missing.0)
    }
}
