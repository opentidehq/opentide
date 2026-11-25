//! A vocabulary that cannot be read.

/// A vocabulary that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VocabError {
    /// A file name without the `.vocab.toml` suffix.
    #[error("not a vocabulary file: {0}")]
    NotAVocabularyFile(String),
    /// The document is not TOML.
    #[error("could not read vocabulary TOML {file}: {message}")]
    Toml {
        /// The file.
        file: String,
        /// The parser's message.
        message: String,
    },
    /// A required top-level key is missing.
    #[error("missing required key {key:?} in vocabulary document: {file}")]
    MissingKey {
        /// The file.
        file: String,
        /// The key.
        key: String,
    },
    /// A top-level key has the wrong type or value.
    #[error("invalid {key:?} in vocabulary document {file}: {why}")]
    InvalidKey {
        /// The file.
        file: String,
        /// The key.
        key: String,
        /// What is wrong with it.
        why: String,
    },
    /// The document's `field` is not its file name's stem.
    #[error("vocabulary field {field:?} does not match filename {expected:?} in {file}")]
    FieldMismatch {
        /// The file.
        file: String,
        /// The `field` the document declares.
        field: String,
        /// The file name's stem.
        expected: String,
    },
    /// Two entries share a key.
    #[error("duplicate entry key {key:?} in vocabulary {file} at index {index}")]
    DuplicateKey {
        /// The file.
        file: String,
        /// The key.
        key: String,
        /// The second entry's index.
        index: usize,
    },
    /// A version that is not `M.m`.
    #[error("invalid vocabulary version: {0:?}")]
    InvalidVersion(String),
    /// A contract that is not `field::M.m`.
    #[error("invalid vocabulary contract: {0:?}")]
    InvalidContract(String),
}
