//! The facade's one error type, each variant with a stable code.

use std::path::PathBuf;

/// Why an operation of the facade failed.
///
/// Each variant maps to a stable code ([`Error::code`]): the code a binding
/// reports, and the one a program should match on. The message
/// ([`std::fmt::Display`]) is for people and may change between releases.
/// New variants may be added in a minor release, so a `match` needs a
/// wildcard arm.
///
/// | Variant | Code |
/// |---------|------|
/// | [`Error::Configuration`] | the configuration's own code (`config_parse`, `retired_configuration_file`, ...), else `configuration_invalid` |
/// | [`Error::Io`] | `io_error` |
/// | [`Error::Usage`] | the command line's usage code (`usage_missing_option`, `usage_invalid_choice`, `usage_invalid_value`) |
/// | [`Error::NoDocument`] | `no_json_document` |
/// | [`Error::Lsp`] | `lsp_failed` |
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The workspace's configuration (`.opentide/configurations/`) does not
    /// resolve: every command stops on it.
    #[error("{message}")]
    Configuration {
        /// The stable code: the configuration check's, or
        /// `configuration_invalid`.
        code: &'static str,
        /// What is wrong, naming the file.
        message: String,
    },
    /// A file or folder could not be read.
    #[error("{}: {message}", path.display())]
    Io {
        /// The path.
        path: PathBuf,
        /// Why.
        message: String,
    },
    /// An option has a value the operation cannot use (a strategy that is not
    /// one, a missing strategy): the command line's usage error.
    #[error("{message}")]
    Usage {
        /// The command line's code for it.
        code: &'static str,
        /// What to pass instead.
        message: String,
    },
    /// A command run for its JSON document wrote none (it was interrupted, or
    /// its output is not JSON).
    #[error("the command wrote no JSON document (exit {exit_code}): {stderr}")]
    NoDocument {
        /// The command's exit code.
        exit_code: i32,
        /// What it wrote on stderr.
        stderr: String,
    },
    /// The language server stopped on an error of its transport.
    #[error("language server: {message}")]
    Lsp {
        /// What failed.
        message: String,
    },
}

impl Error {
    /// The code `configuration_invalid`: a configuration error without a code
    /// of its own (a `paths.toml` that does not fit its model).
    pub const CONFIGURATION_INVALID: &'static str = "configuration_invalid";

    /// The stable code of this error (the table on [`Error`]).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Configuration { code, .. } | Self::Usage { code, .. } => code,
            Self::Io { .. } => "io_error",
            Self::NoDocument { .. } => "no_json_document",
            Self::Lsp { .. } => "lsp_failed",
        }
    }
}

#[cfg(feature = "workspace")]
impl From<opentide_workspace::ConfigError> for Error {
    fn from(error: opentide_workspace::ConfigError) -> Self {
        Self::Configuration {
            code: error.code().unwrap_or(Self::CONFIGURATION_INVALID),
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_its_code() {
        let cases = [
            (
                Error::Configuration {
                    code: "config_parse",
                    message: "paths.toml: bad".into(),
                },
                "config_parse",
                "paths.toml: bad",
            ),
            (
                Error::Io {
                    path: PathBuf::from("ws"),
                    message: "not found".into(),
                },
                "io_error",
                "ws: not found",
            ),
            (
                Error::Usage {
                    code: "usage_invalid_choice",
                    message: "Use PREVIEW or RELEASE".into(),
                },
                "usage_invalid_choice",
                "Use PREVIEW or RELEASE",
            ),
            (
                Error::NoDocument {
                    exit_code: 130,
                    stderr: "error: interrupted".into(),
                },
                "no_json_document",
                "the command wrote no JSON document (exit 130): error: interrupted",
            ),
            (
                Error::Lsp {
                    message: "broken pipe".into(),
                },
                "lsp_failed",
                "language server: broken pipe",
            ),
        ];
        for (error, code, message) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), message);
        }
    }

    #[cfg(feature = "workspace")]
    #[test]
    fn a_configuration_error_keeps_its_code_or_takes_the_default() {
        let paths = opentide_workspace::ConfigError::Paths(vec!["unknown key".into()]);
        let error = Error::from(paths);
        assert_eq!(error.code(), Error::CONFIGURATION_INVALID);
        assert_eq!(error.to_string(), "paths.toml: unknown key");

        let unreadable = opentide_workspace::ConfigError::Unreadable {
            path: "paths.toml".into(),
            message: "not UTF-8".into(),
        };
        assert_eq!(Error::from(unreadable).code(), "config_parse");
    }
}
