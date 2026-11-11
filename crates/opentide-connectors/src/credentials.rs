//! Credentials: `$VARIABLE` resolution, and a value that never prints.
//!
//! A tenant's setup names its secrets as `$NAME` or `${NAME}` (the one parser
//! `opentide_workspace::info::env_reference` is the resolver's, `info`'s and
//! `doctor`'s). A command that sends nothing (a dry run, `info`, a count)
//! resolves them in [`Mode::Counting`]: an unset variable becomes a
//! [`Credential::Placeholder`], as the vscode-extension contract expects. A
//! command that reaches the tenant resolves them in [`Mode::Required`]: an
//! unset variable is an error naming the variable, never a value.

use std::fmt;

use crate::Environment;
use crate::error::ConnectorError;

/// A secret value. `Debug` and `Display` print `***`: only [`Secret::expose`]
/// gives the value, at the one place it is sent.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// A secret holding *value*.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value, to send to the tenant.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

/// How an unset variable is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The command sends nothing: an unset variable is a placeholder.
    Counting,
    /// The command reaches the tenant: an unset variable is an error.
    Required,
}

/// A resolved setup value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// The value to send.
    Value(Secret),
    /// `$NAME` whose variable is unset, in a command that sends nothing.
    Placeholder {
        /// The variable's name.
        variable: String,
    },
}

impl Credential {
    /// The value, when there is one.
    pub fn secret(&self) -> Option<&Secret> {
        match self {
            Self::Value(secret) => Some(secret),
            Self::Placeholder { .. } => None,
        }
    }
}

/// What resolving one value gave, with what a person should be told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The credential.
    pub credential: Credential,
    /// Set when the value was read the 0.21.0 way: `$text` from the variable
    /// `text`, though `text` is not a variable name (`$AZ-SECRET`). The run
    /// warns once with the name to write instead.
    pub legacy_variable: Option<String>,
}

/// Where a value comes from: the platform, tenant and setup key, for errors.
#[derive(Clone, Copy, Debug)]
pub struct Origin<'a> {
    /// The platform's identifier.
    pub platform: &'a str,
    /// The tenant's name.
    pub tenant: &'a str,
    /// The setup key.
    pub key: &'a str,
}

/// Resolves one setup *value* against *env*.
///
/// `$NAME` and `${NAME}` as a whole read the variable. Any other value is
/// itself, a literal starting with `$` included, unless the text after the
/// `$` is a variable that is set: 0.21.0 and earlier read `$text` from
/// `text`, so a set one keeps working, with [`Resolved::legacy_variable`].
pub fn resolve(
    value: &str,
    env: &Environment,
    mode: Mode,
    origin: Origin<'_>,
) -> Result<Resolved, ConnectorError> {
    if let Some(variable) = opentide_workspace::info::env_reference(value) {
        let credential = match (env.raw(variable).filter(|v| !v.is_empty()), mode) {
            (Some(found), _) => Credential::Value(Secret::new(found)),
            (None, Mode::Counting) => Credential::Placeholder {
                variable: variable.to_owned(),
            },
            (None, Mode::Required) => {
                return Err(ConnectorError::MissingCredential {
                    platform: origin.platform.to_owned(),
                    tenant: origin.tenant.to_owned(),
                    key: origin.key.to_owned(),
                    variable: variable.to_owned(),
                });
            }
        };
        return Ok(Resolved {
            credential,
            legacy_variable: None,
        });
    }
    if let Some(name) = value.strip_prefix('$')
        && !name.is_empty()
        && let Some(found) = env.raw(name)
    {
        return Ok(Resolved {
            credential: Credential::Value(Secret::new(found)),
            legacy_variable: Some(name.to_owned()),
        });
    }
    Ok(Resolved {
        credential: Credential::Value(Secret::new(value)),
        legacy_variable: None,
    })
}
