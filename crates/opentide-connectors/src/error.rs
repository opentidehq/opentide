//! What can go wrong between opentide and a tenant, and the failure code each
//! is reported with.
//!
//! The messages name the platform, the tenant and the tenant's address
//! (scheme, host and port: never a path, a query or credentials), as the
//! Python transport layer's `TenantUnreachableError` does. A credential never
//! reaches a message: the request's URL is dropped from every reqwest error
//! before its text is read ([`describe`]).

use std::error::Error as _;

/// The `failure.code` of a command that failed for a reason not more
/// specific (docs/cli/exit-codes.md): every tenant failure.
pub const COMMAND_FAILED: &str = "command_failed";
/// The `failure.code` of a run stopped by Ctrl-C or a client's cancellation.
pub const INTERRUPTED: &str = "interrupted";

/// A failure to reach, or to be answered by, one tenant.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// The connection, DNS, TLS or the proxy failed before the tenant took
    /// the request (Python's `_CONNECT_ERRORS`).
    #[error("Cannot reach {platform} tenant '{tenant}' at {address}: {reason}")]
    Unreachable {
        /// The platform's identifier.
        platform: String,
        /// The tenant's name.
        tenant: String,
        /// `scheme://host[:port]` of the request.
        address: String,
        /// What failed, without the URL.
        reason: String,
    },
    /// The tenant took the request and sent no answer in time (a read
    /// timeout: one query outlived the timeout, the tenant is not down).
    #[error("{platform} tenant '{tenant}' at {address} sent no answer within {seconds}s")]
    Timeout {
        /// The platform's identifier.
        platform: String,
        /// The tenant's name.
        tenant: String,
        /// `scheme://host[:port]` of the request.
        address: String,
        /// The timeout, in seconds.
        seconds: u64,
    },
    /// The request was answered, but the answer could not be read.
    #[error("{platform} tenant '{tenant}' at {address}: {reason}")]
    Answer {
        /// The platform's identifier.
        platform: String,
        /// The tenant's name.
        tenant: String,
        /// `scheme://host[:port]` of the request.
        address: String,
        /// What failed.
        reason: String,
    },
    /// A tenant's settings that cannot be used: an `ssl` that is not true or
    /// false, a CA bundle that cannot be read, a proxy URL that is not one.
    #[error("{platform} tenant '{tenant}' setup: {message}")]
    Setup {
        /// The platform's identifier.
        platform: String,
        /// The tenant's name.
        tenant: String,
        /// What is wrong.
        message: String,
    },
    /// A credential's environment variable is unset.
    #[error(
        "{platform} tenant '{tenant}' setup: {key} names the environment variable {variable}, which is unset"
    )]
    MissingCredential {
        /// The platform's identifier.
        platform: String,
        /// The tenant's name.
        tenant: String,
        /// The setup key.
        key: String,
        /// The variable's name (never a value).
        variable: String,
    },
    /// The tenant's work stopped on a bug (a panic) before it returned: the
    /// tenant failed, the other tenants of the run go on.
    #[error("{platform} tenant '{tenant}': the connector stopped unexpectedly: {message}")]
    Crashed {
        /// The platform's identifier.
        platform: String,
        /// The tenant's name.
        tenant: String,
        /// The panic's message, when it has one.
        message: String,
    },
    /// The run was cancelled (Ctrl-C, `$/cancelRequest`).
    #[error("interrupted")]
    Cancelled,
}

impl ConnectorError {
    /// The `failure.code` a command reports this failure with.
    pub fn failure_code(&self) -> &'static str {
        match self {
            Self::Cancelled => INTERRUPTED,
            _ => COMMAND_FAILED,
        }
    }

    /// Whether the tenant could not be reached at all (connection, DNS,
    /// TLS, proxy): live validation reports the tenant unreachable then,
    /// where a [`ConnectorError::Timeout`] fails one query only.
    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable { .. })
    }
}

/// `scheme://host[:port]` of *url*, without credentials, path or query
/// (Python's `transport._origin`).
pub fn origin(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

/// The text of a reqwest error and of the errors under it, without the
/// request's URL (which may carry a credential in its query or user info).
pub fn describe(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut parts: Vec<String> = Vec::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = error.source();
    let top = error.to_string();
    parts.push(top);
    while let Some(inner) = current {
        let text = inner.to_string();
        if !parts.iter().any(|part| part.contains(&text)) {
            parts.push(text);
        }
        current = inner.source();
    }
    parts.join(": ")
}

/// A reqwest error from a request to *url* on the tenant *label*, as a
/// [`ConnectorError`].
pub fn from_reqwest(
    error: reqwest::Error,
    label: &crate::TenantLabel,
    url: &url::Url,
    timeout_secs: u64,
) -> ConnectorError {
    let address = origin(url);
    if error.is_timeout() && !error.is_connect() {
        return ConnectorError::Timeout {
            platform: label.platform.clone(),
            tenant: label.tenant.clone(),
            address,
            seconds: timeout_secs,
        };
    }
    let unreachable = error.is_connect() || error.is_request() || error.is_timeout();
    let reason = describe(error);
    if unreachable {
        ConnectorError::Unreachable {
            platform: label.platform.clone(),
            tenant: label.tenant.clone(),
            address,
            reason,
        }
    } else {
        ConnectorError::Answer {
            platform: label.platform.clone(),
            tenant: label.tenant.clone(),
            address,
            reason,
        }
    }
}
