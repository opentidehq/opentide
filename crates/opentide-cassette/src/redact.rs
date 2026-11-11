//! How a request or answer is normalised before it is recorded or compared,
//! so that no secret lands in a cassette and only what a client chooses to
//! send is compared.
//!
//! - **Transport headers** are left out: what the HTTP library adds, not the
//!   client (`Host`, `User-Agent`, `Accept-Encoding`, `Connection`,
//!   `Content-Length`, proxy headers). `requests`, `urllib` and reqwest each
//!   write their own; none of them is the platform's API.
//! - **Secret headers** keep their scheme and lose their value
//!   (`Authorization: Bearer REDACTED`): `Authorization`, cookies, and any
//!   header whose name speaks of a key, token, secret, password, signature
//!   or session.
//! - **URLs** lose their user info and the values of query parameters named
//!   so.
//! - **Bodies** lose the values of JSON keys and form fields named so, in
//!   place: the rest of the bytes stay as they were, so a body is still
//!   compared byte for byte.
//! - **Known secrets** (the values a scenario's credentials have) are
//!   replaced wherever they appear.

/// What replaces a secret.
pub const REDACTED: &str = "REDACTED";

/// Request headers a client's HTTP library writes, never compared or recorded.
pub const TRANSPORT_HEADERS: [&str; 13] = [
    "host",
    "user-agent",
    "accept-encoding",
    "connection",
    "content-length",
    "transfer-encoding",
    "te",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
    "expect",
    crate::ORIGIN_HEADER,
];

/// Answer headers left out of a cassette: they describe one connection.
pub const RESPONSE_TRANSPORT_HEADERS: [&str; 5] = [
    "connection",
    "content-length",
    "transfer-encoding",
    "keep-alive",
    "date",
];

/// Header names whose value is always a secret.
const SECRET_HEADERS: [&str; 4] = [
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
];

/// Words that make a header, query parameter, JSON key or form field a secret.
const SECRET_WORDS: [&str; 11] = [
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "api-key",
    "signature",
    "session",
    "credential",
    "private_key",
];

/// Authentication schemes kept in front of a redacted header value.
const SCHEMES: [&str; 8] = [
    "Bearer", "Basic", "ApiKey", "Token", "Key", "SSWS", "Digest", "Splunk",
];

/// Whether a header, parameter or key named *name* holds a secret.
pub fn is_secret_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    SECRET_HEADERS.contains(&lowered.as_str())
        || SECRET_WORDS.iter().any(|word| lowered.contains(word))
        || lowered == "key"
        || lowered.ends_with("-key")
        || lowered.ends_with("_key")
        || lowered == "code"
        || lowered == "sig"
}

/// The secrets of a run, replaced wherever they appear.
#[derive(Clone, Debug, Default)]
pub struct Redaction {
    secrets: Vec<String>,
}

impl Redaction {
    /// A redaction of these known secret values (empty ones ignored).
    pub fn new(secrets: impl IntoIterator<Item = String>) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .filter(|secret| secret.len() >= 3)
            .collect();
        // Longest first: a secret that contains another is replaced whole.
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        Self { secrets }
    }

    /// *text* with every known secret replaced.
    pub fn text(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        out
    }

    /// A header value, redacted when its name or content is a secret.
    pub fn header(&self, name: &str, value: &str) -> String {
        if !is_secret_name(name) {
            return self.text(value);
        }
        let trimmed = value.trim();
        if let Some((scheme, _)) = trimmed.split_once(' ')
            && SCHEMES
                .iter()
                .any(|known| known.eq_ignore_ascii_case(scheme))
        {
            return format!("{scheme} {REDACTED}");
        }
        REDACTED.to_owned()
    }

    /// Request headers as recorded: transport headers left out, names in
    /// lower case, values redacted, sorted.
    pub fn request_headers<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = headers
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .filter(|(name, _)| !TRANSPORT_HEADERS.contains(&name.as_str()))
            .map(|(name, value)| {
                let value = self.header(&name, value);
                (name, value)
            })
            .collect();
        out.sort();
        out
    }

    /// Answer headers as recorded: per-connection headers left out, names
    /// in lower case, values redacted, in the order received.
    pub fn response_headers<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Vec<(String, String)> {
        headers
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .filter(|(name, _)| !RESPONSE_TRANSPORT_HEADERS.contains(&name.as_str()))
            .map(|(name, value)| {
                let value = self.header(&name, value);
                (name, value)
            })
            .collect()
    }

    /// A URL with its user info and secret query values redacted.
    pub fn url(&self, raw: &str) -> String {
        let Ok(mut url) = url::Url::parse(raw) else {
            return self.text(raw);
        };
        if !url.username().is_empty() || url.password().is_some() {
            let _ = url.set_username(REDACTED);
            let _ = url.set_password(Some(REDACTED));
        }
        if let Some(query) = url.query() {
            let rewritten: Vec<String> = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((name, _)) if is_secret_name(&decode(name)) => {
                        format!("{name}={REDACTED}")
                    }
                    _ => pair.to_owned(),
                })
                .collect();
            url.set_query(Some(&rewritten.join("&")));
        }
        self.text(url.as_str())
    }

    /// A body with the values of secret JSON keys and form fields, and the
    /// known secrets, replaced in place.
    pub fn body(&self, bytes: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return bytes.to_vec();
        };
        let mut values: Vec<String> = Vec::new();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            secret_json_values(&json, false, &mut values);
        } else if !text.contains(char::is_whitespace) && text.contains('=') {
            for pair in text.split('&') {
                if let Some((name, value)) = pair.split_once('=')
                    && is_secret_name(&decode(name))
                    && !value.is_empty()
                {
                    values.push(value.to_owned());
                }
            }
        }
        let mut out = text.to_owned();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        for value in values {
            if value.len() >= 3 && value != REDACTED {
                out = out.replace(&value, REDACTED);
            }
        }
        self.text(&out).into_bytes()
    }
}

/// The string values under secret keys of *value*, as they appear in its
/// JSON text (escaped).
fn secret_json_values(value: &serde_json::Value, secret: bool, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) if secret => {
            let encoded = serde_json::to_string(text).unwrap_or_default();
            out.push(encoded.trim_matches('"').to_owned());
        }
        serde_json::Value::Array(items) => {
            for item in items {
                secret_json_values(item, secret, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                secret_json_values(item, secret || is_secret_name(key), out);
            }
        }
        _ => {}
    }
}

/// A form field name, percent-decoded.
fn decode(name: &str) -> String {
    url::form_urlencoded::parse(format!("{name}=").as_bytes())
        .next()
        .map(|(key, _)| key.into_owned())
        .unwrap_or_else(|| name.to_owned())
}
