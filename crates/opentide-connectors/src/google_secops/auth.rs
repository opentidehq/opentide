//! OAuth 2.0 access tokens for Google Security Operations, ported from
//! 0.28.0's `client.py` (`load_credentials`, `_authorise`), which used
//! google-auth.
//!
//! A tenant's `credentials` is a service-account key, as a JSON document or
//! the path to one (`type: service_account` only: another type runs commands
//! or reads files to get its token). Without it, Application Default
//! Credentials are read as google-auth's `default()` reads them: the file
//! `GOOGLE_APPLICATION_CREDENTIALS` names, else gcloud's well-known file,
//! else the metadata server of the machine opentide runs on.
//!
//! Every token request is sent on the tenant's own client, so it takes the
//! tenant's proxy, CA bundles and timeouts: a service-account key signs a JWT
//! (RS256, `jsonwebtoken`) and exchanges it at the key's `token_uri`; an
//! `authorized_user` file (gcloud's `application-default login`) exchanges its
//! refresh token; the metadata server is asked for the default service
//! account's token. A token is reused until 3 minutes 45 seconds before it
//! expires, google-auth's refresh threshold. The quota project (the file's
//! `quota_project_id`, or `GOOGLE_CLOUD_QUOTA_PROJECT`) is sent as
//! `x-goog-user-project`, as google-auth's `apply` sends it.
//!
//! A token that cannot be obtained stops the tenant: the credentials are
//! missing or unreadable (`google_secops_credentials_missing`), or Google
//! refused them or did not answer (`google_secops_tenant_unauthorized`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use jiff::Timestamp;
use opentide_compile::Json;

use crate::Environment;
use crate::connector::TenantContext;
use crate::credentials::{Credential, Secret};
use crate::encode::urlencode;
use crate::error::ConnectorError;

use super::PLATFORM;

/// The OAuth 2.0 scope every request's token carries.
pub const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Google's token endpoint, when a key names none.
pub const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// The metadata server's host, unless `GCE_METADATA_HOST` names another.
pub const METADATA_HOST: &str = "metadata.google.internal";

/// A token is asked for again this long before it expires (google-auth's
/// `REFRESH_THRESHOLD`).
pub const REFRESH_THRESHOLD: Duration = Duration::from_secs(225);

/// A signed assertion's lifetime (google-auth's `_DEFAULT_TOKEN_LIFETIME_SECS`).
pub const ASSERTION_LIFETIME: i64 = 3600;

/// The code of credentials that are missing or cannot be read.
pub const CREDENTIALS_MISSING: &str = "google_secops_credentials_missing";

/// The code of credentials Google refused, or a token endpoint that did not
/// answer.
pub const TENANT_UNAUTHORIZED: &str = "google_secops_tenant_unauthorized";

/// What time it is, for a token's expiry and an assertion's `iat`: the
/// system's clock, or a fixed one in a test.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// The system clock.
pub fn system_clock() -> Clock {
    Arc::new(Timestamp::now)
}

/// Credentials a token is obtained with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credentials {
    /// A service-account key: a JWT signed with its private key.
    ServiceAccount {
        /// `client_email`, the assertion's issuer.
        client_email: String,
        /// `private_key`, PEM.
        private_key: Secret,
        /// `private_key_id`, the assertion's `kid`.
        private_key_id: Option<String>,
        /// `token_uri`.
        token_uri: String,
        /// `quota_project_id`.
        quota_project: Option<String>,
    },
    /// gcloud's user credentials (`application-default login`): a refresh
    /// token.
    AuthorizedUser {
        /// `client_id`.
        client_id: String,
        /// `client_secret`.
        client_secret: Secret,
        /// `refresh_token`.
        refresh_token: Secret,
        /// `token_uri`.
        token_uri: String,
        /// `quota_project_id`.
        quota_project: Option<String>,
    },
    /// The metadata server of the machine opentide runs on.
    Metadata {
        /// The metadata server's host.
        host: String,
        /// `GOOGLE_CLOUD_QUOTA_PROJECT`.
        quota_project: Option<String>,
    },
}

impl Credentials {
    /// The quota project sent as `x-goog-user-project`.
    pub fn quota_project(&self) -> Option<&str> {
        match self {
            Self::ServiceAccount { quota_project, .. }
            | Self::AuthorizedUser { quota_project, .. }
            | Self::Metadata { quota_project, .. } => quota_project.as_deref(),
        }
    }
}

/// Why credentials cannot be loaded: a message, without the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadError(pub String);

fn text(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn required(value: &serde_json::Value, key: &str, kind: &str) -> Result<String, LoadError> {
    text(value, key).ok_or_else(|| LoadError(format!("the {kind} has no {key}")))
}

/// Credentials of a JSON document; `allowed` lists the types accepted.
fn from_info(
    info: &str,
    allowed: &[&str],
    quota_override: Option<&str>,
) -> Result<Credentials, LoadError> {
    let value: serde_json::Value = serde_json::from_str(info)
        .map_err(|error| LoadError(format!("cannot load Google credentials: {error}")))?;
    let kind = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !value.is_object() || !allowed.contains(&kind) {
        let reason = if allowed == ["service_account"] {
            "the key is not a service-account key (type: service_account)".to_owned()
        } else {
            format!(
                "credentials of type {kind:?} are not supported: use a service-account key or \
                 gcloud auth application-default login"
            )
        };
        return Err(LoadError(format!(
            "cannot load Google credentials: {reason}"
        )));
    }
    let quota = quota_override
        .map(str::to_owned)
        .or_else(|| text(&value, "quota_project_id"));
    let token_uri = text(&value, "token_uri").unwrap_or_else(|| TOKEN_URI.to_owned());
    let invalid =
        |error: LoadError| LoadError(format!("cannot load Google credentials: {}", error.0));
    if kind == "service_account" {
        let private_key =
            required(&value, "private_key", "service-account key").map_err(invalid)?;
        // A key that does not parse is refused here, as google-auth refuses it.
        jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|error| {
            LoadError(format!(
                "cannot load Google credentials: the private key cannot be read ({error})"
            ))
        })?;
        Ok(Credentials::ServiceAccount {
            client_email: required(&value, "client_email", "service-account key")
                .map_err(invalid)?,
            private_key: Secret::new(private_key),
            private_key_id: text(&value, "private_key_id"),
            token_uri,
            quota_project: quota,
        })
    } else {
        Ok(Credentials::AuthorizedUser {
            client_id: required(&value, "client_id", "authorized_user file").map_err(invalid)?,
            client_secret: Secret::new(
                required(&value, "client_secret", "authorized_user file").map_err(invalid)?,
            ),
            refresh_token: Secret::new(
                required(&value, "refresh_token", "authorized_user file").map_err(invalid)?,
            ),
            token_uri,
            quota_project: quota,
        })
    }
}

fn read_file(path: &Path, what: &str) -> Result<String, LoadError> {
    let bytes = std::fs::read(path)
        .map_err(|error| LoadError(format!("cannot read the {what}: {error}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|error| LoadError(format!("cannot read the {what}: {error}")))?;
    // `utf-8-sig`: one leading byte order mark is dropped.
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned())
}

/// A path as `Path.expanduser()` reads it: a leading `~` is the home
/// directory.
fn expand_user(value: &str, env: &Environment) -> PathBuf {
    if let Some(rest) = value.strip_prefix('~')
        && (rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\'))
        && let Some(home) = home(env)
    {
        return home.join(rest.trim_start_matches(['/', '\\']));
    }
    PathBuf::from(value)
}

fn home(env: &Environment) -> Option<PathBuf> {
    env.first(&["HOME", "USERPROFILE"]).map(PathBuf::from)
}

/// gcloud's well-known file: `$CLOUDSDK_CONFIG`, else `%APPDATA%\gcloud` on
/// Windows, else `~/.config/gcloud`, then `application_default_credentials.json`.
pub fn well_known_file(env: &Environment) -> Option<PathBuf> {
    let directory = if let Some(config) = env.get("CLOUDSDK_CONFIG") {
        PathBuf::from(config)
    } else if cfg!(windows) {
        PathBuf::from(env.get("APPDATA")?).join("gcloud")
    } else {
        home(env)?.join(".config").join("gcloud")
    };
    Some(directory.join("application_default_credentials.json"))
}

/// The credentials for a tenant's `credentials` setup value (`None` when
/// the tenant names none: Application Default Credentials).
///
/// # Errors
///
/// [`LoadError`] when the credentials are missing or cannot be read.
pub fn load(value: Option<&Credential>, env: &Environment) -> Result<Credentials, LoadError> {
    match value {
        None => application_default(env),
        Some(Credential::Placeholder { variable }) => Err(LoadError(format!(
            "the credentials variable {variable} is not set: set it to a service-account key \
             (JSON) or the path to one"
        ))),
        Some(Credential::Value(secret)) => {
            let value = secret.expose();
            if value.trim_start().starts_with('{') {
                return from_info(value, &["service_account"], None);
            }
            let path = expand_user(value, env);
            if !path.is_file() {
                return Err(LoadError(
                    "the credentials variable names no file and holds no JSON key".to_owned(),
                ));
            }
            from_info(
                &read_file(&path, "credentials file")?,
                &["service_account"],
                None,
            )
        }
    }
}

/// Application Default Credentials (`google.auth.default`).
fn application_default(env: &Environment) -> Result<Credentials, LoadError> {
    let quota = env.get("GOOGLE_CLOUD_QUOTA_PROJECT");
    let missing = |reason: String| {
        LoadError(format!(
            "no credentials: the tenant names none and Application Default Credentials are not \
             set up ({reason})"
        ))
    };
    let kinds = ["service_account", "authorized_user"];
    if let Some(named) = env.get("GOOGLE_APPLICATION_CREDENTIALS") {
        let path = expand_user(named, env);
        if !path.is_file() {
            return Err(missing(format!(
                "File {named} was not found, from GOOGLE_APPLICATION_CREDENTIALS"
            )));
        }
        return from_info(&read_file(&path, "credentials file")?, &kinds, quota)
            .map_err(|error| missing(error.0));
    }
    if let Some(path) = well_known_file(env).filter(|path| path.is_file()) {
        return from_info(&read_file(&path, "credentials file")?, &kinds, quota)
            .map_err(|error| missing(error.0));
    }
    Ok(Credentials::Metadata {
        host: env
            .get("GCE_METADATA_HOST")
            .unwrap_or(METADATA_HOST)
            .to_owned(),
        quota_project: quota.map(str::to_owned),
    })
}

/// The claims of a service account's assertion (google-auth's
/// `service_account.Credentials._make_authorization_grant_assertion`).
#[derive(Debug, serde::Serialize)]
struct Claims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
    aud: &'a str,
    scope: &'a str,
}

/// The signed JWT a service account exchanges for a token, at `now`.
///
/// # Errors
///
/// [`LoadError`] when the key cannot sign.
pub fn assertion(
    client_email: &str,
    private_key: &Secret,
    private_key_id: Option<&str>,
    token_uri: &str,
    now: Timestamp,
) -> Result<String, LoadError> {
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.expose().as_bytes())
        .map_err(|error| LoadError(format!("the private key cannot be read ({error})")))?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = private_key_id.map(str::to_owned);
    let iat = now.as_second();
    let claims = Claims {
        iat,
        exp: iat + ASSERTION_LIFETIME,
        iss: client_email,
        aud: token_uri,
        scope: SCOPE,
    };
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|error| LoadError(format!("the private key cannot sign ({error})")))
}

/// An access token and when it expires.
#[derive(Clone, Debug)]
pub struct Token {
    /// The token.
    pub secret: Secret,
    /// When it is asked for again.
    pub refresh_at: Timestamp,
}

/// One tenant's credentials and its cached token.
pub struct Authorizer {
    credentials: Credentials,
    clock: Clock,
    token: Mutex<Option<Token>>,
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorizer")
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

fn unauthorized(cx: TenantContext<'_>, message: String) -> ConnectorError {
    ConnectorError::Authentication {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message: format!("{TENANT_UNAUTHORIZED}: {message}"),
        detail: None,
    }
}

/// The error of credentials that are missing or cannot be read.
pub fn credentials_missing(tenant: &str, error: &LoadError) -> ConnectorError {
    ConnectorError::Authentication {
        platform: PLATFORM.to_owned(),
        tenant: tenant.to_owned(),
        message: format!("{CREDENTIALS_MISSING}: {}", error.0),
        detail: None,
    }
}

impl Authorizer {
    /// An authorizer for `credentials`, reading time from `clock`.
    pub fn new(credentials: Credentials, clock: Clock) -> Self {
        Self {
            credentials,
            clock,
            token: Mutex::new(None),
        }
    }

    /// The credentials.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// The headers a request carries: `Authorization` and, with a quota
    /// project, `x-goog-user-project` (`Credentials.apply`).
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Authentication`] when no token can be obtained.
    pub async fn headers(
        &self,
        cx: TenantContext<'_>,
    ) -> Result<Vec<(&'static str, String)>, ConnectorError> {
        let token = self.token(cx).await?;
        let mut headers = vec![("Authorization", format!("Bearer {}", token.expose()))];
        if let Some(project) = self.credentials.quota_project() {
            headers.push(("x-goog-user-project", project.to_owned()));
        }
        Ok(headers)
    }

    /// A valid access token, obtained on first use and again when it is
    /// about to expire.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Authentication`] when no token can be obtained.
    pub async fn token(&self, cx: TenantContext<'_>) -> Result<Secret, ConnectorError> {
        let now = (self.clock)();
        if let Some(token) = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|token| token.refresh_at > now)
        {
            return Ok(token.secret.clone());
        }
        let token = self.fetch(cx, now).await?;
        let secret = token.secret.clone();
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = Some(token);
        Ok(secret)
    }

    async fn fetch(&self, cx: TenantContext<'_>, now: Timestamp) -> Result<Token, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        let request = match &self.credentials {
            Credentials::ServiceAccount {
                client_email,
                private_key,
                private_key_id,
                token_uri,
                ..
            } => {
                let jwt = assertion(
                    client_email,
                    private_key,
                    private_key_id.as_deref(),
                    token_uri,
                    now,
                )
                .map_err(|error| credentials_missing(&tenant, &error))?;
                cx.http
                    .request(reqwest::Method::POST, token_uri)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(urlencode([
                        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                        ("assertion", jwt.as_str()),
                    ]))
            }
            Credentials::AuthorizedUser {
                client_id,
                client_secret,
                refresh_token,
                token_uri,
                ..
            } => cx
                .http
                .request(reqwest::Method::POST, token_uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(urlencode([
                    ("grant_type", "refresh_token"),
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.expose()),
                    ("refresh_token", refresh_token.expose()),
                ])),
            Credentials::Metadata { host, .. } => cx
                .http
                .request(
                    reqwest::Method::GET,
                    &format!(
                        "http://{host}/computeMetadata/v1/instance/service-accounts/default/token?{}",
                        urlencode([("scopes", SCOPE)])
                    ),
                )
                .header("Metadata-Flavor", "Google"),
        };
        let answer = match crate::answer::exchange(cx, request).await {
            Ok(answer) => answer,
            Err(ConnectorError::Cancelled) => return Err(ConnectorError::Cancelled),
            Err(error) if matches!(self.credentials, Credentials::Metadata { .. }) => {
                // No metadata server: google-auth finds no default credentials.
                return Err(credentials_missing(
                    &tenant,
                    &LoadError(format!(
                        "no credentials: the tenant names none and Application Default \
                         Credentials are not set up (the metadata server did not answer: {error})"
                    )),
                ));
            }
            Err(error) => {
                return Err(unauthorized(
                    cx,
                    format!("tenant {tenant}: Google's token endpoint did not answer ({error})"),
                ));
            }
        };
        let body = answer.json().unwrap_or(Json::Null);
        let token = body
            .get("access_token")
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty());
        let Some(token) = token.filter(|_| answer.status == 200) else {
            if answer.status == 200 {
                return Err(unauthorized(
                    cx,
                    format!("tenant {tenant}: the credentials gave no access token"),
                ));
            }
            let reason = match (body.get("error"), body.get("error_description")) {
                (Some(Json::Str(error)), Some(Json::Str(description))) => {
                    format!("{error}: {description}")
                }
                (Some(Json::Str(error)), _) => error.clone(),
                _ => answer
                    .not_json_detail()
                    .unwrap_or_else(|| format!("HTTP {}", answer.status)),
            };
            return Err(unauthorized(
                cx,
                format!("tenant {tenant}: Google refused the credentials ({reason})"),
            ));
        };
        let seconds = match body.get("expires_in") {
            Some(Json::Int(seconds)) => *seconds,
            Some(Json::Str(text)) => text.parse().unwrap_or(0),
            _ => 0,
        };
        let lifetime =
            seconds.saturating_sub(i64::try_from(REFRESH_THRESHOLD.as_secs()).unwrap_or(i64::MAX));
        Ok(Token {
            secret: Secret::new(token),
            refresh_at: now
                .checked_add(jiff::SignedDuration::from_secs(lifetime.max(0)))
                .unwrap_or(now),
        })
    }
}

#[cfg(test)]
mod tests;
