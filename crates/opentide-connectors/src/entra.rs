//! Signing in to Microsoft Entra ID (Azure AD) with an app registration's
//! client secret: the OAuth 2.0 client-credentials grant of the Microsoft
//! identity platform's v2.0 token endpoint, the one sign-in Sentinel and
//! Defender for Endpoint use.
//!
//! One form `POST` to `https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token`
//! with exactly `grant_type=client_credentials`, `client_id`,
//! `client_secret` and `scope=<resource>/.default`, through the tenant's
//! own HTTP client (its proxy and CA bundle). Nothing interactive, no
//! OpenID discovery, no library telemetry. The token is kept by the
//! platform's [`TokenCache`](crate::token::TokenCache) per tenant and scope,
//! so a token for one resource is never sent to another.
//!
//! The `POST` is idempotent for the retry policy: a `429` or a gateway's
//! `502`/`503`/`504` is sent again as any idempotent call is, `Retry-After`
//! honoured. A refusal (`400` or `401` with an OAuth 2.0 `error` code: a
//! wrong tenant id, a wrong or expired secret, Entra's `AADSTS…` codes) is
//! [`ConnectorError::Authentication`] naming the platform and the tenant,
//! with Entra's `error_description`. Any other answer without a token (a
//! rate limit or an outage the retries did not outlast, a proxy's page) is
//! [`ConnectorError::Gateway`] or [`ConnectorError::Answer`] naming Entra ID
//! and the HTTP status. The secret is never part of an error or a log.

use opentide_compile::json::Json;

use crate::Secret;
use crate::answer::{Answer, gateway_answer};
use crate::connector::TenantContext;
use crate::error::ConnectorError;
use crate::text::json_text;
use crate::token::{Issued, lifetime};

/// The Microsoft identity platform.
pub const LOGIN_ENDPOINT: &str = "https://login.microsoftonline.com";

/// The names a platform's tenant setup gives its app registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialNames {
    /// The directory (tenant) id.
    pub tenant_id: &'static str,
    /// The application (client) id.
    pub client_id: &'static str,
    /// The client secret.
    pub client_secret: &'static str,
}

/// A token for *scope* (`<resource>/.default`) from Entra ID, with the
/// credentials *names* reads from the tenant's setup.
///
/// # Errors
///
/// A credential that is not set, the transport's error,
/// [`ConnectorError::Authentication`] when Entra ID refuses the
/// credentials, or [`ConnectorError::Gateway`] / [`ConnectorError::Answer`]
/// when it answers anything else without a token.
pub async fn sign_in(
    cx: TenantContext<'_>,
    names: CredentialNames,
    scope: &str,
) -> Result<Issued, ConnectorError> {
    sign_in_at(cx, LOGIN_ENDPOINT, names, scope).await
}

/// [`sign_in`] at the identity platform *authority* (a stand-in in tests).
///
/// # Errors
///
/// As [`sign_in`].
pub async fn sign_in_at(
    cx: TenantContext<'_>,
    authority: &str,
    names: CredentialNames,
    scope: &str,
) -> Result<Issued, ConnectorError> {
    let label = &cx.tenant.label;
    let tenant_id = cx.tenant.secret(names.tenant_id)?;
    let client_id = cx.tenant.secret(names.client_id)?;
    let client_secret = cx.tenant.secret(names.client_secret)?;
    let failed = |message: String| ConnectorError::Authentication {
        platform: label.platform.clone(),
        tenant: label.tenant.clone(),
        message,
        detail: None,
    };
    let mut url = url::Url::parse(authority)
        .map_err(|error| failed(format!("{authority} is not a URL: {error}")))?;
    url.path_segments_mut()
        .map_err(|()| failed(format!("{authority} cannot hold a path")))?
        .pop_if_empty()
        .extend([tenant_id.expose(), "oauth2", "v2.0", "token"]);
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .append_pair("client_id", client_id.expose())
        .append_pair("client_secret", client_secret.expose())
        .append_pair("scope", scope)
        .finish();
    let mut request = cx
        .http
        .request(crate::transport::Method::POST, url.as_str())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form)
        .build()
        .map_err(|error| ConnectorError::Setup {
            platform: label.platform.clone(),
            tenant: label.tenant.clone(),
            message: error.describe(),
        })?;
    // Issuing a token changes nothing: a 429 or a gateway's 5xx is retried
    // as an idempotent call is, `Retry-After` honoured.
    request.set_idempotent(true);
    tracing::debug!(
        platform = %label.platform,
        tenant = %label.tenant,
        scope,
        "signing in to Entra ID"
    );
    let answer = Answer::fetch(cx.http, request, cx.cancel).await?;
    let body = answer.json();
    let token = body
        .as_ref()
        .and_then(|body| body.get("access_token"))
        .and_then(Json::as_str)
        .filter(|token| !token.is_empty());
    if let Some(token) = token
        && answer.status == 200
    {
        return Ok(Issued {
            token: Secret::new(token),
            lifetime: lifetime(body.as_ref().and_then(|body| body.get("expires_in"))),
        });
    }
    // Entra never echoes the secret; should an answer do, it is not repeated.
    let mask = |text: String| {
        let secret = client_secret.expose();
        if secret.is_empty() {
            text
        } else {
            text.replace(secret, "***")
        }
    };
    let field = |name: &str| {
        body.as_ref()
            .and_then(|body| body.get(name))
            .filter(|value| !value.is_null())
            .map(json_text)
            .filter(|text| !text.trim().is_empty())
    };
    // A refusal of the credentials: OAuth 2.0's error answer (RFC 6749
    // §5.2), `400` or `401` with an `error` code (AADSTS… in its
    // description).
    if matches!(answer.status, 400 | 401)
        && let Some(error) = field("error")
    {
        let reason = field("error_description").unwrap_or(error);
        return Err(failed(mask(format!(
            "Entra ID issued no token for tenant {}: {reason}",
            label.tenant
        ))));
    }
    // Anything else (a rate limit or an outage still there after the
    // retries, a proxy's page) is the identity platform's state, not the
    // credentials'.
    let said = answer
        .not_json_detail()
        .or_else(|| field("error_description"))
        .or_else(|| field("error"))
        .unwrap_or_else(|| "no access token".to_owned());
    let said = mask(said);
    let status = answer.status;
    if let Some(hint) = gateway_answer(status, Some(answer.elapsed)) {
        return Err(ConnectorError::Gateway {
            platform: label.platform.clone(),
            tenant: label.tenant.clone(),
            message: format!(
                "Entra ID answered HTTP {status} when tenant {} signed in ({said}): {hint}",
                label.tenant
            ),
            status,
        });
    }
    Err(ConnectorError::Answer {
        platform: label.platform.clone(),
        tenant: label.tenant.clone(),
        address: crate::error::origin(&url),
        reason: format!("Entra ID answered HTTP {status} and issued no token: {said}"),
    })
}
