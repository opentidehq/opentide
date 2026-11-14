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
//! A refusal (a wrong tenant id, a wrong or expired secret: Entra's
//! `AADSTS…` codes) is [`ConnectorError::Authentication`] naming the
//! platform and the tenant, with Entra's `error_description`. The secret is
//! never part of an error.

use opentide_compile::json::Json;

use crate::Secret;
use crate::answer::Answer;
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
/// A credential that is not set, the transport's error, or
/// [`ConnectorError::Authentication`] when Entra ID issues no token.
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
    let request = cx
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
    let answer = Answer::fetch(cx.http, request, cx.cancel).await?;
    let body = answer.json();
    let token = body
        .as_ref()
        .and_then(|body| body.get("access_token"))
        .and_then(Json::as_str)
        .filter(|token| !token.is_empty());
    match token {
        Some(token) if answer.status == 200 => Ok(Issued {
            token: Secret::new(token),
            lifetime: lifetime(body.as_ref().and_then(|body| body.get("expires_in"))),
        }),
        _ => {
            let field = |name: &str| {
                body.as_ref()
                    .and_then(|body| body.get(name))
                    .filter(|value| !value.is_null())
                    .map(json_text)
                    .filter(|text| !text.trim().is_empty())
            };
            let reason = field("error_description")
                .or_else(|| field("error"))
                .unwrap_or_else(|| format!("HTTP {} and no access token", answer.status));
            // Entra never echoes the secret; should an answer do, it is not repeated.
            let secret = client_secret.expose();
            let reason = if secret.is_empty() {
                reason
            } else {
                reason.replace(secret, "***")
            };
            Err(failed(format!(
                "Entra ID issued no token for tenant {}: {reason}",
                label.tenant
            )))
        }
    }
}
