//! Signing in to Microsoft Entra ID (Azure AD) with an app registration's
//! client secret: the OAuth 2.0 client-credentials grant of the Microsoft
//! identity platform's v2.0 token endpoint, the one sign-in Sentinel and
//! Microsoft Defender use.
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
    /// The client secret's key (`azure_client_secret` for Sentinel).
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
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
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
        // A sign-in writes no rule (`HttpClient::writes_taken`).
        .read_only()
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
    // Entra never echoes the secret. Should an answer do (a proxy or server
    // echoing the form it was sent), in any form it may take there, it is
    // masked in the whole body before any of it is read, so an excerpt can
    // never hold part of it either.
    let forms = secret_forms(client_secret.expose());
    let mask = |text: String| {
        forms
            .iter()
            .fold(text, |text, form| text.replace(form.as_str(), "***"))
    };
    let answer = Answer {
        body: mask(answer.text()).into_bytes(),
        ..answer
    };
    let body = answer.json();
    let field = |name: &str| {
        body.as_ref()
            .and_then(|body| body.get(name))
            .filter(|value| !value.is_null())
            .map(Json::to_text)
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

/// The forms *secret* may be echoed in: as it is; form-encoded, a space as
/// `+` or `%20`; percent-encoded as a URI component or byte by byte; each
/// escape's hex in either case; and as a JSON string's content. Longest
/// first, so a longer form is masked whole; none when the secret is empty.
fn secret_forms(secret: &str) -> Vec<String> {
    use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
    /// RFC 3986's unreserved characters left as they are.
    const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    /// JavaScript's `encodeURIComponent`.
    const COMPONENT: &AsciiSet = &UNRESERVED
        .remove(b'!')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');
    if secret.is_empty() {
        return Vec::new();
    }
    let encoded = [
        url::form_urlencoded::byte_serialize(secret.as_bytes()).collect(),
        utf8_percent_encode(secret, NON_ALPHANUMERIC).to_string(),
        utf8_percent_encode(secret, UNRESERVED).to_string(),
        utf8_percent_encode(secret, COMPONENT).to_string(),
    ];
    // A `+` the secret holds is `%2B` in each: a `+` there is a space.
    let mut forms: Vec<String> = encoded
        .iter()
        .flat_map(|text| [text.replace('+', "%20"), text.replace("%20", "+")])
        .flat_map(|text| [lower_hex(&text), text])
        .collect();
    forms.push(secret.to_owned());
    if let Ok(quoted) = serde_json::to_string(secret)
        && let Some(inner) = quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"'))
    {
        forms.push(inner.to_owned());
    }
    forms.sort_by_key(|form| std::cmp::Reverse(form.len()));
    forms.dedup();
    forms
}

/// *text* with the hex digits of each `%XX` escape in lower case.
fn lower_hex(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut after = 0;
    for c in text.chars() {
        if c == '%' {
            after = 2;
            out.push(c);
        } else if after > 0 {
            after -= 1;
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_masked_in_every_form_it_may_be_echoed_in() {
        let secret = "aB3~Q8_x.y+z/w=v&u%t s~9";
        let forms = secret_forms(secret);
        for echoed in [
            secret,
            "aB3%7EQ8_x.y%2Bz%2Fw%3Dv%26u%25t+s%7E9",
            "aB3%7EQ8_x.y%2Bz%2Fw%3Dv%26u%25t%20s%7E9",
            "aB3~Q8_x.y%2Bz%2Fw%3Dv%26u%25t+s~9",
            "aB3~Q8_x.y%2Bz%2Fw%3Dv%26u%25t%20s~9",
            "aB3~Q8_x.y%2bz%2fw%3dv%26u%25t+s~9",
            "aB3%7EQ8%5Fx%2Ey%2Bz%2Fw%3Dv%26u%25t%20s%7E9",
        ] {
            assert!(
                forms.iter().any(|form| form == echoed),
                "{echoed}: {forms:?}"
            );
        }
        assert!(secret_forms("").is_empty());
        // Longest first: the `+` form is masked before a shorter one could
        // leave part of it.
        assert!(forms.windows(2).all(|pair| pair[0].len() >= pair[1].len()));
    }
}
