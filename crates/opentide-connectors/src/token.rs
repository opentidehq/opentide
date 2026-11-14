//! Bearer tokens a platform signs in for, kept per tenant and scope until
//! shortly before they expire ([`TokenCache`]), and the rule for an API call
//! the platform answers `401` ([`TokenCache::send`]).
//!
//! - A token is reused until [`REFRESH_MARGIN`] before its `expires_in`
//!   runs out (whole seconds, as a JSON number or as text). A token whose
//!   answer names no lifetime, or one too short to outlive the margin,
//!   serves the request it was asked for and is not kept.
//! - A `401` from the API means the call was not processed: the token is
//!   forgotten, the platform is signed in to again once, and the call is
//!   sent again once, whatever its method. A second `401` is an
//!   authentication failure naming the tenant. A `403` is the platform's
//!   answer to a valid token and is returned as it is.
//! - Tokens are keyed by the tenant's label (platform and tenant) and the
//!   scope, so one tenant's token never reaches another tenant or another
//!   resource. Neither the cache's `Debug` nor any error carries a token.
//!
//! How a platform signs in is its own: the cache only asks the sign-in
//! function it is given when it holds no usable token.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use opentide_compile::json::Json;
use tokio_util::sync::CancellationToken;

use crate::answer::Answer;
use crate::connector::TenantContext;
use crate::error::ConnectorError;
use crate::{Secret, TenantLabel};

/// How long before its expiry a token is asked for again.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(300);

/// A token a sign-in issued, and how long it lives, when the answer says.
#[derive(Clone, Debug)]
pub struct Issued {
    /// The bearer token.
    pub token: Secret,
    /// Its `expires_in`; `None` when the answer named none.
    pub lifetime: Option<Duration>,
}

/// A token answer's `expires_in`: whole seconds as a JSON number or as
/// text; `None` when absent, negative or not a number.
pub fn lifetime(expires_in: Option<&Json>) -> Option<Duration> {
    let seconds = match expires_in? {
        Json::Int(seconds) => u64::try_from(*seconds).ok()?,
        Json::Str(text) => text.trim().parse::<u64>().ok()?,
        _ => return None,
    };
    Some(Duration::from_secs(seconds))
}

/// What tells the time: [`Instant::now`] in a run, a test's own clock.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// A token kept, and when it is asked for again.
struct Kept {
    token: Secret,
    renew_at: Instant,
}

/// The tokens of a platform's tenants, per tenant and scope.
pub struct TokenCache {
    tokens: Mutex<BTreeMap<(TenantLabel, String), Kept>>,
    now: Clock,
}

impl std::fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kept = self
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("TokenCache")
            .field("kept", &kept)
            .finish_non_exhaustive()
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenCache {
    /// An empty cache on the system clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }

    /// An empty cache on *now*.
    pub fn with_clock(now: Clock) -> Self {
        Self {
            tokens: Mutex::new(BTreeMap::new()),
            now,
        }
    }

    /// The token of *label* for *scope*: the one kept while it is not due
    /// for renewal, else a new one from *sign_in*, kept when its lifetime
    /// outlives [`REFRESH_MARGIN`].
    ///
    /// # Errors
    ///
    /// What *sign_in* returns.
    pub async fn token<S, F>(
        &self,
        label: &TenantLabel,
        scope: &str,
        sign_in: S,
    ) -> Result<Secret, ConnectorError>
    where
        S: FnOnce() -> F,
        F: Future<Output = Result<Issued, ConnectorError>>,
    {
        let key = (label.clone(), scope.to_owned());
        {
            let tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(kept) = tokens.get(&key)
                && (self.now)() < kept.renew_at
            {
                return Ok(kept.token.clone());
            }
        }
        let issued = sign_in().await?;
        let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        match issued
            .lifetime
            .and_then(|lifetime| lifetime.checked_sub(REFRESH_MARGIN))
            .filter(|usable| !usable.is_zero())
        {
            Some(usable) => {
                tokens.insert(
                    key,
                    Kept {
                        token: issued.token.clone(),
                        renew_at: (self.now)() + usable,
                    },
                );
            }
            None => {
                tokens.remove(&key);
            }
        }
        Ok(issued.token)
    }

    /// Forgets the token of *label* for *scope*.
    pub fn forget(&self, label: &TenantLabel, scope: &str) {
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(label.clone(), scope.to_owned()));
    }

    /// Sends the request *build* makes with the tenant's token for *scope*
    /// (signing in with *sign_in* when there is none) through the tenant's
    /// client, and its answer. On a `401` the token is forgotten, a new one
    /// asked for and the request sent again, once.
    ///
    /// # Errors
    ///
    /// The sign-in's error, the transport's, or
    /// [`ConnectorError::Authentication`] when the request is answered
    /// `401` with a new token too.
    pub async fn send<S, F, B>(
        &self,
        cx: TenantContext<'_>,
        scope: &str,
        sign_in: S,
        build: B,
        cancel: &CancellationToken,
    ) -> Result<Answer, ConnectorError>
    where
        S: Fn() -> F,
        F: Future<Output = Result<Issued, ConnectorError>>,
        B: Fn(&Secret) -> crate::transport::RequestBuilder,
    {
        let label = &cx.tenant.label;
        let once = |token: &Secret| {
            let request = build(token).build().map_err(|error| ConnectorError::Setup {
                platform: label.platform.clone(),
                tenant: label.tenant.clone(),
                message: error.describe(),
            });
            async move { Answer::fetch(cx.http, request?, cancel).await }
        };
        let answer = once(&self.token(label, scope, &sign_in).await?).await?;
        if answer.status != 401 {
            return Ok(answer);
        }
        self.forget(label, scope);
        let answer = once(&self.token(label, scope, &sign_in).await?).await?;
        if answer.status == 401 {
            self.forget(label, scope);
            return Err(ConnectorError::authentication(
                &label.platform,
                &label.tenant,
                format!(
                    "tenant {} refused a new token too (HTTP 401): check the credentials' \
                     permissions",
                    label.tenant
                ),
            ));
        }
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(tenant: &str) -> TenantLabel {
        TenantLabel::new("crowdstrike", tenant)
    }

    /// A clock a test moves.
    fn clock() -> (Clock, Arc<Mutex<Instant>>) {
        let at = Arc::new(Mutex::new(Instant::now()));
        let read = Arc::clone(&at);
        (
            Arc::new(move || *read.lock().unwrap_or_else(PoisonError::into_inner)),
            at,
        )
    }

    fn issue(token: &str, seconds: Option<u64>) -> Issued {
        Issued {
            token: Secret::new(token),
            lifetime: seconds.map(Duration::from_secs),
        }
    }

    #[test]
    fn expires_in_is_a_number_or_a_numeric_text() {
        let json = |text: &str| serde_json::from_str::<Json>(text).unwrap_or(Json::Null);
        assert_eq!(
            lifetime(Some(&json("3599"))),
            Some(Duration::from_secs(3599))
        );
        assert_eq!(
            lifetime(Some(&json("\"3599\""))),
            Some(Duration::from_secs(3599))
        );
        for none in ["-1", "1.5", "\"soon\"", "null", "true"] {
            assert_eq!(lifetime(Some(&json(none))), None, "{none}");
        }
        assert_eq!(lifetime(None), None);
    }

    #[tokio::test]
    async fn a_token_is_kept_until_five_minutes_before_it_expires() {
        let (now, at) = clock();
        let cache = TokenCache::with_clock(now);
        let signed = std::sync::atomic::AtomicUsize::new(0);
        let sign_in = |seconds| {
            let n = signed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { Ok(issue(&format!("t{n}"), seconds)) }
        };
        let a = label("a");
        let get = |seconds| cache.token(&a, "s", move || sign_in(seconds));
        assert_eq!(
            get(Some(3599)).await.ok().map(|t| t.expose().to_owned()),
            Some("t0".into())
        );
        assert_eq!(
            get(Some(3599)).await.ok().map(|t| t.expose().to_owned()),
            Some("t0".into())
        );
        // 3599 - 300 s later the token is due: a new one.
        *at.lock().unwrap_or_else(PoisonError::into_inner) += Duration::from_secs(3299);
        assert_eq!(
            get(Some(3599)).await.ok().map(|t| t.expose().to_owned()),
            Some("t1".into())
        );
        assert_eq!(signed.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_token_without_a_usable_lifetime_serves_one_request() {
        let (now, _) = clock();
        let cache = TokenCache::with_clock(now);
        let signed = std::sync::atomic::AtomicUsize::new(0);
        for lifetime in [None, Some(0), Some(300), None] {
            let token = cache
                .token(&label("a"), "s", || {
                    signed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(issue("t", lifetime)) }
                })
                .await;
            assert!(token.is_ok());
        }
        assert_eq!(signed.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(format!("{cache:?}"), "TokenCache { kept: 0, .. }");
    }

    #[tokio::test]
    async fn tokens_are_kept_per_tenant_and_scope() {
        let cache = TokenCache::new();
        let labels = [label("a"), label("b")];
        let get = |tenant: &'static str, scope: &'static str| {
            let at = usize::from(tenant == "b");
            cache.token(&labels[at], scope, move || async move {
                Ok(issue(&format!("{tenant}/{scope}"), Some(3599)))
            })
        };
        for (tenant, scope) in [("a", "arm"), ("a", "logs"), ("b", "arm")] {
            assert_eq!(
                get(tenant, scope).await.ok().map(|t| t.expose().to_owned()),
                Some(format!("{tenant}/{scope}"))
            );
        }
        // Kept: a second ask names the same token for each key.
        assert_eq!(
            get("b", "arm").await.ok().map(|t| t.expose().to_owned()),
            Some("b/arm".to_owned())
        );
        assert!(!format!("{cache:?}").contains("a/arm"));
    }
}
