//! Bearer tokens a platform signs in for, kept per tenant and scope until
//! shortly before they expire ([`TokenCache`]), and the rule for an API call
//! the platform answers `401` ([`TokenCache::send`]).
//!
//! - A token is reused until [`REFRESH_MARGIN`] before its `expires_in`
//!   runs out (whole seconds, as a JSON number or as text), and never longer
//!   than [`MAX_LIFETIME`]. A token whose answer names no lifetime, or one
//!   too short to outlive the margin, serves the request it was asked for
//!   and is not kept.
//! - One sign-in at a time per tenant and scope: calls that find no usable
//!   token wait for the first one's sign-in and share its token.
//! - A `401` from the API means the call was not processed: the token is
//!   forgotten (unless a newer one has replaced it), the platform is signed
//!   in to again once, and the call is sent again once, whatever its method.
//!   A second `401` is an authentication failure naming the tenant. A `403`
//!   is the platform's answer to a valid token and is returned as it is.
//! - Tokens are keyed by the tenant's label (platform and tenant) and the
//!   scope, so one tenant's token never reaches another tenant or another
//!   resource. Neither the cache's `Debug` nor any error carries a token.
//!
//! How a platform signs in is its own: the cache only asks the sign-in
//! function it is given when it holds no usable token.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// The longest a token is kept, whatever its `expires_in` says (Entra's
/// and CrowdStrike's last an hour or less).
pub const MAX_LIFETIME: Duration = Duration::from_hours(24);

/// How many characters of the API's answer a second `401` reports.
const DETAIL_CHARS: usize = 300;

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

/// A tenant and a scope.
type Key = (TenantLabel, String);

/// The sign-in gates of the keys calls are looking for a token for.
type Signing = BTreeMap<Key, Arc<tokio::sync::Mutex<()>>>;

/// A call's share of its key's sign-in gate. Every clone of a gate is made
/// and dropped under the map's lock, so the turn that finds only itself and
/// the map holding the gate is the last one, and removes it.
struct Turn<'a> {
    signing: &'a Mutex<Signing>,
    key: Key,
    /// `None` only once dropped.
    gate: Option<Arc<tokio::sync::Mutex<()>>>,
}

impl<'a> Turn<'a> {
    /// Takes a share of *key*'s gate, made when no call holds one.
    fn take(signing: &'a Mutex<Signing>, key: &Key) -> Self {
        let gate = Arc::clone(
            signing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(key.clone())
                .or_default(),
        );
        Self {
            signing,
            key: key.clone(),
            gate: Some(gate),
        }
    }

    /// Waits for the key's sign-in gate.
    async fn wait(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        Some(self.gate.as_ref()?.lock().await)
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut signing = self.signing.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(gate) = self.gate.take() {
            let last = Arc::strong_count(&gate) == 2
                && signing
                    .get(&self.key)
                    .is_some_and(|kept| Arc::ptr_eq(kept, &gate));
            if last {
                signing.remove(&self.key);
            }
            // Dropped under the lock, as it was cloned.
            drop(gate);
        }
    }
}

/// A token kept, when it is asked for again, and which sign-in issued it.
struct Kept {
    token: Secret,
    renew_at: Instant,
    issue: u64,
}

/// A token handed out, and which sign-in issued it.
struct Handed {
    token: Secret,
    issue: u64,
}

/// The tokens of a platform's tenants, per tenant and scope.
pub struct TokenCache {
    tokens: Mutex<BTreeMap<Key, Kept>>,
    /// One sign-in at a time per key. A key's gate is kept only while calls
    /// for it look for a token ([`Turn`]): the last one out removes it, so
    /// the map holds no more keys than calls in flight.
    signing: Mutex<Signing>,
    /// Numbers each sign-in, so a `401` forgets only the token it got.
    issued: AtomicU64,
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
            signing: Mutex::new(BTreeMap::new()),
            issued: AtomicU64::new(0),
            now,
        }
    }

    /// The token of *label* for *scope*: the one kept while it is not due
    /// for renewal, else a new one from *sign_in*, kept when its lifetime
    /// outlives [`REFRESH_MARGIN`]. Calls for one key that find no usable
    /// token sign in one after another, and a call that finds the token
    /// the one before it kept uses it.
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
        Ok(self.handed(label, scope, sign_in).await?.token)
    }

    /// The kept token of *key* while it is not due for renewal.
    fn kept(&self, key: &Key) -> Option<Handed> {
        let tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        tokens
            .get(key)
            .filter(|kept| (self.now)() < kept.renew_at)
            .map(|kept| Handed {
                token: kept.token.clone(),
                issue: kept.issue,
            })
    }

    /// [`Self::token`], with which sign-in issued it.
    async fn handed<S, F>(
        &self,
        label: &TenantLabel,
        scope: &str,
        sign_in: S,
    ) -> Result<Handed, ConnectorError>
    where
        S: FnOnce() -> F,
        F: Future<Output = Result<Issued, ConnectorError>>,
    {
        let key = (label.clone(), scope.to_owned());
        if let Some(handed) = self.kept(&key) {
            return Ok(handed);
        }
        // Declared before the guard, so dropped after it on every way out:
        // a token, an error, or the call dropped while it waits.
        let turn = Turn::take(&self.signing, &key);
        let _signing = turn.wait().await;
        // Another call may have signed in while this one waited.
        if let Some(handed) = self.kept(&key) {
            return Ok(handed);
        }
        let issued = sign_in().await?;
        let issue = self.issued.fetch_add(1, Ordering::Relaxed);
        let now = (self.now)();
        let renew_at = issued
            .lifetime
            .map(|lifetime| lifetime.min(MAX_LIFETIME))
            .and_then(|lifetime| lifetime.checked_sub(REFRESH_MARGIN))
            .filter(|usable| !usable.is_zero())
            .and_then(|usable| now.checked_add(usable));
        let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        match renew_at {
            Some(renew_at) => {
                tokens.insert(
                    key,
                    Kept {
                        token: issued.token.clone(),
                        renew_at,
                        issue,
                    },
                );
            }
            None => {
                tokens.remove(&key);
            }
        }
        Ok(Handed {
            token: issued.token,
            issue,
        })
    }

    /// Forgets the token of *label* for *scope*.
    pub fn forget(&self, label: &TenantLabel, scope: &str) {
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(label.clone(), scope.to_owned()));
    }

    /// Forgets the token of *label* for *scope* when it is still the one
    /// sign-in *issue* issued, not one a sibling call signed in for since.
    fn forget_issue(&self, label: &TenantLabel, scope: &str, issue: u64) {
        let key = (label.clone(), scope.to_owned());
        let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        if tokens.get(&key).is_some_and(|kept| kept.issue == issue) {
            tokens.remove(&key);
        }
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
        let first = self.handed(label, scope, &sign_in).await?;
        let answer = once(&first.token).await?;
        if answer.status != 401 {
            return Ok(answer);
        }
        self.forget_issue(label, scope, first.issue);
        let second = self.handed(label, scope, &sign_in).await?;
        let answer = once(&second.token).await?;
        if answer.status == 401 {
            self.forget_issue(label, scope, second.issue);
            let message = format!(
                "tenant {} refused a new token too (HTTP 401): check the credentials' \
                 permissions",
                label.tenant
            );
            // What the API said, any token it echoes masked in the whole body
            // first: cutting first would leave the head of a token that
            // straddles the cut.
            let masked = [&first.token, &second.token]
                .iter()
                .map(|token| token.expose())
                .filter(|token| !token.is_empty())
                .fold(answer.text(), |text, token| text.replace(token, "***"));
            let said: String = masked.chars().take(DETAIL_CHARS).collect();
            let said = said.trim();
            return Err(ConnectorError::Authentication {
                platform: label.platform.clone(),
                tenant: label.tenant.clone(),
                message,
                detail: (!said.is_empty()).then(|| said.to_owned()),
            });
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

    #[tokio::test]
    async fn a_huge_expires_in_is_kept_a_day_at_most_and_never_overflows() {
        let json = |text: &str| serde_json::from_str::<Json>(text).unwrap_or(Json::Null);
        // u64::MAX as text parses; as a number it is no integer, so no
        // lifetime: either way no panic adding it to the clock.
        assert_eq!(
            lifetime(Some(&json("\"18446744073709551615\""))),
            Some(Duration::from_secs(u64::MAX))
        );
        assert_eq!(lifetime(Some(&json("18446744073709551615"))), None);
        for seconds in [u64::MAX, u64::MAX / 2, 10 * 365 * 24 * 3600] {
            let (now, at) = clock();
            let cache = TokenCache::with_clock(now);
            let signed = std::sync::atomic::AtomicUsize::new(0);
            let a = label("a");
            let get = || {
                cache.token(&a, "s", || {
                    let n = signed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(issue(&format!("t{n}"), Some(seconds))) }
                })
            };
            assert_eq!(
                get().await.ok().map(|t| t.expose().to_owned()),
                Some("t0".into())
            );
            *at.lock().unwrap_or_else(PoisonError::into_inner) +=
                Duration::from_secs(24 * 3600 - 300 - 1);
            assert_eq!(
                get().await.ok().map(|t| t.expose().to_owned()),
                Some("t0".into())
            );
            *at.lock().unwrap_or_else(PoisonError::into_inner) += Duration::from_secs(1);
            assert_eq!(
                get().await.ok().map(|t| t.expose().to_owned()),
                Some("t1".into()),
                "{seconds}"
            );
        }
    }

    #[tokio::test]
    async fn calls_that_find_no_token_at_once_sign_in_once() {
        let cache = TokenCache::new();
        let signed = std::sync::atomic::AtomicUsize::new(0);
        let a = label("a");
        let get = || {
            cache.token(&a, "s", || {
                signed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(issue("t", Some(3600)))
                }
            })
        };
        let all = tokio::join!(get(), get(), get(), get());
        assert!(all.0.is_ok() && all.1.is_ok() && all.2.is_ok() && all.3.is_ok());
        assert_eq!(signed.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Another key signs in on its own.
        let other = cache
            .token(&label("b"), "s", || async { Ok(issue("u", Some(3600))) })
            .await;
        assert_eq!(other.ok().map(|t| t.expose().to_owned()), Some("u".into()));
    }

    #[tokio::test]
    async fn a_sign_in_gate_is_dropped_once_no_call_waits_on_it() {
        let gates = |cache: &TokenCache| {
            cache
                .signing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len()
        };
        let cache = TokenCache::new();
        let labels = ["a", "b", "c", "d", "e", "f"].map(label);
        let get = |at: usize| {
            cache.token(&labels[at], "s", || async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(issue("t", None))
            })
        };
        // Calls at once on one key, then on many keys.
        let all = tokio::join!(get(0), get(0), get(0), get(1), get(2));
        assert!(all.0.is_ok() && all.3.is_ok() && all.4.is_ok());
        assert_eq!(gates(&cache), 0);
        // A sign-in that fails.
        let failed = cache
            .token(&labels[3], "s", || async { Err(ConnectorError::Cancelled) })
            .await;
        assert!(failed.is_err());
        assert_eq!(gates(&cache), 0);
        // A call dropped while it signs in, and one dropped while it waits
        // for the first.
        let stuck = || {
            cache.token(&labels[4], "s", || async {
                std::future::pending::<Result<Issued, ConnectorError>>().await
            })
        };
        let dropped = tokio::time::timeout(Duration::from_millis(20), async {
            tokio::join!(stuck(), stuck())
        })
        .await;
        assert!(dropped.is_err());
        assert_eq!(gates(&cache), 0);
        // While a call holds the gate, it is there.
        let held = cache.token(&labels[5], "s", || async {
            assert_eq!(gates(&cache), 1);
            Ok(issue("t", None))
        });
        assert!(held.await.is_ok());
        assert_eq!(gates(&cache), 0);
    }

    #[tokio::test]
    async fn a_401_never_forgets_a_newer_token_than_the_one_it_got() {
        let cache = TokenCache::new();
        let a = label("a");
        let first = cache
            .handed(&a, "s", || async { Ok(issue("old", Some(3600))) })
            .await
            .map(|handed| handed.issue)
            .unwrap_or(u64::MAX);
        // A sibling's 401 forgot the old token and signed in again.
        cache.forget_issue(&a, "s", first);
        let newer = cache
            .token(&a, "s", || async { Ok(issue("new", Some(3600))) })
            .await;
        assert_eq!(
            newer.ok().map(|t| t.expose().to_owned()),
            Some("new".into())
        );
        // This call's 401 on the old token leaves the newer one kept.
        cache.forget_issue(&a, "s", first);
        let kept = cache
            .token(&a, "s", || async { Ok(issue("third", Some(3600))) })
            .await;
        assert_eq!(kept.ok().map(|t| t.expose().to_owned()), Some("new".into()));
    }
}
