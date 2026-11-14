//! When a request is sent again.
//!
//! One policy for every connector that retries at the transport
//! ([`RetryPolicy::standard`]): up to three retries, waiting 0.5 s, 1 s and
//! 2 s (or what the answer's `Retry-After` asks, at most [`MAX_BACKOFF`]).
//! What is retried depends on whether sending the request twice is safe:
//!
//! - A connection that could not be made ([`Outcome::NotSent`]: DNS, refused,
//!   TLS, the proxy's tunnel, the connect timeout) is retried for every
//!   method: the request never left, so the tenant cannot have acted on it.
//! - A transient answer (408, 429, 502, 503, 504) is retried only for an
//!   idempotent method: `GET`, `HEAD`, `OPTIONS`, `PUT` and `DELETE`. Every
//!   connector's `PUT` replaces a resource it names by id (a rule, a
//!   watchlist, a report, a policy) and every `DELETE` removes one, so a
//!   second copy leaves the tenant as the first did. `POST` and `PATCH`
//!   create rules, start searches and run JSON-RPC calls: the tenant may
//!   have acted on a request it answered with a 502, so they are sent once,
//!   and the answer is the caller's to read.
//! - Any other answer, a 500 included, is returned at once: a server error
//!   that is not a gateway's or a rate limit's does not go away on its own.
//! - A request sent and not answered within the tenant's timeout is not
//!   sent again: the same search would take as long again (a Sentinel query
//!   may take 300 s), and `validate --live` counts the timeouts in a row to
//!   find a tenant that does not answer.
//!
//! An answer still transient after the last retry is returned as the
//! answer, not raised: the connectors read its status and body to say what
//! the tenant or its gateway said.
//!
//! The platforms whose clients wait out their tenant's rate limits
//! themselves (Bitdefender GravityZone, Exabeam, Google Security
//! Operations) mount [`RetryPolicy::none`], so the two never stack.

use std::time::Duration;

use http::{Method, StatusCode};

/// The longest wait before a retry, and the longest `Retry-After` honoured:
/// one tenant cannot hold a run for an unbounded time.
pub const MAX_BACKOFF: Duration = Duration::from_secs(120);

/// How often, and after how long, a request is sent again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retries after the first attempt; 0 sends once.
    pub max_retries: u32,
    /// The wait before the first retry; each next one doubles, up to
    /// [`MAX_BACKOFF`].
    pub base_delay: Duration,
}

/// How one attempt ended, as far as a retry is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// An answer, with its `Retry-After` header when it has one.
    Answer {
        /// Its status.
        status: StatusCode,
        /// Its `Retry-After`, as sent.
        retry_after: Option<&'a str>,
    },
    /// No connection was made: the request was not sent.
    NotSent,
    /// Any other failure, a read timeout included: never retried.
    Failed,
}

impl RetryPolicy {
    /// No retry: the request is sent once.
    pub const fn none() -> Self {
        Self {
            max_retries: 0,
            base_delay: Duration::ZERO,
        }
    }

    /// The connectors' policy: three retries, 0.5 s first.
    pub const fn standard() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
        }
    }

    /// Whether sending *method* twice leaves the tenant as sending it once.
    pub fn is_idempotent(method: &Method) -> bool {
        [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ]
        .contains(method)
    }

    /// Whether *status* says the request may succeed if sent again.
    pub fn is_transient(status: StatusCode) -> bool {
        matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
    }

    /// The wait before retry number *retry* (0 for the first):
    /// `base_delay * 2^retry`, at most [`MAX_BACKOFF`].
    pub fn backoff(&self, retry: u32) -> Duration {
        2u32.checked_pow(retry)
            .and_then(|factor| self.base_delay.checked_mul(factor))
            .map_or(MAX_BACKOFF, |delay| delay.min(MAX_BACKOFF))
    }

    /// How long to wait before sending a *method* request again after
    /// *outcome*, when *retried* retries were already made; `None` when it
    /// is not sent again. *now* reads a `Retry-After` given as a date.
    pub fn wait(
        &self,
        method: &Method,
        outcome: Outcome<'_>,
        retried: u32,
        now: jiff::Timestamp,
    ) -> Option<Duration> {
        if retried >= self.max_retries {
            return None;
        }
        let backoff = self.backoff(retried);
        match outcome {
            Outcome::NotSent => Some(backoff),
            Outcome::Answer {
                status,
                retry_after,
            } if Self::is_idempotent(method) && Self::is_transient(status) => Some(
                matches!(status.as_u16(), 429 | 503)
                    .then(|| retry_after.and_then(|value| parse_retry_after(value, now)))
                    .flatten()
                    .unwrap_or(backoff),
            ),
            Outcome::Answer { .. } | Outcome::Failed => None,
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::none()
    }
}

/// A `Retry-After` value (RFC 9110): seconds, or an HTTP-date (zero when
/// past); at most [`MAX_BACKOFF`]. `None` when it is neither.
pub fn parse_retry_after(value: &str, now: jiff::Timestamp) -> Option<Duration> {
    let value = value.trim();
    let seconds = match value.parse::<u64>() {
        Ok(seconds) => Duration::from_secs(seconds),
        Err(_) => {
            let when = jiff::fmt::rfc2822::parse(value).ok()?.timestamp();
            Duration::try_from(when.duration_since(now)).unwrap_or(Duration::ZERO)
        }
    };
    Some(seconds.min(MAX_BACKOFF))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> jiff::Timestamp {
        "2026-11-11T12:00:00Z".parse().unwrap()
    }

    fn answer(status: u16) -> Outcome<'static> {
        Outcome::Answer {
            status: StatusCode::from_u16(status).unwrap(),
            retry_after: None,
        }
    }

    #[test]
    fn only_idempotent_methods_are_retried_after_the_request_was_sent() {
        let policy = RetryPolicy::standard();
        for method in [Method::POST, Method::PATCH] {
            for outcome in [answer(503), answer(502), answer(429), Outcome::Failed] {
                assert_eq!(policy.wait(&method, outcome, 0, now()), None, "{method}");
            }
            assert_eq!(
                policy.wait(&method, Outcome::NotSent, 0, now()),
                Some(Duration::from_millis(500)),
                "a request that never left may be sent: {method}"
            );
        }
        for method in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ] {
            for outcome in [
                answer(408),
                answer(429),
                answer(502),
                answer(503),
                answer(504),
                Outcome::NotSent,
            ] {
                assert!(
                    policy.wait(&method, outcome, 0, now()).is_some(),
                    "{method}"
                );
            }
            for outcome in [answer(200), answer(400), answer(404), answer(500)] {
                assert_eq!(policy.wait(&method, outcome, 0, now()), None);
            }
            assert_eq!(policy.wait(&method, Outcome::Failed, 0, now()), None);
        }
    }

    #[test]
    fn the_waits_double_and_stop_after_the_last_retry() {
        let policy = RetryPolicy::standard();
        let waits: Vec<_> = (0..4)
            .map(|retried| policy.wait(&Method::GET, answer(503), retried, now()))
            .collect();
        assert_eq!(
            waits,
            [
                Some(Duration::from_millis(500)),
                Some(Duration::from_secs(1)),
                Some(Duration::from_secs(2)),
                None
            ]
        );
        assert_eq!(
            RetryPolicy::none().wait(&Method::GET, Outcome::NotSent, 0, now()),
            None
        );
        let slow = RetryPolicy {
            max_retries: 40,
            base_delay: Duration::from_secs(60),
        };
        assert_eq!(slow.backoff(1), MAX_BACKOFF);
        assert_eq!(slow.backoff(39), MAX_BACKOFF);
    }

    #[test]
    fn retry_after_is_honoured_on_429_and_503_and_capped() {
        let policy = RetryPolicy::standard();
        let with = |status: u16, value: &'static str| Outcome::Answer {
            status: StatusCode::from_u16(status).unwrap(),
            retry_after: Some(value),
        };
        assert_eq!(
            policy.wait(&Method::GET, with(429, "7"), 0, now()),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            policy.wait(
                &Method::GET,
                with(503, "Wed, 11 Nov 2026 12:00:30 GMT"),
                0,
                now()
            ),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            policy.wait(&Method::GET, with(503, "3600"), 0, now()),
            Some(MAX_BACKOFF)
        );
        // Not a status it means anything on, or not a value: the backoff.
        assert_eq!(
            policy.wait(&Method::GET, with(502, "7"), 0, now()),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            policy.wait(&Method::GET, with(429, "soon"), 0, now()),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            parse_retry_after("Wed, 11 Nov 2026 11:00:00 GMT", now()),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("-3", now()), None);
    }
}
