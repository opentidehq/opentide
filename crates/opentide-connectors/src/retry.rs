//! Retries, as each platform's client retries today.
//!
//! The Python clients mount urllib3's `Retry` on their session: Elastic and
//! Sysdig retry 3 times on 429, 500, 502, 503 and 504 with a backoff factor
//! of 0.5, Sentinel's ARM client 3 times on 408 as well with 0.8 and the
//! answer's `Retry-After`; the others do not retry. A [`RetryPolicy`] says
//! the same; backon schedules the waits (exponential from the factor). A
//! status still failing after the last retry is returned as the answer,
//! never raised (urllib3's `raise_on_status=False`).

use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};

/// When and how often a request is sent again.
#[derive(Clone, Debug, PartialEq)]
pub struct RetryPolicy {
    /// Retries after the first attempt; 0 sends once.
    pub total: usize,
    /// The first wait, in seconds; each next one doubles.
    pub backoff_factor: f32,
    /// The statuses that are retried.
    pub statuses: Vec<u16>,
    /// The methods that are retried (upper case).
    pub methods: Vec<String>,
    /// Wait as long as a 413, 429 or 503 answer's `Retry-After` says.
    pub respect_retry_after: bool,
}

impl RetryPolicy {
    /// No retry: the request is sent once.
    pub fn none() -> Self {
        Self {
            total: 0,
            backoff_factor: 0.0,
            statuses: Vec::new(),
            methods: Vec::new(),
            respect_retry_after: false,
        }
    }

    /// urllib3's `Retry(total, backoff_factor, status_forcelist,
    /// allowed_methods)`, `respect_retry_after_header` on as by default.
    pub fn urllib3(total: usize, backoff_factor: f32, statuses: &[u16], methods: &[&str]) -> Self {
        Self {
            total,
            backoff_factor,
            statuses: statuses.to_vec(),
            methods: methods.iter().map(|method| method.to_uppercase()).collect(),
            respect_retry_after: true,
        }
    }

    /// Whether a request with *method* is retried at all.
    pub fn retries(&self, method: &str) -> bool {
        self.total > 0 && self.methods.iter().any(|allowed| allowed == method)
    }

    /// Whether an answer with *status* is sent again.
    pub fn retries_status(&self, status: u16) -> bool {
        self.statuses.contains(&status)
    }

    /// The waits before each retry, in order.
    pub fn delays(&self) -> impl Iterator<Item = Duration> + use<> {
        ExponentialBuilder::new()
            .with_min_delay(Duration::from_secs_f32(self.backoff_factor.max(0.0)))
            .with_factor(2.0)
            .with_max_delay(Duration::from_secs(120))
            .with_max_times(self.total)
            .build()
    }

    /// The wait an answer asks for in its `Retry-After` (seconds), when
    /// its status is one that may carry it.
    pub fn retry_after(&self, status: u16, header: Option<&str>) -> Option<Duration> {
        if !self.respect_retry_after || !matches!(status, 413 | 429 | 503) {
            return None;
        }
        let seconds: f64 = header?.trim().parse().ok()?;
        (seconds.is_finite() && seconds >= 0.0).then(|| Duration::from_secs_f64(seconds.min(120.0)))
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::none()
    }
}
