//! Pacing requests to a tenant's rate limit: at most so many calls in any
//! rolling window, counted per key ([`Pacer`]), on a [`Clock`] a test can
//! replace. Bitdefender GravityZone paces its rule writes per API key,
//! Exabeam every request of the process under one key.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::connector::BoxFuture;
use crate::error::ConnectorError;

/// What sleeps and tells the time: tokio's clock in a run, a recorded one
/// in tests.
pub trait Clock: Send + Sync {
    /// Now, from the clock's own start.
    fn now(&self) -> Duration;

    /// Waits `duration`, or returns [`ConnectorError::Cancelled`] when the
    /// run is cancelled first.
    fn sleep<'a>(
        &'a self,
        duration: Duration,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), ConnectorError>>;
}

/// tokio's clock, so a test may pause it (`tokio::time::pause`), read from
/// when the clock was made.
#[derive(Debug)]
pub struct SystemClock {
    start: tokio::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: tokio::time::Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        tokio::time::Instant::now().saturating_duration_since(self.start)
    }

    fn sleep<'a>(
        &'a self,
        duration: Duration,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), ConnectorError>> {
        Box::pin(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => Ok(()),
                () = cancel.cancelled() => Err(ConnectorError::Cancelled),
            }
        })
    }
}

/// At most `limit` calls per key in any rolling `window`, on its clock.
pub struct Pacer {
    calls: Mutex<HashMap<u64, VecDeque<Duration>>>,
    limit: usize,
    window: Duration,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Pacer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pacer")
            .field("limit", &self.limit)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl Pacer {
    /// A pacer of `limit` calls per `window` on the [`SystemClock`].
    pub fn new(limit: usize, window: Duration) -> Self {
        Self::with_clock(limit, window, Arc::new(SystemClock::default()))
    }

    /// A pacer of `limit` calls per `window` on `clock`.
    pub fn with_clock(limit: usize, window: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
            limit: limit.max(1),
            window,
            clock,
        }
    }

    /// The calls allowed per window.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The span of time [`limit`](Self::limit) calls are allowed in.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// The clock the pacer, and a rate limit's wait, run on.
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// How long to wait before a call on `key` at `now`, or `None` (and the
    /// call counted) when it may go now.
    pub fn reserve(&self, key: u64, now: Duration) -> Option<Duration> {
        let mut calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let made = calls.entry(key).or_default();
        while made
            .front()
            .is_some_and(|first| now.saturating_sub(*first) >= self.window)
        {
            made.pop_front();
        }
        if made.len() < self.limit {
            made.push_back(now);
            return None;
        }
        let first = made.front().copied().unwrap_or(now);
        Some(self.window.saturating_sub(now.saturating_sub(first)))
    }

    /// Waits until a call on `key` fits in the window, and counts it.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Cancelled`] when the run is cancelled first.
    pub async fn wait(&self, key: u64, cancel: &CancellationToken) -> Result<(), ConnectorError> {
        loop {
            match self.reserve(key, self.clock.now()) {
                None => return Ok(()),
                Some(pause) if pause.is_zero() => {}
                Some(pause) => self.clock.sleep(pause, cancel).await?,
            }
        }
    }

    /// Forgets every call counted.
    pub fn reset(&self) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    #[test]
    fn calls_are_counted_per_key_in_a_rolling_window() {
        let pacer = Pacer::new(5, at(60));
        for second in 0..5 {
            assert_eq!(pacer.reserve(1, at(second)), None);
        }
        assert_eq!(pacer.reserve(1, at(10)), Some(at(50)));
        assert_eq!(pacer.reserve(2, at(10)), None);
        assert_eq!(pacer.reserve(1, at(60)), None);
        assert_eq!(pacer.reserve(1, at(60)), Some(at(1)));
        pacer.reset();
        assert_eq!(pacer.reserve(1, at(60)), None);
    }
}
