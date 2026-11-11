//! The runtime: tokio, a bounded fan-out over tenants, cancellation.
//!
//! The CLI is synchronous; a command that reaches tenants calls [`block_on`],
//! which runs the work on a runtime of its own and returns its result. Work
//! across tenants goes through [`fan_out`]: at most `limit` tenants at once,
//! each reported as a [`TenantEvent`] when it ends, and every tenant not yet
//! finished stopped when the run's [`CancellationToken`] fires (Ctrl-C, a
//! client's `$/cancelRequest`; [`cancel_when`] wires a polled flag to it).

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::TenantLabel;
use crate::error::ConnectorError;
use crate::progress::{ProgressSink, TenantEvent};

/// Runs *work* to completion on a runtime of its own.
pub fn block_on<F: Future>(work: F) -> Result<F::Output, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the network runtime: {error}"))?;
    Ok(runtime.block_on(work))
}

/// Cancels *token* once *requested* returns true, checking every 50 ms
/// until the token is cancelled. For the CLI's Ctrl-C flag.
pub fn cancel_when(
    token: &CancellationToken,
    requested: impl Fn() -> bool + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let token = token.clone();
    tokio::spawn(async move {
        loop {
            if requested() {
                token.cancel();
                return;
            }
            tokio::select! {
                () = token.cancelled() => return,
                () = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    })
}

/// One tenant's result in a fan-out.
#[derive(Debug)]
pub struct TenantRun<T> {
    /// The tenant.
    pub label: TenantLabel,
    /// What its work returned.
    pub result: Result<T, ConnectorError>,
    /// How long it took.
    pub elapsed: Duration,
}

/// What a tenant's work reports for its progress event.
pub trait Rows {
    /// The rows it returned (0 when it returns none).
    fn rows(&self) -> u64 {
        0
    }
}

impl Rows for () {}

/// Runs *work* for every tenant, at most *limit* at once, in the order
/// given; the results come back in that order. A tenant whose turn comes
/// after *cancel* fired is not started; one running is stopped.
pub async fn fan_out<T, W, F>(
    tenants: Vec<TenantLabel>,
    limit: usize,
    cancel: &CancellationToken,
    progress: Arc<dyn ProgressSink>,
    work: W,
) -> Vec<TenantRun<T>>
where
    T: Rows + Send + 'static,
    W: Fn(TenantLabel, CancellationToken) -> F,
    F: Future<Output = Result<T, ConnectorError>> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(limit.max(1)));
    let mut set = JoinSet::new();
    for (index, label) in tenants.into_iter().enumerate() {
        let token = cancel.child_token();
        let future = work(label.clone(), token.clone());
        let permits = permits.clone();
        let progress = progress.clone();
        set.spawn(async move {
            let started = Instant::now();
            let result = tokio::select! {
                biased;
                () = token.cancelled() => Err(ConnectorError::Cancelled),
                outcome = async {
                    let _permit = permits.acquire_owned().await.map_err(|_| ConnectorError::Cancelled)?;
                    if token.is_cancelled() {
                        return Err(ConnectorError::Cancelled);
                    }
                    future.await
                } => outcome,
            };
            let elapsed = started.elapsed();
            let rows = result.as_ref().map_or(0, Rows::rows);
            if !matches!(result, Err(ConnectorError::Cancelled)) {
                progress.emit(&TenantEvent::new(
                    &label.platform,
                    &label.tenant,
                    result.is_ok(),
                    rows,
                    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                ));
            }
            (
                index,
                TenantRun {
                    label,
                    result,
                    elapsed,
                },
            )
        });
    }
    let mut runs: Vec<(usize, TenantRun<T>)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(run) = joined {
            runs.push(run);
        }
    }
    runs.sort_by_key(|(index, _)| *index);
    runs.into_iter().map(|(_, run)| run).collect()
}
