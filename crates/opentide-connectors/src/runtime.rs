//! The runtime: tokio, a bounded fan-out over tenants, cancellation.
//!
//! The CLI is synchronous; a command that reaches tenants calls [`block_on`],
//! which runs the work on a runtime of its own and returns its result. Work
//! across tenants goes through [`fan_out`]: at most `limit` tenants at once,
//! each reported as a [`TenantEvent`] when it ends, and every tenant not yet
//! finished stopped when the run's [`CancellationToken`] fires (Ctrl-C, a
//! client's `$/cancelRequest`; [`cancel_when`] wires a polled flag to it).

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::TenantLabel;
use crate::error::ConnectorError;
use crate::progress::{ProgressSink, TenantEvent};

/// A runtime's builder: two worker threads, or, on WASI (one thread), the
/// current thread.
pub fn builder() -> tokio::runtime::Builder {
    #[cfg(not(target_os = "wasi"))]
    {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(2);
        builder
    }
    #[cfg(target_os = "wasi")]
    {
        tokio::runtime::Builder::new_current_thread()
    }
}

/// Runs *work* on a thread of its own and waits for it, as
/// `std::thread::scope(|s| s.spawn(work).join())` does: a panic in *work*
/// is the `Err`. A runtime cannot start on a thread that is already driving
/// one, so a blocking caller inside a command hands the work to this. On
/// WASI, which has no threads (a spawn traps), it runs on the caller's, and
/// a panic is caught there.
///
/// # Errors
///
/// The panic of *work*.
pub fn apart<T: Send>(work: impl FnOnce() -> T + Send) -> std::thread::Result<T> {
    #[cfg(not(target_os = "wasi"))]
    {
        std::thread::scope(|scope| scope.spawn(work).join())
    }
    #[cfg(target_os = "wasi")]
    {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
    }
}

/// Runs *work* to completion on a runtime of its own.
///
/// # Errors
///
/// The runtime cannot start; or, on WASI, the caller is inside a runtime
/// (the MCP server's): tokio refuses to start one there (it panics), and
/// WASI has no other thread to hand the work to (`apart` runs it on this
/// one).
pub fn block_on<F: Future>(work: F) -> Result<F::Output, String> {
    Ok(start()?.block_on(work))
}

/// A runtime of its own, for a caller that runs many pieces of work one
/// after another on it (`deploy`, a request per rule): [`block_on`]'s,
/// kept.
///
/// # Errors
///
/// As [`block_on`]'s: the runtime cannot start, or, on WASI, the caller is
/// inside a runtime, where blocking on another would panic.
pub fn start() -> Result<tokio::runtime::Runtime, String> {
    #[cfg(target_os = "wasi")]
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(INSIDE_A_RUNTIME.into());
    }
    build()
}

/// How many runtimes this process has started through [`block_on`],
/// [`start`] and [`shared`]: tests read it to prove a client reuses one.
static STARTED: AtomicUsize = AtomicUsize::new(0);

/// A new runtime, counted in [`started`]: [`start`]'s and [`shared`]'s.
fn build() -> Result<tokio::runtime::Runtime, String> {
    let runtime = builder()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the network runtime: {error}"))?;
    STARTED.fetch_add(1, Ordering::Relaxed);
    Ok(runtime)
}

/// How many runtimes [`block_on`] and [`shared`] have started in this
/// process.
#[doc(hidden)]
pub fn started() -> usize {
    STARTED.load(Ordering::Relaxed)
}

/// The process's shared runtime, started by its first caller and never
/// dropped (a multi-thread runtime dropped inside another runtime panics).
/// Clients that ask many times, such as the CVE lookups, run on it rather
/// than start one per request.
///
/// # Errors
///
/// The runtime cannot start.
pub fn shared() -> Result<&'static tokio::runtime::Runtime, String> {
    static SHARED: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    SHARED.get_or_init(build).as_ref().map_err(Clone::clone)
}

/// Runs *work* to completion on the [`shared`] runtime, from any thread: a
/// caller inside a runtime (the MCP server's) hands it to a thread of its
/// own ([`apart`]), since a runtime cannot block a thread that drives one.
///
/// # Errors
///
/// The runtime cannot start; *work* panicked; or, on WASI, the caller is
/// inside a runtime, as for [`block_on`].
pub fn block_on_shared<F: Future + Send>(work: F) -> Result<F::Output, String>
where
    F::Output: Send,
{
    let runtime = shared()?;
    if tokio::runtime::Handle::try_current().is_err() {
        return Ok(runtime.block_on(work));
    }
    #[cfg(target_os = "wasi")]
    {
        drop(work);
        Err(INSIDE_A_RUNTIME.into())
    }
    #[cfg(not(target_os = "wasi"))]
    {
        apart(|| runtime.block_on(work)).map_err(|_| "the network work panicked".to_owned())
    }
}

/// [`block_on`]'s refusal inside a runtime on WASI.
#[cfg(target_os = "wasi")]
const INSIDE_A_RUNTIME: &str =
    "cannot start the network runtime inside another on a target without threads";

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
/// after *cancel* fired is not started; one running is stopped. A tenant
/// whose work panics fails with [`ConnectorError::Crashed`].
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
    let mut spawned: HashMap<tokio::task::Id, (usize, TenantLabel, Instant)> = HashMap::new();
    for (index, label) in tenants.into_iter().enumerate() {
        let token = cancel.child_token();
        let future = work(label.clone(), token.clone());
        let permits = permits.clone();
        let progress = progress.clone();
        let tenant = label.clone();
        let handle = set.spawn(async move {
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
            report(progress.as_ref(), &label, &result, elapsed);
            (
                index,
                TenantRun {
                    label,
                    result,
                    elapsed,
                },
            )
        });
        spawned.insert(handle.id(), (index, tenant, Instant::now()));
    }
    let mut runs: Vec<(usize, TenantRun<T>)> = Vec::new();
    while let Some(joined) = set.join_next_with_id().await {
        match joined {
            Ok((_, run)) => runs.push(run),
            // A tenant whose work panicked failed: it is reported like any
            // other failure, never dropped from the run.
            Err(failure) => {
                let Some((index, label, started)) = spawned.remove(&failure.id()) else {
                    continue;
                };
                let elapsed = started.elapsed();
                let result = Err(ConnectorError::Crashed {
                    platform: label.platform.clone(),
                    tenant: label.tenant.clone(),
                    message: panic_message(failure),
                });
                report(progress.as_ref(), &label, &result, elapsed);
                runs.push((
                    index,
                    TenantRun {
                        label,
                        result,
                        elapsed,
                    },
                ));
            }
        }
    }
    runs.sort_by_key(|(index, _)| *index);
    runs.into_iter().map(|(_, run)| run).collect()
}

/// The tenant's progress event, unless it was cancelled.
fn report<T: Rows>(
    progress: &dyn ProgressSink,
    label: &TenantLabel,
    result: &Result<T, ConnectorError>,
    elapsed: Duration,
) {
    if matches!(result, Err(ConnectorError::Cancelled)) {
        return;
    }
    progress.emit(&TenantEvent::new(
        &label.platform,
        &label.tenant,
        result.is_ok(),
        result.as_ref().map_or(0, Rows::rows),
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    ));
}

/// What a task that did not finish says: its panic's text, when it has one.
fn panic_message(failure: tokio::task::JoinError) -> String {
    if !failure.is_panic() {
        return failure.to_string();
    }
    let payload = failure.into_panic();
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "a panic".to_owned()
    }
}

#[cfg(all(test, target_os = "wasi"))]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn block_on_inside_a_runtime_is_refused_not_a_panic() {
        assert_eq!(block_on(async { 7 }), Err(INSIDE_A_RUNTIME.to_owned()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn start_inside_a_runtime_is_refused_not_a_panic() {
        assert_eq!(start().err().as_deref(), Some(INSIDE_A_RUNTIME));
    }

    #[test]
    fn apart_gives_the_result_or_the_panic() {
        assert_eq!(apart(|| 1 + 1).ok(), Some(2));
        assert!(apart(|| -> u8 { panic!("stopped") }).is_err());
    }
}
