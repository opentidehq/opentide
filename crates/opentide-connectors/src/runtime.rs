//! The runtime: tokio, a bounded fan-out over tenants, cancellation.
//!
//! One tokio runtime per process ([`shared`], #1558): started by its first
//! user, two worker threads (the current thread on WASI), never dropped. The
//! CLI is synchronous; a command that reaches tenants calls [`block_on`],
//! which drives the work on that runtime from the calling thread and
//! returns its result. Work across tenants goes through [`fan_out`]: at most
//! `limit` tenants at once, each reported as a [`TenantEvent`] when it ends,
//! and every tenant not yet finished stopped when the run's
//! [`CancellationToken`] fires (Ctrl-C, a client's `$/cancelRequest`;
//! [`cancel_when`] wires a polled flag to it).
//!
//! CPU work runs on rayon and network I/O on this runtime: a blocking call
//! from async code goes through `tokio::task::spawn_blocking`, and
//! [`block_on`] may be called from any thread that is not driving async
//! work (the main thread, a rayon thread, a `spawn_blocking` thread). From
//! one that is, it answers [`INSIDE_THE_RUNTIME`] instead of blocking it.

use std::cell::Cell;
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

/// [`shared`]'s builder: two worker threads, or, on WASI (one thread), the
/// current thread. It installs the thread flags [`block_on`] reads, so it
/// builds only [`shared`].
fn builder() -> tokio::runtime::Builder {
    #[cfg(not(target_os = "wasi"))]
    {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder
            .worker_threads(2)
            .thread_name("opentide-net")
            // Every thread of the runtime is known as one: a `spawn_blocking`
            // thread may block on it.
            .on_thread_start(|| RUNTIME_THREAD.set(true))
            // A worker thread drives async work: [`block_on`] there would
            // block it, so it refuses. (Only workers park and unpark. A worker
            // just started may poll a task before it first parks; a
            // `block_on` in that task gets tokio's panic, caught as the
            // task's crash: no opentide code blocks inside async work.)
            .on_thread_unpark(|| ASYNC_THREAD.set(true));
        builder
    }
    #[cfg(target_os = "wasi")]
    {
        tokio::runtime::Builder::new_current_thread()
    }
}

thread_local! {
    /// Whether this thread drives async work: [`block_on`] is driving a
    /// future here, or it is one of [`shared`]'s worker threads.
    static ASYNC_THREAD: Cell<bool> = const { Cell::new(false) };
    /// Whether this thread is one of [`shared`]'s (a worker, or a
    /// `spawn_blocking` thread).
    static RUNTIME_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// [`block_on`]'s refusal on a thread that drives async work, where blocking
/// would stall (or, in tokio, panic): await the future there instead, or
/// hand the blocking call to `tokio::task::spawn_blocking`.
pub const INSIDE_THE_RUNTIME: &str = "cannot block on the network runtime from a thread that \
     drives asynchronous work; await the work there, or call it through spawn_blocking";

/// Runs *work* to completion on the [`shared`] runtime, driven from this
/// thread: the main thread, a rayon thread, a `spawn_blocking` thread of the
/// runtime.
///
/// # Errors
///
/// The runtime cannot start, or this thread may be driving async work
/// ([`INSIDE_THE_RUNTIME`]), where tokio would panic: a call nested in
/// another `block_on`, from a worker of the runtime, or from inside another
/// runtime (an embedder's, or the MCP server's on WASI), which tokio cannot
/// tell from one that drives it. [`block_on_anywhere`] serves that last
/// caller.
pub fn block_on<F: Future>(work: F) -> Result<F::Output, String> {
    let runtime = shared()?;
    if ASYNC_THREAD.get() || in_another_runtime() {
        return Err(INSIDE_THE_RUNTIME.into());
    }
    Ok(drive(runtime, work))
}

/// [`block_on`], which also serves a caller inside another runtime (an
/// embedder's, or the MCP server's until it runs on [`shared`]) by handing
/// the work to a thread of its own (`apart`). For a client a host may
/// call from its own runtime (the CVE lookups, MISP, a plugin's tenant).
///
/// # Errors
///
/// As [`block_on`]'s, but inside another runtime only on WASI (no thread to
/// hand the work to); or *work* panicked on that thread.
pub fn block_on_anywhere<F: Future + Send>(work: F) -> Result<F::Output, String>
where
    F::Output: Send,
{
    let runtime = shared()?;
    if ASYNC_THREAD.get() {
        return Err(INSIDE_THE_RUNTIME.into());
    }
    if in_another_runtime() {
        #[cfg(target_os = "wasi")]
        {
            drop(work);
            return Err(INSIDE_THE_RUNTIME.into());
        }
        #[cfg(not(target_os = "wasi"))]
        return apart(|| drive(runtime, work))
            .map_err(|_| "the network work stopped unexpectedly".to_owned());
    }
    Ok(drive(runtime, work))
}

/// Whether this thread is inside a runtime other than [`shared`]: entered
/// (driving it, where tokio panics on a block) or one of its
/// `spawn_blocking` threads, which tokio does not tell apart.
fn in_another_runtime() -> bool {
    !RUNTIME_THREAD.get() && tokio::runtime::Handle::try_current().is_ok()
}

/// *work* driven on *runtime* from this thread, which is marked as driving
/// async work meanwhile.
fn drive<F: Future>(runtime: &tokio::runtime::Runtime, work: F) -> F::Output {
    /// Clears the flag when the drive ends, panics included.
    struct Driving;
    impl Drop for Driving {
        fn drop(&mut self) {
            ASYNC_THREAD.set(false);
        }
    }
    ASYNC_THREAD.set(true);
    let _driving = Driving;
    runtime.block_on(work)
}

/// How many runtimes this process has started ([`shared`]'s, once): tests
/// read it to prove a run starts one.
static STARTED: AtomicUsize = AtomicUsize::new(0);

/// How many runtimes this process has started: 0 before the first network
/// call, 1 after.
#[doc(hidden)]
pub fn started() -> usize {
    STARTED.load(Ordering::Relaxed)
}

/// The process's runtime, started by its first caller and never dropped (a
/// multi-thread runtime dropped inside another runtime panics, and process
/// exit ends its threads). Every network call of the process runs on it.
///
/// # Errors
///
/// The runtime cannot start.
pub fn shared() -> Result<&'static tokio::runtime::Runtime, String> {
    static SHARED: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            let runtime = builder()
                .enable_all()
                .build()
                .map_err(|error| format!("cannot start the network runtime: {error}"))?;
            STARTED.fetch_add(1, Ordering::Relaxed);
            Ok(runtime)
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Runs *work* on a thread of its own and waits for it, as
/// `std::thread::scope(|s| s.spawn(work).join())` does: a panic in *work*
/// is the `Err`. On WASI, which has no threads (a spawn traps), it runs on
/// the caller's, and a panic is caught there. [`block_on_anywhere`]'s way
/// out of an embedder's runtime.
///
/// # Errors
///
/// The panic of *work*.
fn apart<T: Send>(work: impl FnOnce() -> T + Send) -> std::thread::Result<T> {
    #[cfg(not(target_os = "wasi"))]
    {
        std::thread::scope(|scope| scope.spawn(work).join())
    }
    #[cfg(target_os = "wasi")]
    {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
    }
}

/// Runs *work*, a synchronous call that may [`block_on`] the runtime, and
/// gives its result, or its panic as the `Err`: on this thread, or, inside
/// another runtime (an embedder's: a host that calls a command from a tokio
/// task), on a thread of its own (`apart`), where blocking is allowed. On a
/// thread that drives this runtime's async work it runs here, and its
/// [`block_on`] refuses ([`INSIDE_THE_RUNTIME`]): blocking a worker would
/// stall the runtime.
///
/// # Errors
///
/// The panic of *work*.
pub fn sync_call<T: Send>(work: impl FnOnce() -> T + Send) -> std::thread::Result<T> {
    if !ASYNC_THREAD.get() && in_another_runtime() {
        return apart(work);
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
}

/// How often [`cancel_when`] checks its flag.
const CANCEL_POLL: Duration = Duration::from_millis(50);

/// Cancels *token* once *requested* returns true, checking every
/// [`CANCEL_POLL`] until the token is cancelled. For the CLI's Ctrl-C flag.
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
                () = tokio::time::sleep(CANCEL_POLL) => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_runs_on_the_one_runtime() {
        assert_eq!(block_on(async { 7 }), Ok(7));
        assert_eq!(block_on(async { 8 }), Ok(8));
        assert_eq!(started(), 1, "the second call reuses the first's runtime");
    }

    /// #1558: a nested call is refused, never a tokio panic, and the thread
    /// may block again once the outer call returns.
    #[test]
    fn a_call_inside_another_is_refused_not_a_panic() {
        let inner = block_on(async { block_on(async { 1 }) });
        assert_eq!(inner, Ok(Err(INSIDE_THE_RUNTIME.to_owned())));
        assert_eq!(block_on(async { 2 }), Ok(2));
    }

    /// A blocking call handed to `spawn_blocking` (the MCP server's tools)
    /// may block on the runtime again.
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_spawn_blocking_thread_may_block_on_the_runtime() {
        let answer =
            block_on(async { tokio::task::spawn_blocking(|| block_on(async { 3 })).await });
        assert_eq!(answer.map(Result::ok), Ok(Some(Ok(3))));
    }

    /// A worker of the runtime drives async work: it is refused there.
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_worker_is_refused() {
        // The workers have parked once the runtime has served a call.
        assert_eq!(
            block_on(async { tokio::time::sleep(Duration::from_millis(50)).await }),
            Ok(())
        );
        let answer = block_on(async { tokio::spawn(async { block_on(async { 4 }) }).await });
        assert_eq!(
            answer.map(Result::ok),
            Ok(Some(Err(INSIDE_THE_RUNTIME.to_owned())))
        );
    }

    /// Inside another runtime (an embedder's), `block_on` refuses rather
    /// than tokio's panic, and `block_on_anywhere` serves the call.
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn inside_another_runtime_block_on_refuses_and_block_on_anywhere_serves() {
        let embedder = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap_or_else(|error| panic!("{error}"));
        let (refused, served) =
            embedder.block_on(async { (block_on(async { 5 }), block_on_anywhere(async { 6 })) });
        assert_eq!(refused, Err(INSIDE_THE_RUNTIME.to_owned()));
        assert_eq!(served, Ok(6));
    }

    #[cfg(target_os = "wasi")]
    #[tokio::test(flavor = "current_thread")]
    async fn on_wasi_a_call_inside_any_runtime_is_refused() {
        assert_eq!(
            block_on_anywhere(async { 7 }),
            Err(INSIDE_THE_RUNTIME.to_owned())
        );
        assert_eq!(block_on(async { 7 }), Err(INSIDE_THE_RUNTIME.to_owned()));
    }

    #[test]
    fn apart_gives_the_result_or_the_panic() {
        assert_eq!(apart(|| 1 + 1).ok(), Some(2));
        assert!(apart(|| -> u8 { panic!("stopped") }).is_err());
    }
}
