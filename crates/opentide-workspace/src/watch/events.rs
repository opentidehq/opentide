//! What wakes the watch loop: the `notify` crate's file system events on the
//! object folders. An event says only that something may have changed; the
//! [`super::Watcher`] then compares snapshots, which is what decides.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};

use crate::fs::FileSystem;

/// How long a burst of events (an editor's save: a temporary file, a write,
/// a rename) is let settle before the folders are read.
pub const SETTLE: Duration = Duration::from_millis(100);

/// The events of the watched folders.
pub struct Events {
    _watcher: RecommendedWatcher,
    receiver: Receiver<notify::Result<notify::Event>>,
}

impl std::fmt::Debug for Events {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Events").finish_non_exhaustive()
    }
}

impl Events {
    /// Watches each folder of `roots` that exists, without descending: an
    /// object is a direct child of its folder.
    ///
    /// # Errors
    ///
    /// The platform's watcher could not be started, or a folder could not
    /// be watched.
    pub fn watch(fs: &dyn FileSystem, roots: &[PathBuf]) -> notify::Result<Self> {
        let (sender, receiver) = channel();
        let mut watcher = notify::recommended_watcher(sender)?;
        for root in roots.iter().filter(|root| fs.is_dir(root)) {
            watcher.watch(Path::new(root), RecursiveMode::NonRecursive)?;
        }
        Ok(Self {
            _watcher: watcher,
            receiver,
        })
    }

    /// Waits up to `timeout` for an event, then lets a burst settle; whether
    /// any arrived. A watcher error counts as an event: the snapshot
    /// comparison that follows is what decides.
    pub fn wait(&self, timeout: Duration) -> bool {
        match self.receiver.recv_timeout(timeout) {
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return false,
        }
        let until = Instant::now() + SETTLE;
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            if self.receiver.recv_timeout(left).is_err() {
                break;
            }
        }
        true
    }
}

impl<V: super::Validate> super::Watcher<'_, V> {
    /// Validates, shows the pass, then waits for changes and shows each pass
    /// that follows, until `stop` says so (the command line's Ctrl-C). An
    /// event wakes the loop at once; without one it looks every
    /// [`super::POLL_INTERVAL`].
    ///
    /// # Errors
    ///
    /// The folders could not be watched.
    pub fn run(
        &mut self,
        mut show: impl FnMut(&super::WatchRun),
        stop: impl Fn() -> bool,
    ) -> notify::Result<()> {
        let events = Events::watch(self.fs, self.roots())?;
        show(&self.start());
        while !stop() {
            events.wait(super::POLL_INTERVAL);
            if let Some(run) = self.poll() {
                show(&run);
            }
        }
        Ok(())
    }
}
