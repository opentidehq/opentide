//! Workspaces kept warm between runs in one process: `opentide serve`'s
//! read-only requests (UC-2.7, #822).
//!
//! A [`Session`] keeps each workspace it opened, by the [`Options`] that
//! opened it. The next open with the same options gets the kept one, brought
//! up to date first:
//!
//! - every folder the workspace reads (its object folders, recursively, and
//!   its configuration folders) is listed again and each entry's [`Stamp`]
//!   compared with the one taken before the last load, so an edit, a new
//!   file or a deleted one is read without being announced, as the Python
//!   `serve` reads it ([`crate::Workspace::invalidate`] re-reads only those
//!   files);
//! - the paths [`Session::invalidate`] was told about since (`serve`'s
//!   `invalidate`, a file the configuration points at) are invalidated too;
//! - a workspace whose root moved (a marker created or deleted) is opened
//!   again.
//!
//! The stamps are taken before the files are read, so a file written while
//! the workspace loads counts as changed at the next open.
//!
//! Each open returns a clone: a run that changes its workspace changes its
//! own copy. The process-wide session [`activate`] turns on makes
//! [`crate::Workspace::open`] go through it for the disk ([`FileSystem::shared`]),
//! so a command that opens its workspace the usual way is warm under `serve`
//! and cold everywhere else.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::fs::{EntryKind, FileSystem, Stamp};
use crate::root;
use crate::workspace::{Change, OpenError, Options, Workspace};

/// What the folders a workspace reads held: each entry's path, with its
/// stamp (`None` for a folder).
type Fingerprint = BTreeMap<PathBuf, Option<Stamp>>;

/// One kept workspace.
struct Kept {
    options: Options,
    workspace: Workspace,
    fingerprint: Fingerprint,
    /// Paths named by [`Session::invalidate`] since the last open.
    pending: Vec<PathBuf>,
}

/// What a session has done, counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Opens served.
    pub opens: usize,
    /// Opens served by a kept workspace (brought up to date or not).
    pub hits: usize,
    /// Of the hits, those that re-read something.
    pub refreshes: usize,
    /// Workspaces kept now.
    pub kept: usize,
    /// Object files read by the workspaces kept now, over their lifetime.
    pub file_reads: usize,
}

/// Workspaces kept between runs.
#[derive(Default)]
pub struct Session {
    kept: Vec<Kept>,
    opens: usize,
    hits: usize,
    refreshes: usize,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// An empty session.
    pub fn new() -> Self {
        Self::default()
    }

    /// The workspace `options` place, read through `fs`: the kept one,
    /// brought up to date, or a fresh load, which is kept.
    ///
    /// # Errors
    ///
    /// The configuration does not resolve; nothing is kept for `options`.
    pub fn open(
        &mut self,
        fs: Arc<dyn FileSystem>,
        options: Options,
    ) -> Result<Workspace, OpenError> {
        self.opens += 1;
        if let Some(position) = self.kept.iter().position(|kept| kept.options == options) {
            let mut kept = self.kept.swap_remove(position);
            if let Some(refreshed) = Self::refresh(&mut kept, fs.as_ref()) {
                self.hits += 1;
                if refreshed {
                    self.refreshes += 1;
                }
                let workspace = kept.workspace.clone();
                self.kept.push(kept);
                return Ok(workspace);
            }
            // The root moved, or the configuration no longer resolves: a
            // fresh load says which.
        }
        let mut fingerprint = Fingerprint::new();
        let workspace = Workspace::open_observed(fs, options.clone(), |workspace_fs, config| {
            fingerprint = take_fingerprint(workspace_fs, &folders(config));
        })?;
        self.kept.push(Kept {
            options,
            workspace: workspace.clone(),
            fingerprint,
            pending: Vec::new(),
        });
        Ok(workspace)
    }

    /// Brings `kept` up to date: `Some(whether anything was re-read)`, or
    /// `None` when it must be opened afresh.
    fn refresh(kept: &mut Kept, fs: &dyn FileSystem) -> Option<bool> {
        if root::resolve(fs, &kept.workspace.options().roots) != *kept.workspace.roots() {
            return None;
        }
        let now = take_fingerprint(fs, &folders(kept.workspace.configuration()));
        let mut changes: Vec<Change> = kept.pending.drain(..).map(Change::changed).collect();
        changes.extend(differences(&kept.fingerprint, &now));
        if changes.is_empty() {
            return Some(false);
        }
        kept.workspace.invalidate(&changes).ok()?;
        // Taken before the re-read: a file written meanwhile differs at the
        // next open. Folders a changed configuration reads instead show up
        // there as created, and are read again then.
        kept.fingerprint = now;
        Some(true)
    }

    /// Takes `paths` into account at each kept workspace's next open: a path
    /// inside a workspace re-reads what it names, any other loads that
    /// workspace again ([`Workspace::invalidate`]). The number of kept
    /// workspaces.
    pub fn invalidate(&mut self, paths: &[PathBuf]) -> usize {
        if paths.is_empty() {
            return 0;
        }
        for kept in &mut self.kept {
            kept.pending.extend(paths.iter().cloned());
        }
        self.kept.len()
    }

    /// Forgets every kept workspace (a run that may have written one).
    pub fn clear(&mut self) {
        self.kept.clear();
    }

    /// What the session has done.
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            opens: self.opens,
            hits: self.hits,
            refreshes: self.refreshes,
            kept: self.kept.len(),
            file_reads: self
                .kept
                .iter()
                .map(|kept| kept.workspace.stats().file_reads)
                .sum(),
        }
    }
}

/// The folders a workspace with `config` reads.
fn folders(config: &crate::Configuration) -> Vec<PathBuf> {
    let mut folders: Vec<PathBuf> = config
        .object_folders
        .iter()
        .filter_map(|folder| folder.path.clone())
        .chain(config.folders.iter().cloned())
        .collect();
    folders.sort();
    folders.dedup();
    folders
}

/// Every entry under `folders`, each folder itself included; linked
/// folders are not entered, as discovery does not enter them.
fn take_fingerprint(fs: &dyn FileSystem, folders: &[PathBuf]) -> Fingerprint {
    let mut out = Fingerprint::new();
    let mut pending: Vec<PathBuf> = folders.to_vec();
    while let Some(folder) = pending.pop() {
        let Ok(entries) = fs.read_dir(&folder) else {
            continue;
        };
        out.insert(folder.clone(), None);
        for entry in entries {
            let path = folder.join(&entry.file_name);
            match entry.kind {
                EntryKind::Dir if !entry.symlink => pending.push(path),
                EntryKind::Dir => {
                    out.insert(path, None);
                }
                EntryKind::File | EntryKind::Other => {
                    let stamp = fs.stamp(&path).ok();
                    out.insert(path, stamp.or(Some(Stamp { version: 0, len: 0 })));
                }
            }
        }
    }
    out
}

/// The changes that turn `before` into `after`.
fn differences(before: &Fingerprint, after: &Fingerprint) -> Vec<Change> {
    let mut changes = Vec::new();
    for (path, stamp) in before {
        match after.get(path) {
            None => changes.push(Change::deleted(path.clone())),
            Some(now) if now != stamp => changes.push(Change::changed(path.clone())),
            Some(_) => {}
        }
    }
    for path in after.keys() {
        if !before.contains_key(path) {
            changes.push(Change::created(path.clone()));
        }
    }
    changes
}

/// The process-wide session.
static GLOBAL: Mutex<Option<Session>> = Mutex::new(None);
/// Whether [`Workspace::open`] goes through [`GLOBAL`] now.
static ACTIVE: AtomicBool = AtomicBool::new(false);

fn global() -> MutexGuard<'static, Option<Session>> {
    GLOBAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// While the returned guard lives, [`Workspace::open`] on a shared
/// filesystem (the disk) goes through the process-wide session: the host
/// (`serve`) activates it around a read-only run. Activations do not nest.
#[must_use = "the session is active only while the guard lives"]
pub fn activate() -> Active {
    ACTIVE.store(true, Ordering::SeqCst);
    Active(())
}

/// The process-wide session's activation ([`activate`]).
#[derive(Debug)]
pub struct Active(());

impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// [`Workspace::open`] through the process-wide session, when it is active
/// and `fs` is shared; `None` otherwise.
pub(crate) fn open_global(
    fs: &Arc<dyn FileSystem>,
    options: &Options,
) -> Option<Result<Workspace, OpenError>> {
    if !ACTIVE.load(Ordering::SeqCst) || !fs.shared() {
        return None;
    }
    let mut guard = global();
    let session = guard.get_or_insert_with(Session::new);
    Some(session.open(Arc::clone(fs), options.clone()))
}

/// [`Session::invalidate`] on the process-wide session.
pub fn invalidate(paths: &[PathBuf]) -> usize {
    global()
        .as_mut()
        .map_or(0, |session| session.invalidate(paths))
}

/// [`Session::clear`] on the process-wide session.
pub fn clear() {
    if let Some(session) = global().as_mut() {
        session.clear();
    }
}

/// [`Session::stats`] of the process-wide session.
pub fn stats() -> SessionStats {
    global().as_ref().map(Session::stats).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differences_name_each_created_changed_and_deleted_path() {
        let stamp = |version| Some(Stamp { version, len: 1 });
        let before: Fingerprint = [
            (PathBuf::from("/a"), None),
            (PathBuf::from("/a/x"), stamp(1)),
            (PathBuf::from("/a/y"), stamp(1)),
        ]
        .into_iter()
        .collect();
        let after: Fingerprint = [
            (PathBuf::from("/a"), None),
            (PathBuf::from("/a/x"), stamp(2)),
            (PathBuf::from("/a/z"), stamp(1)),
        ]
        .into_iter()
        .collect();
        let changes = differences(&before, &after);
        assert_eq!(
            changes,
            vec![
                Change::changed("/a/x"),
                Change::deleted("/a/y"),
                Change::created("/a/z"),
            ]
        );
        assert!(differences(&after, &after).is_empty());
    }
}
