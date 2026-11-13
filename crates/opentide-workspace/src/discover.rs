//! Which files are objects (`registry/catalogue.py`, workspace 1.3, #584).
//!
//! An object is a YAML file directly in its family's folder. A YAML file in a
//! subfolder is listed as nested and never read. Names are matched
//! case-sensitively: `.yaml` and `.yml`, but not `.debug.yaml` or
//! `.debug.yml`, which are scratch output.

use std::io;
use std::path::{Path, PathBuf};

use crate::fs::{EntryKind, FileSystem};

/// Suffixes an object file may carry.
pub const OBJECT_SUFFIXES: [&str; 2] = [".yaml", ".yml"];
/// Scratch output some tools write next to objects; never an object.
pub const DEBUG_SUFFIXES: [&str; 2] = [".debug.yaml", ".debug.yml"];
/// How deep a walk under an object folder goes. Python's `rglob` has no
/// bound; this one only keeps a pathological tree from exhausting memory.
pub const MAX_DEPTH: usize = 64;

/// Whether `name` is an object file name: `*.yaml` or `*.yml`, not
/// `*.debug.yaml` or `*.debug.yml`.
pub fn is_object_file_name(name: &str) -> bool {
    OBJECT_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
        && !DEBUG_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// The object files directly in a folder, and those in its subfolders, each
/// sorted as Python sorts paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// Objects.
    pub files: Vec<PathBuf>,
    /// YAML files in subfolders: not objects.
    pub nested: Vec<PathBuf>,
    /// The objects that are symbolic links: a change to what one points at
    /// changes the object.
    pub links: Vec<PathBuf>,
}

/// Why an object folder was not scanned (`could_not_find_object_folder`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderProblem {
    /// It does not exist: normal before the first `generate`.
    Missing,
    /// It is a file, or something else that is not a folder.
    NotADirectory,
    /// It cannot be read.
    Unreadable(String),
}

/// Scans the object folder `dir`. A subfolder that cannot be listed is
/// skipped, as `rglob` skips it; a linked subfolder is not entered.
///
/// # Errors
///
/// A [`FolderProblem`]: the folder is missing, not a folder, or unreadable.
pub fn scan(fs: &dyn FileSystem, dir: &Path) -> Result<Scan, FolderProblem> {
    scan_with(fs, dir, is_object_file_name)
}

/// [`scan`], with debug output (`*.debug.yaml`) among the files: `lint`
/// names it, so `lint --fix` keeps its `.debug` suffix
/// (`scan_object_dir(include_debug=True)`).
///
/// # Errors
///
/// As [`scan`].
pub fn scan_including_debug(fs: &dyn FileSystem, dir: &Path) -> Result<Scan, FolderProblem> {
    scan_with(fs, dir, |name| {
        OBJECT_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
    })
}

fn scan_with(
    fs: &dyn FileSystem,
    dir: &Path,
    is_object: fn(&str) -> bool,
) -> Result<Scan, FolderProblem> {
    match fs.kind(dir) {
        Ok(EntryKind::Dir) => {}
        Ok(_) => return Err(FolderProblem::NotADirectory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(FolderProblem::Missing);
        }
        Err(error) => return Err(FolderProblem::Unreadable(error.to_string())),
    }
    let top = fs
        .read_dir(dir)
        .map_err(|error| FolderProblem::Unreadable(error.to_string()))?;
    let mut scan = Scan::default();
    let mut stack = vec![(dir.to_path_buf(), top, 0usize)];
    while let Some((folder, entries, depth)) = stack.pop() {
        for entry in entries {
            let path = folder.join(&entry.file_name);
            if entry.kind == EntryKind::Dir
                && !entry.symlink
                && depth < MAX_DEPTH
                && let Ok(children) = fs.read_dir(&path)
            {
                stack.push((path.clone(), children, depth + 1));
            }
            if entry.kind != EntryKind::File || !is_object(&entry.name) {
                continue;
            }
            if depth == 0 {
                if entry.symlink {
                    scan.links.push(path.clone());
                }
                scan.files.push(path);
            } else {
                scan.nested.push(path);
            }
        }
    }
    scan.files.sort();
    scan.nested.sort();
    scan.links.sort();
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;

    #[test]
    fn object_names_are_case_sensitive_and_skip_debug_output() {
        for name in ["r.yaml", "r.yml", "a.b.yaml", ".hidden.yaml"] {
            assert!(is_object_file_name(name), "{name}");
        }
        for name in ["r.YAML", "r.json", "r.debug.yaml", "r.debug.yml", "yaml"] {
            assert!(!is_object_file_name(name), "{name}");
        }
    }

    #[test]
    fn direct_children_are_objects_and_deeper_files_are_nested() {
        let fs = MemoryFs::new();
        fs.write("/w/rules/b.yaml", "");
        fs.write("/w/rules/a.yml", "");
        fs.write("/w/rules/x.debug.yaml", "");
        fs.write("/w/rules/notes.md", "");
        fs.write("/w/rules/team/c.yaml", "");
        fs.write("/w/rules/team/deep/d.yaml", "");
        fs.create_dir("/w/rules/dir.yaml");
        let found = scan(&fs, Path::new("/w/rules")).unwrap();
        assert_eq!(
            found.files,
            [
                PathBuf::from("/w/rules/a.yml"),
                PathBuf::from("/w/rules/b.yaml")
            ]
        );
        assert_eq!(
            found.nested,
            [
                PathBuf::from("/w/rules/team/c.yaml"),
                PathBuf::from("/w/rules/team/deep/d.yaml")
            ]
        );
    }

    #[test]
    fn lint_scans_debug_output_too() {
        let fs = MemoryFs::new();
        fs.write("/w/rules/b.yaml", "");
        fs.write("/w/rules/x.debug.yaml", "");
        fs.write("/w/rules/team/y.debug.yml", "");
        let found = scan_including_debug(&fs, Path::new("/w/rules")).unwrap();
        assert_eq!(
            found.files,
            [
                PathBuf::from("/w/rules/b.yaml"),
                PathBuf::from("/w/rules/x.debug.yaml")
            ]
        );
        assert_eq!(found.nested, [PathBuf::from("/w/rules/team/y.debug.yml")]);
    }

    #[test]
    fn a_folder_that_is_missing_or_a_file_is_a_problem() {
        let fs = MemoryFs::new();
        fs.write("/w/file", "");
        assert_eq!(scan(&fs, Path::new("/w/none")), Err(FolderProblem::Missing));
        assert_eq!(
            scan(&fs, Path::new("/w/file")),
            Err(FolderProblem::NotADirectory)
        );
    }
}
