//! Which objects a run validates (`validation/scope.py`): every object, or
//! the ones `--file`, `--uuid` and `--type` select.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::fs::FileSystem;

/// One `--file` target: as given, its file name, and the absolute paths it
/// may mean (none for a bare file name, which matches by name anywhere).
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileTarget {
    raw: String,
    name: String,
    paths: BTreeSet<PathBuf>,
}

/// What a run selects.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope {
    narrow: bool,
    /// Every `--file` target (stripped) and `--uuid`.
    targets: BTreeSet<String>,
    /// `--type`.
    object_types: BTreeSet<String>,
    file_names: BTreeSet<String>,
    file_paths: BTreeSet<PathBuf>,
    file_targets: Vec<FileTarget>,
}

/// `--file`, `--uuid` and `--type`, as given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// `--file`, repeatable.
    pub files: Vec<String>,
    /// `--uuid`, repeatable.
    pub uuids: Vec<String>,
    /// `--type`, repeatable.
    pub types: Vec<String>,
}

impl Selection {
    /// Whether nothing narrows the run.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.uuids.is_empty() && self.types.is_empty()
    }
}

impl Scope {
    /// Every object.
    pub fn full() -> Self {
        Self::default()
    }

    /// The objects `selection` names. A relative `--file` is resolved
    /// against each of `roots` (the workspace and the working directory),
    /// since `--repo` lets the two differ.
    pub fn narrow(fs: &dyn FileSystem, selection: &Selection, roots: &[PathBuf]) -> Self {
        if selection.is_empty() {
            return Self::full();
        }
        let mut scope = Self {
            narrow: true,
            object_types: selection.types.iter().cloned().collect(),
            ..Self::default()
        };
        let files: BTreeSet<&String> = selection.files.iter().collect();
        for raw in files {
            scope.targets.insert(raw.trim().to_owned());
            let (name, paths) = variants(fs, raw, roots);
            if paths.is_empty() {
                scope.file_names.insert(name.clone());
            } else {
                scope.file_paths.extend(paths.iter().cloned());
            }
            scope.file_targets.push(FileTarget {
                raw: raw.clone(),
                name,
                paths,
            });
        }
        scope.targets.extend(selection.uuids.iter().cloned());
        scope
    }

    /// Whether every object is selected.
    pub fn is_full(&self) -> bool {
        !self.narrow
    }

    /// Whether `--file`, `--uuid` or `--type` narrows the run.
    pub fn has_filter(&self) -> bool {
        self.narrow && !(self.targets.is_empty() && self.object_types.is_empty())
    }

    /// Whether `--file` was given.
    pub fn has_file_targets(&self) -> bool {
        !self.file_targets.is_empty()
    }

    /// Whether `--file` or `--uuid` was given.
    pub fn has_targets(&self) -> bool {
        !self.targets.is_empty()
    }

    /// `--file` and `--uuid`, sorted.
    pub fn targets(&self) -> Vec<String> {
        self.targets.iter().cloned().collect()
    }

    /// `--type`, sorted.
    pub fn object_types(&self) -> Vec<String> {
        self.object_types.iter().cloned().collect()
    }

    /// Whether `--type` leaves out `family`.
    pub fn excludes_type(&self, family: &str) -> bool {
        !self.object_types.is_empty() && !self.object_types.contains(family)
    }

    /// Whether a `--file` target selects the file at `path`.
    pub fn matches_file(&self, fs: &dyn FileSystem, path: &Path) -> bool {
        if !self.file_paths.is_empty() && self.file_paths.contains(&fs.resolve(path)) {
            return true;
        }
        file_name(path).is_some_and(|name| self.file_names.contains(&name))
    }

    /// Whether the object `uuid` of `family` in `path` is selected.
    pub fn includes_object(
        &self,
        fs: &dyn FileSystem,
        uuid: &str,
        family: &str,
        path: &Path,
    ) -> bool {
        if !self.narrow {
            return true;
        }
        if self.excludes_type(family) {
            return false;
        }
        if self.targets.is_empty() {
            return !self.object_types.is_empty();
        }
        self.targets.contains(uuid) || self.matches_file(fs, path)
    }

    /// The `--file` targets, as given, that select none of `files`.
    pub fn unmatched_file_targets(&self, fs: &dyn FileSystem, files: &[&Path]) -> Vec<String> {
        self.file_targets
            .iter()
            .filter(|target| {
                !files.iter().any(|path| {
                    if target.paths.is_empty() {
                        file_name(path).as_deref() == Some(target.name.as_str())
                    } else {
                        target.paths.contains(&fs.resolve(path))
                    }
                })
            })
            .map(|target| target.raw.clone())
            .collect()
    }
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// `(file name, absolute candidates)` of a `--file` target; no candidates
/// for a bare file name.
fn variants(fs: &dyn FileSystem, target: &str, roots: &[PathBuf]) -> (String, BTreeSet<PathBuf>) {
    let raw = target.trim();
    let path = Path::new(raw);
    let name = file_name(path).unwrap_or_default();
    if raw.is_empty() || raw == "." || (name == raw && !path.is_absolute()) {
        return (raw.to_owned(), BTreeSet::new());
    }
    if path.is_absolute() {
        return (name, BTreeSet::from([fs.resolve(path)]));
    }
    let paths = roots
        .iter()
        .map(|root| fs.resolve(&root.join(path)))
        .collect();
    (name, paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;

    fn scope(files: &[&str], uuids: &[&str], types: &[&str]) -> Scope {
        let own = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect();
        Scope::narrow(
            &MemoryFs::new(),
            &Selection {
                files: own(files),
                uuids: own(uuids),
                types: own(types),
            },
            &[PathBuf::from("/w")],
        )
    }

    #[test]
    fn nothing_selected_is_the_full_scope() {
        let full = scope(&[], &[], &[]);
        assert!(full.is_full());
        assert!(full.includes_object(&MemoryFs::new(), "u", "rule", Path::new("/w/x.yaml")));
    }

    #[test]
    fn a_bare_name_matches_by_name_and_a_path_only_that_path() {
        let fs = MemoryFs::new();
        let bare = scope(&["x.yaml"], &[], &[]);
        assert!(bare.includes_object(&fs, "u", "rule", Path::new("/w/rules/x.yaml")));
        assert!(bare.includes_object(&fs, "u", "rule", Path::new("/w/other/x.yaml")));
        let path = scope(&["rules/x.yaml"], &[], &[]);
        assert!(path.includes_object(&fs, "u", "rule", Path::new("/w/rules/x.yaml")));
        assert!(!path.includes_object(&fs, "u", "rule", Path::new("/w/rules/team/x.yaml")));
        assert_eq!(
            path.unmatched_file_targets(&fs, &[Path::new("/w/rules/y.yaml")]),
            vec!["rules/x.yaml".to_owned()]
        );
    }

    #[test]
    fn types_and_uuids_combine() {
        let fs = MemoryFs::new();
        let types = scope(&[], &[], &["rule"]);
        assert!(types.includes_object(&fs, "u", "rule", Path::new("/w/a.yaml")));
        assert!(!types.includes_object(&fs, "u", "threat", Path::new("/w/a.yaml")));
        let uuid = scope(&[], &["u"], &["rule"]);
        assert!(uuid.includes_object(&fs, "u", "rule", Path::new("/w/a.yaml")));
        assert!(!uuid.includes_object(&fs, "v", "rule", Path::new("/w/a.yaml")));
        assert!(!uuid.includes_object(&fs, "u", "threat", Path::new("/w/a.yaml")));
        assert_eq!(uuid.targets(), vec!["u".to_owned()]);
    }
}
