//! The file stem an object's name gives (`core/lint_config.py`
//! `expected_stem`, `documentation/markdown/links.py` `slugify`,
//! `registry/catalogue.py` `split_object_name`).

use std::path::{Path, PathBuf};

use opentide_schema::configuration::lint::FilenameConfig;

use crate::discover::{DEBUG_SUFFIXES, OBJECT_SUFFIXES};

/// What a stem keeps of a name under `slug`: ASCII letters and digits, every
/// other run as one `-`, lower case; `object` when nothing is left.
pub fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut dash = false;
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash {
            slug.push('-');
            dash = true;
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "object".to_owned()
    } else {
        device_safe(slug)
    }
}

/// Whether Windows takes `stem` for a device, not a file: its base (up to
/// the first `.`, trimmed of spaces) is `CON`, `PRN`, `AUX`, `NUL`,
/// `CONIN$`, `CONOUT$`, or `COM` or `LPT` and one digit (`0`-`9`, or the
/// superscripts `¹` `²` `³` Windows also reserves), in any case. `con.yaml`
/// or `con.md` cannot be made there, nor checked out. `COM0` and `LPT0` are
/// on Microsoft's list though older Windows accepts them: a `_` costs
/// nothing.
pub fn is_windows_device(stem: &str) -> bool {
    let base = stem.split('.').next().unwrap_or_default().trim();
    let upper = base.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|digit| {
            let mut chars = digit.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
}

/// `stem`, or `_` and `stem` when it names a Windows device
/// ([`is_windows_device`]): every file name opentide derives from an
/// object's name goes through it (`new`, `generate docs`, the importers).
pub fn device_safe(stem: &str) -> String {
    if is_windows_device(stem) {
        format!("_{stem}")
    } else {
        stem.to_owned()
    }
}

/// What a file name cannot hold on Windows or Unix (`safe_file_name`).
const FORBIDDEN: [char; 9] = ['>', '<', ':', '"', '\\', '/', '|', '?', '*'];

/// The stem `style` asks for an object called `name`: `slug` is
/// [`slugify`]; `name` is the name less what a file name cannot hold,
/// control characters, the spaces and dots around it (Windows drops a
/// trailing one, a leading dot hides the file) and a trailing `.debug`
/// (which would make the file debug output). `None` for `none`, or when
/// nothing of the name is left.
pub fn expected_stem(name: &str, style: &str) -> Option<String> {
    match style {
        "none" => None,
        "slug" => Some(slugify(name)),
        _ => {
            let cleaned: String = name
                .chars()
                .filter(|c| !FORBIDDEN.contains(c) && !matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'))
                .collect();
            let mut stem = cleaned.trim_matches([' ', '.']);
            while let Some(rest) = stem.strip_suffix(".debug") {
                stem = rest.trim_matches([' ', '.']);
            }
            (!stem.is_empty()).then(|| device_safe(stem))
        }
    }
}

/// An object file name split into the stem its name names and the suffix
/// it keeps: `x.debug.yaml` is `("x", ".debug.yaml")`, so a rename keeps a
/// debug file a debug file.
pub fn split_object_name(name: &str) -> (String, String) {
    for suffix in DEBUG_SUFFIXES.iter().chain(&OBJECT_SUFFIXES) {
        if let Some(stem) = name.strip_suffix(suffix) {
            return (stem.to_owned(), (*suffix).to_owned());
        }
    }
    let path = Path::new(name);
    (
        path.file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path.extension()
            .map(|ext| format!(".{}", ext.to_string_lossy()))
            .unwrap_or_default(),
    )
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The stem of the object file `path`, without its `.debug` infix.
pub fn object_stem(path: &Path) -> String {
    split_object_name(&name_of(path)).0
}

/// `path` renamed to `stem`, keeping its suffix (`.debug.yaml` included).
pub fn with_object_stem(path: &Path, stem: &str) -> PathBuf {
    let (_, suffix) = split_object_name(&name_of(path));
    path.with_file_name(format!("{stem}{suffix}"))
}

/// Whether `path` is debug output.
pub(super) fn is_debug_path(path: &Path) -> bool {
    let name = name_of(path);
    DEBUG_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// The convention of objects of `kind` (`threats`, `objectives`, `rules`).
pub(super) fn for_kind<'c>(config: &'c FilenameConfig, kind: Option<&str>) -> &'c FilenameConfig {
    kind.and_then(|kind| {
        config
            .kinds
            .iter()
            .find(|(name, _)| name == kind)
            .map(|(_, own)| own)
    })
    .unwrap_or(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_keeps_ascii_letters_and_digits() {
        assert_eq!(slugify("Sentinel KQL Rule"), "sentinel-kql-rule");
        assert_eq!(slugify("  --Été 2026!--  "), "t-2026");
        assert_eq!(slugify("!!!"), "object");
        assert_eq!(slugify("a__b"), "a-b");
    }

    #[test]
    fn a_name_stem_drops_what_a_file_name_cannot_hold() {
        assert_eq!(expected_stem("A: rule?", "name").as_deref(), Some("A rule"));
        assert_eq!(expected_stem(" .x. ", "name").as_deref(), Some("x"));
        assert_eq!(expected_stem("B.debug", "name").as_deref(), Some("B"));
        assert_eq!(
            expected_stem("B.debug .debug", "name").as_deref(),
            Some("B")
        );
        assert_eq!(expected_stem("a\u{7}b", "name").as_deref(), Some("ab"));
        assert_eq!(expected_stem("...", "name"), None);
        assert_eq!(expected_stem("x", "none"), None);
        assert_eq!(expected_stem("X y", "slug").as_deref(), Some("x-y"));
    }

    #[test]
    fn a_windows_device_name_gets_an_underscore() {
        for name in [
            "CON", "PRN", "AUX", "NUL", "COM1", "LPT1", "con", "Con", "nUl", "com9", "lpt5",
        ] {
            let lower = name.to_ascii_lowercase();
            assert_eq!(slugify(name), format!("_{lower}"), "{name}");
            assert_eq!(
                expected_stem(name, "name").as_deref(),
                Some(format!("_{name}").as_str()),
                "{name}"
            );
        }
        // An extension does not make it a file to Windows.
        assert_eq!(
            expected_stem("con.txt", "name").as_deref(),
            Some("_con.txt")
        );
        assert_eq!(expected_stem("NUL .x", "name").as_deref(), Some("_NUL .x"));
        // Not devices: a slug joins the parts, and these are other names.
        assert_eq!(slugify("con.txt"), "con-txt");
        for name in ["COM¹", "lpt³", "CONIN$", "conout$", "COM0", "LPT0"] {
            assert_eq!(
                expected_stem(name, "name").as_deref(),
                Some(format!("_{name}").as_str()),
                "{name}"
            );
        }
        assert_eq!(expected_stem("lpt².x", "name").as_deref(), Some("_lpt².x"));
        for name in ["COM10", "COM⁴", "CONSOLE", "CONIN", "LPT", "conn", "a con"] {
            assert!(!is_windows_device(&slugify(name)), "{name}");
            assert_eq!(expected_stem(name, "name").as_deref(), Some(name), "{name}");
        }
    }

    #[test]
    fn a_debug_suffix_stays_with_the_file() {
        assert_eq!(
            split_object_name("x.debug.yaml"),
            ("x".to_owned(), ".debug.yaml".to_owned())
        );
        assert_eq!(
            split_object_name("x.yml"),
            ("x".to_owned(), ".yml".to_owned())
        );
        assert_eq!(
            split_object_name("x.json"),
            ("x".to_owned(), ".json".to_owned())
        );
        assert_eq!(
            with_object_stem(Path::new("/w/x.debug.yaml"), "B"),
            PathBuf::from("/w/B.debug.yaml")
        );
        assert_eq!(object_stem(Path::new("/w/x.debug.yml")), "x");
        assert!(is_debug_path(Path::new("/w/x.debug.yml")));
        assert!(!is_debug_path(Path::new("/w/x.yml")));
    }
}
