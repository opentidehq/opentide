//! The environment a run reads, as a snapshot: tests pass their own.

use std::collections::BTreeMap;

/// Environment variables by name. A value that is not UTF-8 is read lossily.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

impl Env {
    /// This process's environment.
    pub fn from_process() -> Env {
        Env::from_pairs(std::env::vars_os().map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        }))
    }

    /// An environment of exactly these variables.
    pub fn from_pairs<K: Into<String>, V: Into<String>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Env {
        Env {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// The value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// The program search path, `PATH`. Windows names variables in any
    /// case and keeps the one it was given (`Path`), so there the name is
    /// matched whatever its case.
    pub fn search_path(&self) -> Option<&str> {
        self.named(cfg!(windows), "PATH")
    }

    /// The value of `name`, its case ignored when `any_case`.
    fn named(&self, any_case: bool, name: &str) -> Option<&str> {
        if !any_case {
            return self.get(name);
        }
        self.get(name).or_else(|| {
            self.vars
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        })
    }

    /// Every variable, by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// `name` read as a boolean literal (`1`, `true`, `yes`, `on`, their
    /// negatives and the empty string); `None` when unset or anything else,
    /// such as `DEBUG='*'` from Node tooling.
    pub fn boolean(&self, name: &str) -> Option<bool> {
        let value = self.get(name)?.trim().to_lowercase();
        match value.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "" | "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    }

    /// What the colour variables ask for: `Some(false)` to turn colour off,
    /// `Some(true)` to force it, `None` to leave it to the terminal.
    ///
    /// `NO_COLOR` set to anything non-empty (a blank value counts, as at
    /// no-color.org) wins; then `FORCE_COLOR` (`0`, `false`, `no` or `off`
    /// off, any other value on), then `CLICOLOR_FORCE` (any non-empty value
    /// but `0` on). An empty or, for the two force variables, blank value is
    /// the same as unset.
    pub fn colour_choice(&self) -> Option<bool> {
        let set = |name: &str| self.get(name).map(str::trim).filter(|v| !v.is_empty());
        if self.get("NO_COLOR").is_some_and(|value| !value.is_empty()) {
            return Some(false);
        }
        if let Some(value) = set("FORCE_COLOR") {
            return Some(!matches!(
                value.to_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            ));
        }
        set("CLICOLOR_FORCE")
            .filter(|value| *value != "0")
            .map(|_| true)
    }

    /// Whether the environment asks for `--debug`: `OPENTIDE_DEBUG` when it
    /// is a boolean, otherwise `DEBUG` when it is one.
    pub fn debug_requested(&self) -> bool {
        self.boolean("OPENTIDE_DEBUG")
            .or_else(|| self.boolean("DEBUG"))
            .unwrap_or(false)
    }

    /// Whether `OPENTIDE_DEBUG` is the boolean true. A switch that rewrites
    /// files, such as deploy's promotion of every rule file, reads this
    /// and never `DEBUG`: CI systems and tools set `DEBUG` for their own
    /// logging.
    pub fn opentide_debug(&self) -> bool {
        self.boolean("OPENTIDE_DEBUG").unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows keeps the search path as `Path` (#1670 review): matched
    /// whatever its case there, and only as `PATH` elsewhere, where a
    /// `Path` variable is not the search path.
    #[test]
    fn the_search_path_is_found_in_any_case_on_windows() {
        let windows = Env::from_pairs([("Path", "C:\\bin")]);
        assert_eq!(windows.named(true, "PATH"), Some("C:\\bin"));
        assert_eq!(windows.named(false, "PATH"), None);
        assert_eq!(
            windows.search_path(),
            if cfg!(windows) { Some("C:\\bin") } else { None }
        );
        let both = Env::from_pairs([("PATH", "/usr/bin"), ("Path", "/elsewhere")]);
        assert_eq!(both.named(true, "PATH"), Some("/usr/bin"));
        assert_eq!(both.search_path(), Some("/usr/bin"));
    }

    #[test]
    fn framework_colour_choice_follows_no_color_then_force_color_then_clicolor_force() {
        let choice =
            |pairs: &[(&str, &str)]| Env::from_pairs(pairs.iter().copied()).colour_choice();
        assert_eq!(choice(&[]), None);
        assert_eq!(choice(&[("NO_COLOR", "1")]), Some(false));
        assert_eq!(choice(&[("NO_COLOR", "")]), None);
        assert_eq!(choice(&[("NO_COLOR", " ")]), Some(false));
        assert_eq!(choice(&[("FORCE_COLOR", " ")]), None);
        assert_eq!(choice(&[("FORCE_COLOR", "no")]), Some(false));
        assert_eq!(choice(&[("FORCE_COLOR", "OFF")]), Some(false));
        assert_eq!(
            choice(&[("FORCE_COLOR", "1"), ("CLICOLOR_FORCE", "0")]),
            Some(true)
        );
        assert_eq!(choice(&[("FORCE_COLOR", "1")]), Some(true));
        assert_eq!(choice(&[("FORCE_COLOR", "true")]), Some(true));
        assert_eq!(choice(&[("FORCE_COLOR", "3")]), Some(true));
        assert_eq!(choice(&[("FORCE_COLOR", "0")]), Some(false));
        assert_eq!(choice(&[("FORCE_COLOR", "false")]), Some(false));
        assert_eq!(choice(&[("FORCE_COLOR", "")]), None);
        assert_eq!(choice(&[("CLICOLOR_FORCE", "1")]), Some(true));
        assert_eq!(choice(&[("CLICOLOR_FORCE", "0")]), None);
        assert_eq!(choice(&[("CLICOLOR_FORCE", "")]), None);
        // NO_COLOR beats both; FORCE_COLOR beats CLICOLOR_FORCE.
        assert_eq!(
            choice(&[
                ("NO_COLOR", "1"),
                ("FORCE_COLOR", "1"),
                ("CLICOLOR_FORCE", "1")
            ]),
            Some(false)
        );
        assert_eq!(
            choice(&[("FORCE_COLOR", "0"), ("CLICOLOR_FORCE", "1")]),
            Some(false)
        );
    }

    #[test]
    fn framework_debug_reads_opentide_debug_then_a_boolean_debug() {
        let env = |pairs: &[(&str, &str)]| Env::from_pairs(pairs.iter().copied());
        assert!(env(&[("OPENTIDE_DEBUG", "1")]).debug_requested());
        assert!(!env(&[("OPENTIDE_DEBUG", "0"), ("DEBUG", "1")]).debug_requested());
        assert!(env(&[("OPENTIDE_DEBUG", "maybe"), ("DEBUG", "yes")]).debug_requested());
        assert!(!env(&[("DEBUG", "*")]).debug_requested());
        assert!(env(&[("DEBUG", " TRUE ")]).debug_requested());
        assert!(!env(&[]).debug_requested());
        assert!(env(&[("OPENTIDE_DEBUG", "yes")]).opentide_debug());
        assert!(!env(&[("DEBUG", "1")]).opentide_debug());
        assert!(!env(&[("OPENTIDE_DEBUG", "0"), ("DEBUG", "1")]).opentide_debug());
        assert_eq!(env(&[("X", "")]).boolean("X"), Some(false));
        assert!(Env::from_process().iter().count() < usize::MAX);
    }
}
