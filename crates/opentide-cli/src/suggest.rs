//! "Did you mean": the valid value closest to a mistyped one.
//!
//! A choice that differs only in case or separators wins outright (`RULE` ->
//! `rule`, `attack_pattern` -> `attack-pattern`), then a name people know a
//! choice by (`--format gitlab` -> `codequality`), then the one choice the
//! value starts (`--platform microsoft` -> `microsoft_defender`). Otherwise
//! the shared rule every other suggestion follows ([`opentide_core::suggest`]:
//! the fewest edits, at most a third of the length), so the command line, the
//! editor and `validate` suggest the same word for the same typo. A mistyped
//! command or option is clap's to suggest (`crate::usage`); a value clap
//! checks gets this rule where clap's own match finds nothing.

use opentide_core::suggest::{self, fold};

/// Folded spellings that name a choice by what it is for.
const ALIASES: &[(&str, &str)] = &[("gitlab", "codequality"), ("codeclimate", "codequality")];

/// The valid choice closest to `value`, or `None` when nothing is close, or
/// when the closest is `value` itself (a valid word reported for another
/// reason: suggesting it again helps nobody).
pub fn did_you_mean<'a, I>(value: &str, choices: I) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    closest(value, choices).filter(|choice| choice != value)
}

fn closest<'a, I>(value: &str, choices: I) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut options: Vec<&str> = Vec::new();
    for choice in choices {
        if !options.contains(&choice) {
            options.push(choice);
        }
    }
    let folded = fold(value);
    if !folded.is_empty()
        && let Some(choice) = options.iter().find(|choice| fold(choice) == folded)
    {
        return Some((*choice).to_owned());
    }
    if let Some((_, alias)) = ALIASES.iter().find(|(name, _)| *name == folded)
        && options.contains(alias)
    {
        return Some((*alias).to_owned());
    }
    if folded.chars().count() >= 3 {
        let started: Vec<&&str> = options
            .iter()
            .filter(|choice| fold(choice).starts_with(&folded))
            .collect();
        if let [only] = started.as_slice() {
            return Some((**only).to_owned());
        }
    }
    suggest::closest(value, options).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dym(value: &str, choices: &[&str]) -> Option<String> {
        did_you_mean(value, choices.iter().copied())
    }

    #[test]
    fn framework_suggest_case_and_separators_win_outright() {
        assert_eq!(dym("RULE", &["rules", "rule"]).as_deref(), Some("rule"));
        assert_eq!(
            dym("attack_pattern", &["attack-patterns", "attack-pattern"]).as_deref(),
            Some("attack-pattern")
        );
    }

    #[test]
    fn framework_suggest_aliases_and_unique_prefixes() {
        assert_eq!(
            dym("gitlab", &["text", "sarif", "codequality"]).as_deref(),
            Some("codequality")
        );
        assert_eq!(dym("gitlab", &["text"]), None);
        assert_eq!(
            dym("microsoft", &["sentinel", "microsoft_defender", "splunk"]).as_deref(),
            Some("microsoft_defender")
        );
    }

    #[test]
    fn framework_suggest_typos_get_the_closest_value() {
        let commands = ["validate", "query", "lint", "info", "new", "generate"];
        assert_eq!(dym("valdiate", &commands).as_deref(), Some("validate"));
        assert_eq!(
            dym("--jsn", &["--repo", "--json", "--debug"]).as_deref(),
            Some("--json")
        );
        assert_eq!(
            dym("--strictt", &["--check", "--strict", "--fix"]).as_deref(),
            Some("--strict")
        );
        assert_eq!(
            dym(
                "filenamez",
                &["filenames", "metadata", "placeholders", "queries"]
            )
            .as_deref(),
            Some("filenames")
        );
        assert_eq!(
            dym("sentinal", &["sentinel", "splunk", "elastic"]).as_deref(),
            Some("sentinel")
        );
        assert_eq!(
            dym("rulez", &["rules", "threats", "objectives"]).as_deref(),
            Some("rules")
        );
    }

    #[test]
    fn framework_suggest_at_most_a_third_of_the_length_in_edits() {
        // Five letters: one edit is close enough.
        assert_eq!(dym("exprt", &["export"]).as_deref(), Some("export"));
        // Three edits are not.
        assert_eq!(dym("exprt", &["extract"]), None);
        // Nine letters: three edits.
        assert_eq!(dym("valdiatex", &["validate"]).as_deref(), Some("validate"));
        assert_eq!(dym("vaxxxxate", &["validate"]), None);
    }

    #[test]
    fn framework_suggest_ties_never_depend_on_the_order() {
        // Equally close: the one that sorts first, whatever the order given.
        assert_eq!(dym("xab", &["xac", "xad"]).as_deref(), Some("xac"));
        assert_eq!(dym("xab", &["xad", "xac"]).as_deref(), Some("xac"));
    }

    #[test]
    fn framework_suggest_a_prefix_needs_three_letters() {
        let long = "abcdefghijklmnopqrstuvwxyz0123";
        // Two letters are no prefix match, and too many edits away.
        assert_eq!(dym("ab", &[long]), None);
        // Three are, when one choice starts with them.
        assert_eq!(dym("abc", &[long]).as_deref(), Some(long));
        // Two start with them: no prefix match, and the fewest edits win.
        assert_eq!(dym("abc", &[long, "abcz"]).as_deref(), Some("abcz"));
    }

    #[test]
    fn framework_suggest_compares_lower_cased_spellings() {
        let commands = ["validate", "query", "lint"];
        assert_eq!(dym("VALDIATE", &commands).as_deref(), Some("validate"));
        assert_eq!(
            dym("--JSN", &["--json", "--repo"]).as_deref(),
            Some("--json")
        );
    }

    #[test]
    fn framework_suggest_ranks_by_fewest_edits() {
        // A swapped pair is one edit; two letters cut are two.
        assert_eq!(
            dym("valdiate", &["validates", "validate"]).as_deref(),
            Some("validate")
        );
        assert_eq!(
            dym("sentinal", &["sentinel_one", "sentinel"]).as_deref(),
            Some("sentinel")
        );
    }

    #[test]
    fn framework_suggest_never_repeats_the_word_typed() {
        assert_eq!(dym("commands", &["commands", "validate"]), None);
        assert_eq!(dym("query", &["query"]), None);
        // A different spelling of a valid word is still suggested.
        assert_eq!(dym("Query", &["query"]).as_deref(), Some("query"));
    }

    #[test]
    fn framework_suggest_nothing_when_nothing_is_close() {
        assert_eq!(dym("zzzz", &["validate", "query"]), None);
        assert_eq!(dym("", &["validate"]), None);
        assert_eq!(dym("x", &[]), None);
    }
}
