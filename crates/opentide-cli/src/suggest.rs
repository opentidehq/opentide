//! "Did you mean": the valid value closest to a mistyped one.
//!
//! A choice that differs only in case or separators wins outright (`RULE` ->
//! `rule`, `attack_pattern` -> `attack-pattern`), then a name people know a
//! choice by (`--format gitlab` -> `codequality`), then the one choice the
//! value starts (`--platform defender` -> `defender_for_endpoint`). Otherwise
//! the most similar choice by the Jaro similarity of the lower-cased spellings,
//! the measure and the 0.7 cut-off clap's own suggestions use (strsim), so the
//! CLI suggests what clap would.

/// Below this similarity nothing is suggested (clap's threshold).
const THRESHOLD: f64 = 0.7;

/// Folded spellings that name a choice by what it is for.
const ALIASES: &[(&str, &str)] = &[("gitlab", "codequality"), ("codeclimate", "codequality")];

/// `text` without case or separators (space, `-`, `_`).
fn fold(text: &str) -> String {
    text.chars()
        .filter(|c| !(c.is_whitespace() || *c == '-' || *c == '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

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
    let lowered = value.to_lowercase();
    let mut best: Option<(f64, &str)> = None;
    for choice in &options {
        let score = strsim::jaro(&lowered, &choice.to_lowercase());
        if score > THRESHOLD && best.is_none_or(|(top, _)| score > top) {
            best = Some((score, choice));
        }
    }
    best.map(|(_, choice)| choice.to_owned())
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
            dym("defender", &["sentinel", "defender_for_endpoint", "splunk"]).as_deref(),
            Some("defender_for_endpoint")
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
    fn framework_suggest_the_threshold_is_strictly_above_jaro_0_7() {
        // Just above the cut-off: suggested.
        assert!(strsim::jaro("exprt", "extract") > THRESHOLD);
        assert_eq!(dym("exprt", &["extract"]).as_deref(), Some("extract"));
        // Just below: nothing.
        let below = strsim::jaro("ebcdeee", "ced");
        assert!(below < THRESHOLD && below > 0.69, "{below}");
        assert_eq!(dym("ebcdeee", &["ced"]), None);
        // At it exactly (7/10 in exact arithmetic): nothing, as clap.
        let at = strsim::jaro("aaaede", "acabe");
        assert!((at - THRESHOLD).abs() < 1e-9, "{at}");
        assert_eq!(dym("aaaede", &["acabe"]).is_some(), at > THRESHOLD);
    }

    #[test]
    fn framework_suggest_ties_go_to_the_first_choice() {
        assert_eq!(
            strsim::jaro("xab", "xac").to_bits(),
            strsim::jaro("xab", "xad").to_bits()
        );
        assert_eq!(dym("xab", &["xac", "xad"]).as_deref(), Some("xac"));
        assert_eq!(dym("xab", &["xad", "xac"]).as_deref(), Some("xad"));
    }

    #[test]
    fn framework_suggest_a_prefix_needs_three_letters() {
        let long = "abcdefghijklmnopqrstuvwxyz0123";
        // Two letters are no prefix match, and too far by Jaro.
        assert!(strsim::jaro("ab", long) < THRESHOLD);
        assert_eq!(dym("ab", &[long]), None);
        // Three are, when one choice starts with them.
        assert_eq!(dym("abc", &[long]).as_deref(), Some(long));
        // Two start with them: no prefix match, and Jaro picks the nearer.
        assert_eq!(dym("abc", &[long, "abcz"]).as_deref(), Some("abcz"));
    }

    #[test]
    fn framework_suggest_compares_lower_cased_spellings() {
        let commands = ["validate", "query", "lint"];
        assert_eq!(strsim::jaro("VALDIATE", "validate"), 0.0);
        assert_eq!(dym("VALDIATE", &commands).as_deref(), Some("validate"));
        assert_eq!(
            dym("--JSN", &["--json", "--repo"]).as_deref(),
            Some("--json")
        );
    }

    #[test]
    fn framework_suggest_ranks_by_jaro_not_jaro_winkler() {
        // Jaro prefers `cabab`; Jaro-Winkler's prefix bonus would pick `dadcb`.
        assert!(strsim::jaro("dabba", "cabab") > strsim::jaro("dabba", "dadcb"));
        assert!(strsim::jaro_winkler("dabba", "dadcb") > strsim::jaro_winkler("dabba", "cabab"));
        assert_eq!(dym("dabba", &["dadcb", "cabab"]).as_deref(), Some("cabab"));
    }

    #[test]
    fn framework_suggest_never_repeats_the_word_typed() {
        // `opentide -- commands` was refused with "did you mean 'commands'?".
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
