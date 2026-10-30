//! Forms Splunk's parser accepts that are still mistakes in a detection
//! (opentidehq/language-server#135). `spl_parse_error` means Splunk rejects
//! the query; these get their own codes, checked against Splunk 10.6.1:
//!
//! - `spl_empty_command`: a command with no arguments. `where`, `search`,
//!   `fields`, `eventstats`, `streamstats`, `sistats` and `lookup` do nothing
//!   useful (warning); `stats` returns no results and `inputlookup` fails at
//!   run time (error).
//! - `spl_empty_stage`: a trailing `|`, which Splunk ignores (warning).
//! - `spl_command_without_pipe`: the query starts with a command name and no
//!   `|`, so Splunk searches for the words (error, fixed by adding the pipe).

use super::Catalog;
use opentide_core::{Diagnostic, codes, span_to_range};
use opentide_syntax::node_span;
use tree_sitter::Node;

/// A command word followed by at most this many search terms is not
/// reported: a short search may really look for the word (`delete user`).
const MAX_TERMS_AFTER_A_WORD: usize = 1;

pub(crate) fn collect(root: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let mut cursor = root.walk();
    let Some(pipeline) = root
        .named_children(&mut cursor)
        .find(|n| n.kind() == "pipeline")
    else {
        return;
    };
    command_without_pipe(pipeline, source, catalog, out);
    if !root.has_error() {
        empty_stage(pipeline, source, out);
    }
    empty_commands(root, source, out);
}

/// What an argumentless command does, or `None` when it has arguments or
/// none are needed (`head`, `spath`, `fillnull`, `tojson` have defaults).
fn empty_command(node: Node, source: &str) -> Option<(&'static str, bool)> {
    let has = |field: &str| node.child_by_field_name(field).is_some();
    let empty = match node.kind() {
        "where_command" => !has("predicate"),
        "search_command" => !has("clause"),
        "fields_command" => !has("fields"),
        "lookup_command" | "inputlookup_command" => !has("table"),
        // chart, timechart and geostats share the rule; Splunk rejects the
        // first two empty and geostats has defaults.
        "stats_command" => {
            !has("aggregates")
                && matches!(
                    keyword(node, source),
                    "stats" | "eventstats" | "streamstats" | "sistats"
                )
        }
        _ => false,
    };
    if !empty {
        return None;
    }
    Some(match keyword(node, source) {
        "stats" => ("returns no results", true),
        "inputlookup" => ("fails at run time: Splunk needs a lookup table", true),
        "sistats" => ("computes nothing to summarize", false),
        _ => ("does nothing", false),
    })
}

fn keyword<'s>(node: Node, source: &'s str) -> &'s str {
    node.child(0)
        .and_then(|k| source.get(k.start_byte()..k.end_byte()))
        .unwrap_or("")
}

fn empty_commands(root: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if let Some((what, error)) = empty_command(node, source) {
            // Error recovery can leave a command without its arguments; the
            // syntax error is the finding there.
            if !in_broken_pipeline(node) {
                let name = keyword(node, source);
                let range = span_to_range(source, node_span(node));
                let message = format!("`{name}` with no arguments {what}");
                out.push(if error {
                    Diagnostic::error(codes::SPL_EMPTY_COMMAND, message, range)
                } else {
                    Diagnostic::warning(codes::SPL_EMPTY_COMMAND, message, range)
                });
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// Inside an `ERROR`, or in a pipeline with a syntax error. Recovery puts
/// the rest of a broken stage next to the pipeline, so the pipeline's parent
/// (the query or the subsearch) is the one asked.
fn in_broken_pipeline(node: Node) -> bool {
    let mut at = node.parent();
    while let Some(parent) = at {
        if parent.is_error() {
            return true;
        }
        if parent.kind() == "pipeline" {
            return parent.parent().unwrap_or(parent).has_error();
        }
        at = parent.parent();
    }
    false
}

/// `... | stats count |`: the query's last token is a `|`.
fn empty_stage(pipeline: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let Some(last) = pipeline.child(pipeline.child_count().saturating_sub(1)) else {
        return;
    };
    // A lone `|` is the leading pipe of an empty query, not a trailing stage.
    if last.kind() != "|" || last.is_missing() || pipeline.child_count() < 2 {
        return;
    }
    out.push(Diagnostic::warning(
        codes::SPL_EMPTY_STAGE,
        "empty pipeline stage: Splunk ignores a trailing `|`; remove it or add the command",
        span_to_range(source, node_span(last)),
    ));
}

/// `tstats count where index=a by sourcetype`: with no `|`, Splunk runs
/// `search tstats count ...` and returns nothing.
fn command_without_pipe(
    pipeline: Node,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    let mut cursor = pipeline.walk();
    let Some(search) = pipeline
        .children(&mut cursor)
        .find(|n| !n.is_extra())
        .filter(|n| n.kind() == "bare_search")
    else {
        return;
    };
    if search.has_error() {
        return;
    }
    let Some(first) = search.child_by_field_name("first") else {
        return;
    };
    let word = match first.named_child(0) {
        Some(w) if first.kind() == "search_term" && w.kind() == "identifier" => w,
        _ => return,
    };
    let Some(name) = source.get(word.start_byte()..word.end_byte()) else {
        return;
    };
    if name.eq_ignore_ascii_case("search") || catalog.command(name).is_none() {
        return;
    }
    let mut cursor = search.walk();
    let terms_after = search
        .named_children(&mut cursor)
        .filter(|n| n.kind() == "search_term" && n.id() != first.id())
        .count();
    if terms_after <= MAX_TERMS_AFTER_A_WORD {
        return;
    }
    out.push(
        Diagnostic::error(
            codes::SPL_COMMAND_WITHOUT_PIPE,
            format!(
                "the search starts with the command name `{name}` but no `|`; Splunk searches for the word `{name}` instead of running the command"
            ),
            span_to_range(source, node_span(word)),
        )
        .with_suggestion(format!("| {name}")),
    );
}

#[cfg(test)]
mod tests {
    use crate::analyze;
    use opentide_core::{Diagnostic, Severity, codes};

    fn with_code(src: &str, code: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == code)
            .collect()
    }

    fn only(src: &str, code: &str) -> Diagnostic {
        let found = with_code(src, code);
        assert_eq!(found.len(), 1, "{src}: {found:?}");
        let all = analyze(src).diagnostics;
        assert!(
            !all.iter().any(|d| d.code == codes::SPL_PARSE_ERROR),
            "{src}: {all:?}"
        );
        found.into_iter().next().unwrap()
    }

    #[test]
    fn no_op_commands_warn() {
        for (src, name) in [
            ("index=a | where", "where"),
            ("index=a | search", "search"),
            ("index=a | fields", "fields"),
            ("index=a | fields -", "fields"),
            ("index=a | eventstats", "eventstats"),
            ("index=a | streamstats", "streamstats"),
            ("index=a | sistats", "sistats"),
            ("index=a | lookup", "lookup"),
            ("index=a | where | stats count", "where"),
            ("index=a [search b | where] | stats count", "where"),
        ] {
            let d = only(src, codes::SPL_EMPTY_COMMAND);
            assert_eq!(d.severity, Severity::Warning, "{src}");
            assert!(
                d.message
                    .starts_with(&format!("`{name}` with no arguments")),
                "{d:?}"
            );
        }
    }

    #[test]
    fn empty_stats_and_inputlookup_are_errors() {
        let d = only("index=a | stats", codes::SPL_EMPTY_COMMAND);
        assert_eq!(d.severity, Severity::Error);
        assert!(d.message.contains("returns no results"), "{d:?}");
        for src in ["| inputlookup", "index=a [| inputlookup]"] {
            let d = only(src, codes::SPL_EMPTY_COMMAND);
            assert_eq!(d.severity, Severity::Error, "{src}");
            assert!(d.message.contains("lookup table"), "{d:?}");
        }
    }

    #[test]
    fn commands_with_defaults_or_arguments_are_not_empty() {
        for src in [
            "index=a | head",
            "index=a | spath",
            "index=a | fillnull",
            "index=a | tojson",
            "index=a | geostats latfield=lat longfield=lon",
            "index=a | where x=1 | search b | fields a | stats count | lookup t a",
            "| inputlookup t.csv",
            "search a",
        ] {
            assert!(with_code(src, codes::SPL_EMPTY_COMMAND).is_empty(), "{src}");
        }
    }

    #[test]
    fn syntax_errors_are_not_empty_commands() {
        for src in [
            "index=a | where (x=1",
            "index=a | lookup local=t",
            "| makeresults | inputlookup",
        ] {
            assert!(with_code(src, codes::SPL_EMPTY_COMMAND).is_empty(), "{src}");
            assert!(!with_code(src, codes::SPL_PARSE_ERROR).is_empty(), "{src}");
        }
    }

    #[test]
    fn trailing_pipe_warns_and_an_empty_middle_stage_is_an_error() {
        let d = only("index=a | stats count |", codes::SPL_EMPTY_STAGE);
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!((d.range.start.character, d.range.end.character), (22, 23));
        let d = only("search |", codes::SPL_EMPTY_STAGE);
        assert_eq!(d.severity, Severity::Warning);
        assert!(!with_code("index=a | | stats count", codes::SPL_PARSE_ERROR).is_empty());
        assert!(with_code("index=a | | stats count", codes::SPL_EMPTY_STAGE).is_empty());
        // Splunk rejects an empty last stage in a subsearch.
        assert!(!with_code("index=a [search b |]", codes::SPL_PARSE_ERROR).is_empty());
        assert!(with_code("index=a | stats count", codes::SPL_EMPTY_STAGE).is_empty());
    }

    #[test]
    fn command_word_without_pipe_is_an_error_with_a_fix() {
        let src = "tstats count where index=a by sourcetype";
        let d = only(src, codes::SPL_COMMAND_WITHOUT_PIPE);
        assert_eq!(d.severity, Severity::Error);
        assert_eq!((d.range.start.character, d.range.end.character), (0, 6));
        assert_eq!(d.suggestion.as_deref(), Some("| tstats"));
        assert!(d.message.contains("`tstats`"), "{d:?}");
        assert!(with_code(src, codes::SPL_UNKNOWN_COMMAND).is_empty());
        for src in [
            "stats count by host",
            "```note```\nlookup t.csv a OUTPUT b",
            "TSTATS count where index=a",
        ] {
            only(src, codes::SPL_COMMAND_WITHOUT_PIPE);
        }
    }

    #[test]
    fn searches_that_look_for_words_are_not_commands_without_pipe() {
        for src in [
            "index=a",
            "search foo",
            "search foo bar baz",
            "error",
            "tstats",
            "delete user",
            "error code failed",
            "index=a tstats count where x",
            "| tstats count where index=a by sourcetype",
            "`m` stats count by x",
        ] {
            assert!(
                with_code(src, codes::SPL_COMMAND_WITHOUT_PIPE).is_empty(),
                "{src}: {:?}",
                analyze(src).diagnostics
            );
            assert!(with_code(src, codes::SPL_PARSE_ERROR).is_empty(), "{src}");
        }
    }
}
