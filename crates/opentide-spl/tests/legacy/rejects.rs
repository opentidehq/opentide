//! Forms the grammar shares with valid ones that Splunk's parser rejects, so
//! they are `spl_parse_error` (a syntax error is what Splunk rejects):
//!
//! - `tstats ... where` with a loose comparison a search accepts (`==`, `<>`,
//!   `=>`, `=<`, `!~`): "WHERE clause is not an exact query"
//!   (opentidehq/language-server#136).
//! - `geostats by x` with no aggregate: "At least one data field must be
//!   specified" (#135). The stats rule reads that `by` as an aggregate.

use opentide_core::{Diagnostic, codes, span_to_range};
use opentide_syntax::node_span;
use tree_sitter::Node;

const LOOSE_OPERATORS: &[&str] = &["==", "<>", "=>", "=<", "!~"];

pub(crate) fn collect(root: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if node.kind() == "tstats_command"
            && let Some(clause) = node.child_by_field_name("where")
        {
            loose_operators(clause, source, out);
        }
        if node.kind() == "stats_command" {
            geostats_by_without_aggregate(node, source, out);
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

fn geostats_by_without_aggregate(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let text = |n: Node| source.get(n.start_byte()..n.end_byte()).unwrap_or("");
    if node.child(0).map(text) != Some("geostats") {
        return;
    }
    let Some(first) = node.child_by_field_name("aggregates") else {
        return;
    };
    if text(first).eq_ignore_ascii_case("by") {
        out.push(Diagnostic::error(
            codes::SPL_PARSE_ERROR,
            "SPL syntax error: `geostats ... by` needs an aggregate before `by` (`geostats count by x`)",
            span_to_range(source, node_span(first)),
        ));
    }
}

/// Every loose comparison in the clause, outside subsearches (their own
/// searches take them).
fn loose_operators(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    if node.kind() == "subsearch" {
        return;
    }
    let operator = (node.kind() == "field_value")
        .then(|| node.child_by_field_name("operator"))
        .flatten()
        .filter(|op| LOOSE_OPERATORS.contains(&op.kind()));
    if let Some(op) = operator {
        let text = op.kind();
        out.push(Diagnostic::error(
            codes::SPL_PARSE_ERROR,
            format!(
                "SPL syntax error: `tstats ... where` does not take '{text}'; Splunk rejects it (WHERE clause is not an exact query)"
            ),
            span_to_range(source, node_span(op)),
        ));
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        loose_operators(child, source, out);
    }
}
