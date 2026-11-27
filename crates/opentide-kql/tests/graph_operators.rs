//! The graph operators (#1637) through the analysis: their forms are no
//! syntax error, the names in a pattern are not columns, and what follows a
//! graph is an open schema (the columns a graph's nodes carry are not known
//! here: `docs/engine/kql/operators.md`).

use opentide_core::{Severity, codes};
use opentide_kql::{Dialect, Hir, analyze};

fn errors(src: &str) -> Vec<(String, String)> {
    analyze(src, Dialect::Sentinel)
        .diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| (d.code, d.message))
        .collect()
}

#[test]
fn a_graph_query_has_no_error_and_its_pattern_names_are_no_columns() {
    let query = "SigninLogs\n\
        | make-graph UserPrincipalName --> IPAddress with_node_id=id\n\
        | graph-match (u)-[s*1..3]->(i) where u.id == \"x\" and s.Count > 2 project user = u.id, ip = i.id\n\
        | where user != \"\" and anything_at_all > 1";
    assert_eq!(errors(query), Vec::new());
}

#[test]
fn a_syntax_error_in_a_pattern_is_a_parse_error() {
    for query in [
        "SigninLogs | make-graph UserPrincipalName --> IPAddress | graph-match (a)-[e*1..]->(b) project a",
        "SigninLogs | make-graph UserPrincipalName --> IPAddress | graph-match (a)-[e] ->(b) project a",
        "SigninLogs | make-graph UserPrincipalName <-- IPAddress",
    ] {
        let found = errors(query);
        assert!(
            found.iter().any(|(code, _)| code == codes::KQL_PARSE_ERROR),
            "{query}: {found:?}"
        );
    }
}

#[test]
fn the_graph_operators_keep_their_names_in_the_lowered_query() {
    let Hir::Query { operators, .. } = opentide_kql::lower(
        "SigninLogs | make-graph a --> b | graph-match (x)-[e]->(y) project x | graph-shortest-paths (x)-[e*1..2]->(y) | graph-to-table nodes | graph-mark-components",
    ) else {
        panic!("a query");
    };
    let names: Vec<&str> = operators.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "make-graph",
            "graph-match",
            "graph-shortest-paths",
            "graph-to-table",
            "graph-mark-components"
        ]
    );
}
