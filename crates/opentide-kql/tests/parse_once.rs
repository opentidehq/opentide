//! One parse per text (#1230): the tree-sitter engine parsed one query three
//! times in one analysis (`analyze`, `lower`, the highlight query), and again
//! for each hover. The new engine parses a text once and shares the tree
//! among the analysis, the column pass and hover on that text.

use opentide_kql::inspect::parse_count;
use opentide_kql::{Catalog, Dialect, analyze_with_catalog, columns, hover};

#[test]
fn an_analysis_its_columns_and_its_hovers_parse_the_text_once() {
    let query =
        "let t = SigninLogs | where ResultType == 0;\nt | project UserId, IPAddress | take 5";
    let catalog = Catalog::for_workspace(Dialect::Sentinel, query);
    let before = parse_count();
    let analysis = analyze_with_catalog(query, &catalog);
    assert!(!analysis.tokens.is_empty());
    let _ = columns(query, Dialect::Sentinel);
    for offset in [0, 10, 30, 60] {
        let _ = hover(query, offset, Dialect::Sentinel);
    }
    assert_eq!(parse_count() - before, 1, "one parse for the whole text");
    // An edit is a new text: one more parse.
    let edited = format!("{query} | count");
    let _ = analyze_with_catalog(&edited, &catalog);
    let _ = hover(&edited, 5, Dialect::Sentinel);
    assert_eq!(parse_count() - before, 2);
}
