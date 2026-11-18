//! A node's range without trivia, found from its ends inward
//! (`syntax_util::range`), is the range walking every token of the node
//! gives, for every node of every KQL file under `crates/testdata` and of
//! broken and trivia-heavy queries (#1571). Reading the files is this test's,
//! not the library's: engine crates do no I/O.

#![expect(
    clippy::expect_used,
    reason = "a test: a corpus it cannot read stops it"
)]

use opentide_kql::inspect::ranges_disagree;

fn sources() -> Vec<String> {
    let mut out: Vec<String> = [
        "",
        "   ",
        "// only a comment",
        "T | where a == 1 // trailing comment\n",
        "  T\n| where (  a == 1 /* c */ )  \n| project b , c ",
        "let x = (\n  // c\n);\nT",
        "T | where",
        "T | join ( U | where x == 1 ) on a",
        "T | summarize count() by bin(TimeGenerated, 1h) // x",
        "SecurityEvent | union\n",
        "// c\n/* unterminated\n",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let mut dirs = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read testdata").flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "kql") {
                out.push(std::fs::read_to_string(&path).expect("read a .kql file"));
            }
        }
    }
    out
}

#[test]
fn range_from_the_ends_is_range_by_walking() {
    let mut nodes = 0;
    for source in sources() {
        let (count, differ) = ranges_disagree(&source);
        assert!(differ.is_empty(), "{differ:?} in {source:?}");
        nodes += count;
    }
    assert!(nodes > 5_000, "{nodes} nodes");
}
