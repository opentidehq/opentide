//! The `KEYWORDS` table of KQL (`opentide_highlight::keywords`) and the
//! lexer know the same tokens: the generated TextMate grammar colours what
//! the lexer reads as a keyword or an operator, and nothing it reads as a name.

use opentide_core::LanguageId;
use opentide_kql::inspect::token_kinds;

/// Every token of the table lexes as one token that is not a name and not an
/// error, after a pipe (where a hyphen keyword starts an operator).
#[test]
fn every_keyword_of_the_table_is_one_token_of_the_lexer() {
    let table = opentide_highlight::keywords(LanguageId::Kql).expect("a KQL table");
    assert!(table.len() > 140, "{} rows", table.len());
    for (token, capture) in table {
        let kinds = token_kinds(&format!("| {token}"));
        assert_eq!(
            kinds.len(),
            2,
            "`{token}` ({}) lexes as {kinds:?}",
            capture.name()
        );
        assert_ne!(kinds[1], "IDENT", "`{token}` lexes as a name");
        assert_ne!(kinds[1], "ERROR_TOKEN", "`{token}` lexes as an error");
    }
}
