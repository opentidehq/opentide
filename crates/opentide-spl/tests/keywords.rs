//! SPL's `KEYWORDS` table (in `opentide-highlight`) against the lexer: every
//! word of the table lexes as one name, every punctuation token as one token
//! of its own.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_core::LanguageId;
use opentide_spl::syntax::{SyntaxKind, lex};

#[test]
fn every_keyword_lexes_as_one_token() {
    let table = opentide_highlight::keywords(LanguageId::Spl).expect("SPL has a table");
    assert!(table.len() > 80, "{} rows", table.len());
    for (token, _) in table {
        // In a search, where every operator has its own token.
        let source = format!("| search x {token}");
        let lexemes: Vec<_> = lex(&source)
            .into_iter()
            .filter(|l| l.kind != SyntaxKind::WHITESPACE.raw())
            .collect();
        let last = lexemes.last().expect("a token");
        assert_eq!(
            &source[std::ops::Range::<usize>::from(last.range)],
            *token,
            "`{token}` is not one token: {lexemes:?}"
        );
    }
}
