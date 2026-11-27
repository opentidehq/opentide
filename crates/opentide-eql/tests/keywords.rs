//! The lexer against the `KEYWORDS` table (`opentide_highlight::keywords`): each token of the
//! table is a token of the lexer, and the lexer cuts no other fixed token (an operator, a
//! bracket, a delimiter) the table lacks.

use opentide_eql::{lexer, syntax};

use opentide_core::LanguageId;
use opentide_highlight::keywords;
use syntax::SyntaxKind as K;

/// The kind and text of every lexeme of `source`.
fn lexemes(source: &str) -> Vec<(K, &str)> {
    lexer::lex(source)
        .iter()
        .map(|l| {
            let range = std::ops::Range::<usize>::from(l.range);
            (K::from_raw(l.kind), &source[range])
        })
        .collect()
}

#[test]
fn every_table_token_is_a_token_of_the_lexer() {
    let table = keywords(LanguageId::Eql).expect("eql has a KEYWORDS table");
    for (token, _) in table {
        let source = format!("x {token} y");
        assert!(
            lexemes(&source).iter().any(|(_, text)| text == token),
            "`{token}` is not a lexeme of `{source}`: {:?}",
            lexemes(&source)
        );
    }
}

#[test]
fn the_lexer_cuts_no_fixed_token_the_table_lacks() {
    let table = keywords(LanguageId::Eql).expect("eql has a KEYWORDS table");
    // Every fixed token of the lexer. `?` and `![` are nodes of the tree for the highlighter
    // (`optional_marker`, `missing_event_open`), so they are not in the table.
    let source = "a | = == != < <= > >= + - * / % ( ) [ ] , . : b[0] ![ ?";
    for (kind, text) in lexemes(source) {
        let word = matches!(
            kind,
            K::WHITESPACE | K::WORD | K::NUMBER_TOKEN | K::INDEX_TOKEN | K::ERROR_TOKEN
        );
        let node = matches!(kind, K::QUESTION | K::BANG_L_BRACK);
        assert!(
            word || node || table.iter().any(|(token, _)| *token == text),
            "`{text}` ({kind:?}) is not in the table"
        );
    }
}
