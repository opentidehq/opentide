//! The lexer over every `.kql` of `crates/testdata`: lossless.

use opentide_kql::inspect::lex_spans;
mod common;
use common::corpus;

/// Every byte of every corpus file, and of prefixes of it, is in one
/// lexeme (the lexer is lossless).
#[test]
fn lexing_is_lossless_over_the_corpus() {
    let files = corpus();
    assert!(files.len() > 150, "{} files", files.len());
    for path in files {
        let source = std::fs::read_to_string(&path).expect("corpus file");
        for cut in (0..=source.len()).filter(|i| source.is_char_boundary(*i)) {
            if cut % 7 != 0 && cut != source.len() {
                continue;
            }
            let text = &source[..cut];
            let mut end = 0;
            for (start, stop, _) in lex_spans(text) {
                assert_eq!(start, end, "{} cut at {cut}", path.display());
                end = stop;
            }
            assert_eq!(end, text.len(), "{} cut at {cut}", path.display());
        }
    }
}
