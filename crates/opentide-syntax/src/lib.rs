//! Tree-sitter language bindings. Parser C is vendored; do not hand-edit `parser.c`.

use opentide_core::{ByteSpan, LanguageId};
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator, Tree};

unsafe extern "C" {
    fn tree_sitter_opentide_kql() -> *const ();
    fn tree_sitter_opentide_spl() -> *const ();
}

fn from_raw(ptr: *const ()) -> Language {
    // tree-sitter 0.25: Language::new(LanguageFn)
    unsafe { Language::from_raw(ptr as usize as *const tree_sitter::ffi::TSLanguage) }
}

pub fn language(id: LanguageId) -> Option<Language> {
    match id {
        LanguageId::Kql => Some(kql_language()),
        LanguageId::Spl => Some(spl_language()),
        LanguageId::TideYaml => None,
    }
}

pub fn kql_language() -> Language {
    unsafe { from_raw(tree_sitter_opentide_kql()) }
}

pub fn spl_language() -> Language {
    unsafe { from_raw(tree_sitter_opentide_spl()) }
}

pub fn parse(id: LanguageId, source: &str) -> Option<Tree> {
    let language = language(id)?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

pub fn has_error(tree: &Tree) -> bool {
    tree.root_node().has_error()
}

/// Run a highlights.scm query. First capture wins for an identical span so
/// specific patterns listed before `(identifier) @variable` take precedence.
pub fn query_captures(
    id: LanguageId,
    source: &str,
    scm: &str,
) -> Result<Vec<(ByteSpan, String)>, String> {
    let language = language(id).ok_or_else(|| format!("no tree-sitter grammar for {id}"))?;
    let query = Query::new(&language, scm).map_err(|e| e.to_string())?;
    let mut parser = Parser::new();
    parser.set_language(&language).map_err(|e| e.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "parse failed".to_string())?;
    let mut cursor = QueryCursor::new();
    // `captures` is the highlighting iterator: earliest start wins, then
    // earliest pattern in the .scm file. Nested overlapping spans are
    // resolved below so LSP semantic tokens never overlap.
    let mut captures = cursor.captures(&query, tree.root_node(), source.as_bytes());
    let mut first_wins: Vec<(ByteSpan, String)> = Vec::new();
    while let Some((m, cap_index)) = captures.next() {
        let cap = m.captures[*cap_index];
        let name = query.capture_names()[cap.index as usize];
        let start = cap.node.start_byte();
        let end = cap.node.end_byte();
        if start >= end {
            continue;
        }
        first_wins.push((ByteSpan::new(start, end), name.to_string()));
    }
    first_wins.sort_by_key(|(span, _)| (span.start, span.end.saturating_sub(span.start)));
    let mut resolved: Vec<(ByteSpan, String)> = Vec::new();
    let mut last_end = 0usize;
    for (span, name) in first_wins {
        if span.start < last_end {
            continue;
        }
        last_end = span.end;
        resolved.push((span, name));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kql_pipeline() {
        let tree = parse(
            LanguageId::Kql,
            "SecurityEvent | where EventID == 4688 | take 1",
        )
        .expect("parse");
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
    }

    #[test]
    fn parses_kql_let() {
        let tree = parse(LanguageId::Kql, "let x = 1; DeviceProcessEvents | take 1").unwrap();
        assert!(!has_error(&tree));
        let sexp = tree.root_node().to_sexp();
        assert!(sexp.contains("let_statement"));
    }

    #[test]
    fn parses_kql_control_command() {
        let tree = parse(LanguageId::Kql, ".show tables").unwrap();
        assert!(tree.root_node().to_sexp().contains("control_command"));
    }

    #[test]
    fn parses_spl_bare_search() {
        let tree = parse(LanguageId::Spl, "index=main | head 1").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
        assert!(tree.root_node().to_sexp().contains("bare_search"));
    }

    #[test]
    fn parses_spl_unknown_command() {
        let tree = parse(LanguageId::Spl, "index=main | bogus foo=bar | head 1").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
        assert!(tree.root_node().to_sexp().contains("unknown_command"));
    }

    #[test]
    fn query_captures_first_wins_keywords() {
        let src = "SecurityEvent | where EventID == 1 | take 1";
        let caps = query_captures(
            LanguageId::Kql,
            src,
            include_str!("../../../highlights/queries/kql/highlights.scm"),
        )
        .expect("query");
        let keywords: Vec<_> = caps
            .iter()
            .filter(|(_, c)| c == "keyword")
            .map(|(span, _)| src[span.start..span.end].to_string())
            .collect();
        assert!(keywords.iter().any(|k| k == "where"), "{keywords:?}");
        assert!(keywords.iter().any(|k| k == "take"), "{keywords:?}");
    }

    #[test]
    fn parses_spl_stats() {
        let tree = parse(LanguageId::Spl, "search index=main | stats count by host").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
    }

    #[test]
    fn parses_spl_catalog_command() {
        let tree = parse(LanguageId::Spl, "index=main | timechart count by host").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
        assert!(
            tree.root_node().to_sexp().contains("catalog_command"),
            "{}",
            tree.root_node().to_sexp()
        );
    }
}

#[cfg(test)]
mod highlight_cst_dump {
    use super::*;
    use tree_sitter::{Node, Query, QueryCursor, StreamingIterator};

    fn dump_node(node: Node, src: &str, depth: usize, out: &mut String) {
        let pad = "  ".repeat(depth);
        let text = node.utf8_text(src.as_bytes()).unwrap_or("");
        let shown = if text.len() > 48 {
            format!("{}…", &text[..48])
        } else {
            text.replace('\n', "\\n")
        };
        out.push_str(&format!(
            "{pad}kind={:?} named={} children={} bytes=[{}..{}] text={:?}\n",
            node.kind(),
            node.is_named(),
            node.child_count(),
            node.start_byte(),
            node.end_byte(),
            shown
        ));
        let mut c = node.walk();
        for child in node.children(&mut c) {
            dump_node(child, src, depth + 1, out);
        }
    }

    #[test]
    fn dump_cst_kql_and_spl_samples() {
        for (lang, src) in [
            (
                LanguageId::Kql,
                "SecurityEvent | where EventID == 1 | take 1",
            ),
            (LanguageId::Spl, "index=main | stats count by host | head 1"),
        ] {
            let tree = parse(lang, src).unwrap();
            let mut out = String::new();
            dump_node(tree.root_node(), src, 0, &mut out);
            eprintln!("=== CST {lang} ===\n{out}");
            // Focus keyword-like anonymous leaves
            fn focus(node: Node, src: &str) {
                if matches!(
                    node.kind(),
                    "where" | "take" | "stats" | "head" | "by" | "identifier" | "|"
                ) {
                    eprintln!(
                        "FOCUS kind={} named={} children={} parent={:?} text={:?}",
                        node.kind(),
                        node.is_named(),
                        node.child_count(),
                        node.parent().map(|p| p.kind()),
                        node.utf8_text(src.as_bytes()).unwrap_or(""),
                    );
                }
                let mut c = node.walk();
                for child in node.children(&mut c) {
                    focus(child, src);
                }
            }
            focus(tree.root_node(), src);
        }
    }

    #[test]
    fn highlights_scm_query_api_emits_keywords() {
        let src = "SecurityEvent | where EventID == 1 | take 1";
        let lang = kql_language();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let scm = include_str!("../../../highlights/queries/kql/highlights.scm");
        let query = Query::new(&lang, scm).expect("compile kql highlights.scm");
        let mut cursor = QueryCursor::new();
        let mut iter = cursor.matches(&query, tree.root_node(), src.as_bytes());
        let mut keywords = Vec::new();
        while let Some(m) = iter.next() {
            for cap in m.captures {
                let name = query.capture_names()[cap.index as usize];
                if name == "keyword" {
                    keywords.push(src[cap.node.start_byte()..cap.node.end_byte()].to_string());
                }
            }
        }
        assert!(keywords.iter().any(|k| k == "where"), "{keywords:?}");
        assert!(keywords.iter().any(|k| k == "take"), "{keywords:?}");
    }
}
