//! Tree-sitter language bindings. Parser C is vendored; do not hand-edit `parser.c`.

use opentide_core::{ByteSpan, LanguageId};
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, StreamingIterator, Tree};

unsafe extern "C" {
    fn tree_sitter_opentide_kql() -> *const ();
    fn tree_sitter_opentide_spl() -> *const ();
    fn tree_sitter_opentide_esql() -> *const ();
    fn tree_sitter_opentide_eql() -> *const ();
    fn tree_sitter_opentide_kuery() -> *const ();
    fn tree_sitter_opentide_lucene() -> *const ();
    fn tree_sitter_opentide_falco() -> *const ();
    fn tree_sitter_opentide_cql() -> *const ();
    fn tree_sitter_opentide_yara() -> *const ();
}

fn from_raw(ptr: *const ()) -> Language {
    // tree-sitter 0.25: Language::new(LanguageFn)
    unsafe { Language::from_raw(ptr as usize as *const tree_sitter::ffi::TSLanguage) }
}

pub fn language(id: LanguageId) -> Option<Language> {
    match id {
        LanguageId::Kql => Some(kql_language()),
        LanguageId::Spl => Some(spl_language()),
        LanguageId::Esql => Some(unsafe { from_raw(tree_sitter_opentide_esql()) }),
        LanguageId::Eql => Some(unsafe { from_raw(tree_sitter_opentide_eql()) }),
        LanguageId::Kuery => Some(unsafe { from_raw(tree_sitter_opentide_kuery()) }),
        LanguageId::Lucene => Some(unsafe { from_raw(tree_sitter_opentide_lucene()) }),
        LanguageId::Falco => Some(unsafe { from_raw(tree_sitter_opentide_falco()) }),
        LanguageId::Cql => Some(unsafe { from_raw(tree_sitter_opentide_cql()) }),
        // Highlighting and structure only: YARA's verdict parser is
        // yara-x-parser (opentide-yara).
        LanguageId::Yara => Some(unsafe { from_raw(tree_sitter_opentide_yara()) }),
        // Tide YAML has its own parser; configuration TOML is the host's.
        LanguageId::TideYaml | LanguageId::Config => None,
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

/// First `ERROR` or `MISSING` node in document order, for a parse-error range.
///
/// A MISSING token that the grammar hides (a `_`-prefixed rule) is not a
/// visible node, so the smallest visible node that still reports the error
/// stands in for it.
pub fn first_error(node: Node<'_>) -> Option<Node<'_>> {
    if !node.has_error() && !node.is_missing() {
        return None;
    }
    // Down the first erroneous child at each level; iterative, so a deeply
    // nested broken query cannot exhaust the stack.
    let mut node = node;
    loop {
        if node.is_error() || node.is_missing() {
            return Some(node);
        }
        let mut cursor = node.walk();
        let next = node
            .children(&mut cursor)
            .find(|child| child.has_error() || child.is_missing());
        match next {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

/// Pre-order walk that hands each node its ancestors, root first. Iterative,
/// so a query thousands of levels deep cannot exhaust the stack. Checks that
/// look upward read `ancestors` instead of calling [`Node::parent`], which
/// re-descends from the root on every call.
pub fn walk_with_ancestors<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>, &[Node<'t>])) {
    let mut cursor = root.walk();
    let mut ancestors: Vec<Node<'t>> = Vec::new();
    loop {
        let node = cursor.node();
        f(node, &ancestors);
        if cursor.goto_first_child() {
            ancestors.push(node);
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
            ancestors.pop();
        }
    }
}

/// The sibling before `node`, read from its parent's children with a cursor.
///
/// Use this instead of [`Node::prev_sibling`]: in an error-recovered tree,
/// tree-sitter 0.25's `prev_sibling()` can cycle between a `MISSING` node and
/// a zero-width sibling, so a loop over it never ends (#179). A cursor walks
/// the parent's child list, which is finite.
pub fn prev_sibling(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    let mut cursor = parent.walk();
    let mut previous = None;
    for child in parent.children(&mut cursor) {
        if child.id() == node.id() {
            return previous;
        }
        previous = Some(child);
    }
    None
}

/// Byte span of a node, never empty so editors can show it.
pub fn node_span(node: Node<'_>) -> ByteSpan {
    ByteSpan::new(
        node.start_byte(),
        node.end_byte().max(node.start_byte() + 1),
    )
}

/// `scm` compiled for `id`, once per process. `Query::new` costs about
/// 10 ms for the KQL and SPL highlight queries, more than the rest of an
/// analysis (#181); a compiled `Query` is `Send + Sync`, so every thread
/// shares it.
fn compiled_query(
    id: LanguageId,
    language: &Language,
    scm: &str,
) -> Result<std::sync::Arc<Query>, String> {
    type Cache = std::collections::HashMap<LanguageId, Vec<(String, std::sync::Arc<Query>)>>;
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Cache>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let lookup = |cache: &Cache| {
        cache
            .get(&id)
            .and_then(|queries| queries.iter().find(|(text, _)| text == scm))
            .map(|(_, query)| std::sync::Arc::clone(query))
    };
    if let Some(query) = lookup(&cache.lock().unwrap_or_else(|p| p.into_inner())) {
        return Ok(query);
    }
    // Compile outside the lock; a racing thread compiling the same query
    // only wastes the work.
    let query = std::sync::Arc::new(Query::new(language, scm).map_err(|e| e.to_string())?);
    let mut cache = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = lookup(&cache) {
        return Ok(existing);
    }
    cache
        .entry(id)
        .or_default()
        .push((scm.to_string(), std::sync::Arc::clone(&query)));
    Ok(query)
}

/// Run a highlights.scm query. First capture wins for an identical span so
/// specific patterns listed before `(identifier) @variable` take precedence.
pub fn query_captures(
    id: LanguageId,
    source: &str,
    scm: &str,
) -> Result<Vec<(ByteSpan, String)>, String> {
    let language = language(id).ok_or_else(|| format!("no tree-sitter grammar for {id}"))?;
    let mut parser = Parser::new();
    parser.set_language(&language).map_err(|e| e.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "parse failed".to_string())?;
    query_captures_in(id, &tree, source, scm)
}

/// [`query_captures`] on a tree the caller already parsed from `source`.
pub fn query_captures_in(
    id: LanguageId,
    tree: &Tree,
    source: &str,
    scm: &str,
) -> Result<Vec<(ByteSpan, String)>, String> {
    let language = language(id).ok_or_else(|| format!("no tree-sitter grammar for {id}"))?;
    let query = compiled_query(id, &language, scm)?;
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
            include_str!(concat!(
                env!("OPENTIDE_ASSETS"),
                "/highlights/queries/kql/highlights.scm"
            )),
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
    fn hidden_missing_tokens_still_report_an_error() {
        let tree = parse(LanguageId::Esql, "FROM | LIMIT 10").unwrap();
        assert!(has_error(&tree));
        let err = first_error(tree.root_node()).expect("error node");
        assert!(err.start_byte() <= 5, "{}", tree.root_node().to_sexp());
    }

    #[test]
    fn parses_spl_stats() {
        let tree = parse(LanguageId::Spl, "search index=main | stats count by host").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
    }

    #[test]
    fn parses_spl_stats_family() {
        let tree = parse(LanguageId::Spl, "index=main | timechart count by host").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
        assert!(
            tree.root_node().to_sexp().contains("stats_command"),
            "{}",
            tree.root_node().to_sexp()
        );
    }

    #[test]
    fn parses_spl_catalog_command() {
        let tree = parse(LanguageId::Spl, "index=main | top limit=10 host").unwrap();
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
        let scm = include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/highlights/queries/kql/highlights.scm"
        ));
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
