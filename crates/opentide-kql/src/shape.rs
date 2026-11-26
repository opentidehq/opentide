//! What a query reads and which constructs it uses, from its tree: the
//! tables it names, its joins, unions, `externaldata` sources and comments,
//! and the columns it names. A host checks a platform's documented limits
//! on a query against it (Microsoft Defender's continuous, NRT, frequency in
//! opentide-tide, #1890) without parsing the query again: the tree is the
//! one [`crate::analyze`] built for the same text.

use opentide_core::ByteSpan;
use rowan::NodeOrToken;

use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};

/// The parts of one query a platform's limits are about. Every span is a
/// byte span of the query's text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shape {
    /// Each table named where a query reads rows (a pipeline's source, a
    /// `join` or `lookup` side, a `union` leg, a `toscalar` body), in order,
    /// unquoted, with the name's span. A name a `let` or a parameter binds
    /// anywhere in the query is left out, as is a table of another database
    /// (`database("d").T`): the shape does not track scopes, so it never
    /// counts a bound name as a table.
    pub tables: Vec<(String, ByteSpan)>,
    /// The `join` keyword of each `join`.
    pub joins: Vec<ByteSpan>,
    /// The `union` keyword of each `union`, as a source or an operator.
    pub unions: Vec<ByteSpan>,
    /// The keyword of each `externaldata` (or `external_data`) source.
    pub externaldata: Vec<ByteSpan>,
    /// Each `//` comment.
    pub comments: Vec<ByteSpan>,
    /// Each column name the query reads (unquoted), with its span: a name
    /// in [`Shape::defined`]'s place is not one.
    pub names: Vec<(String, ByteSpan)>,
    /// Each column name an operator defines (unquoted), with its span: an
    /// assignment's left-hand name (`extend A = 1`, `summarize N = count()`,
    /// each name of a tuple assignment) and the new name of a
    /// `project-rename`.
    pub defined: Vec<(String, ByteSpan)>,
}

/// The shape of `source`, or `None` when it has a syntax error: a broken
/// tree's parts are not certain, and the syntax error is the finding.
pub fn shape(source: &str) -> Option<Shape> {
    let parsed = crate::parser::parse_once(source);
    if !parsed.errors.is_empty() {
        return None;
    }
    let root = SyntaxNode::new_root(parsed.green);
    let span = |range: rowan::TextRange| {
        ByteSpan::new(usize::from(range.start()), usize::from(range.end()))
    };
    let mut bound: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut tables: Vec<(String, ByteSpan)> = Vec::new();
    let mut out = Shape::default();
    for element in root.descendants_with_tokens() {
        match element {
            NodeOrToken::Token(token) => {
                if token.kind() == K::COMMENT {
                    out.comments.push(span(token.text_range()));
                }
            }
            NodeOrToken::Node(node) => match node.kind() {
                K::LET_STATEMENT | K::PARAMETER => {
                    if let Some(name) = first_ident(&node) {
                        bound.insert(name.text().to_owned());
                    }
                }
                K::TABLE_REF => {
                    let elsewhere = node
                        .parent()
                        .is_some_and(|parent| parent.kind() == K::QUALIFIED_TABLE);
                    if !elsewhere && let Some(token) = crate::syntax_util::table_token(&node) {
                        let name = crate::schema::unquote_name(token.text());
                        if !name.is_empty() && !name.starts_with('$') {
                            tables.push((name.to_owned(), span(token.text_range())));
                        }
                    }
                }
                K::JOIN_OPERATOR => out.joins.extend(keyword(&node, K::JOIN_KW).map(span)),
                K::UNION_OPERATOR => out.unions.extend(keyword(&node, K::UNION_KW).map(span)),
                K::EXTERNALDATA_EXPRESSION => {
                    let word = keyword(&node, K::EXTERNALDATA_KW)
                        .or_else(|| keyword(&node, K::EXTERNAL_DATA_KW));
                    out.externaldata.extend(word.map(span));
                }
                K::NAME_REF => {
                    let name = crate::syntax_util::name(source, &node);
                    if !name.is_empty() {
                        let at = (name.to_owned(), span(crate::syntax_util::range(&node)));
                        if defines(&node) {
                            out.defined.push(at);
                        } else {
                            out.names.push(at);
                        }
                    }
                }
                _ => {}
            },
        }
    }
    out.tables = tables
        .into_iter()
        .filter(|(name, _)| !bound.contains(name))
        .collect();
    Some(out)
}

/// Whether the `NAME_REF` `name_ref` is a name an operator defines: the
/// first name of an assignment or of a `project-rename` item (its new
/// name), or a name of an assignment's tuple.
fn defines(name_ref: &SyntaxNode) -> bool {
    let Some(parent) = name_ref.parent() else {
        return false;
    };
    match parent.kind() {
        K::ASSIGNMENT | K::RENAME_ITEM => parent
            .children()
            .find(|child| child.kind() == K::NAME_REF)
            .is_some_and(|first| first == *name_ref),
        K::NAME_TUPLE => true,
        _ => false,
    }
}

/// The first identifier directly under `node`: a `let`'s or a parameter's
/// name.
fn first_ident(node: &SyntaxNode) -> Option<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .find(|token| token.kind() == K::IDENT)
}

/// The range of the keyword token of `kind` directly under `node`.
fn keyword(node: &SyntaxNode, kind: K) -> Option<rowan::TextRange> {
    node.children_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .find(|token| token.kind() == kind)
        .map(|token| token.text_range())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables(source: &str) -> Vec<String> {
        shape(source)
            .unwrap()
            .tables
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn the_tables_a_query_reads_are_named_with_their_spans() {
        let source = "DeviceEvents | where ActionType == \"x\"";
        let found = shape(source).unwrap();
        assert_eq!(
            found.tables,
            vec![("DeviceEvents".to_owned(), ByteSpan::new(0, 12))]
        );
        assert!(found.joins.is_empty() && found.unions.is_empty());
        assert!(found.externaldata.is_empty() && found.comments.is_empty());
        assert_eq!(
            tables("DeviceEvents | join kind=inner (DeviceInfo | take 1) on DeviceId"),
            ["DeviceEvents", "DeviceInfo"]
        );
        assert_eq!(
            tables("DeviceEvents | lookup DeviceInfo on DeviceId"),
            ["DeviceEvents", "DeviceInfo"]
        );
        assert_eq!(
            tables("union DeviceEvents, ['DeviceFileEvents']"),
            ["DeviceEvents", "DeviceFileEvents"]
        );
        assert_eq!(
            tables("DeviceEvents | where DeviceId in ((DeviceInfo | project DeviceId))"),
            ["DeviceEvents", "DeviceInfo"]
        );
    }

    #[test]
    fn a_bound_name_or_another_databases_table_is_not_a_table() {
        assert_eq!(
            tables("let recent = DeviceEvents | where Timestamp > ago(1h);\nrecent | take 1"),
            ["DeviceEvents"]
        );
        assert_eq!(
            tables("let f = (t: (*)) { t | take 1 };\nf(DeviceEvents)"),
            Vec::<String>::new(),
            "a function call is not a table reference"
        );
        assert_eq!(
            tables("database(\"d\").DeviceEvents | take 1"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn joins_unions_externaldata_and_comments_are_found() {
        let source = "// look\nDeviceEvents\n| join (DeviceInfo) on DeviceId // inline\n\
                      | union (externaldata (a: string) [\"https://x\"] with (format = \"csv\"))";
        let found = shape(source).unwrap();
        let text = |spans: &[ByteSpan]| -> Vec<&str> {
            spans.iter().map(|s| &source[s.start..s.end]).collect()
        };
        assert_eq!(text(&found.joins), ["join"]);
        assert_eq!(text(&found.unions), ["union"]);
        assert_eq!(text(&found.externaldata), ["externaldata"]);
        assert_eq!(text(&found.comments), ["// look", "// inline"]);
        // A `//` in a string is not a comment.
        let quoted = shape("DeviceEvents | where Url has \"https://x\"").unwrap();
        assert!(quoted.comments.is_empty(), "{quoted:?}");
    }

    #[test]
    fn the_columns_a_query_names_are_found() {
        let found = shape("EmailEvents | where LatestDeliveryAction == \"Blocked\"").unwrap();
        assert!(
            found
                .names
                .iter()
                .any(|(name, _)| name == "LatestDeliveryAction"),
            "{found:?}"
        );
    }

    #[test]
    fn a_name_an_operator_defines_is_not_a_name_it_reads() {
        let names = |found: &[(String, ByteSpan)]| -> Vec<String> {
            found.iter().map(|(name, _)| name.clone()).collect()
        };
        let found = shape(
            "EmailEvents\n| extend A = DeliveryAction, B = 1\n\
             | project-rename D = DeliveryLocation\n| summarize N = count() by A",
        )
        .unwrap();
        assert_eq!(names(&found.defined), ["A", "B", "D", "N"], "{found:?}");
        assert_eq!(
            names(&found.names),
            ["DeliveryAction", "DeliveryLocation", "A"],
            "{found:?}"
        );
    }

    #[test]
    fn a_query_with_a_syntax_error_has_no_shape() {
        assert_eq!(shape("DeviceEvents | where ("), None);
    }
}
