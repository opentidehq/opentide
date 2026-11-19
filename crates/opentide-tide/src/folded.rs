//! A line comment that folding carries over the query's next lines.
//!
//! A `>` block scalar, a plain scalar and a quoted scalar on several lines
//! fold their line breaks into spaces: the query the platform runs is one
//! line. A `//` comment on one of the source lines then runs to the end of
//! the query, and every line folded after it is part of the comment: the
//! filter a reader sees is not the one deployed (smoke test B16). The query
//! text itself is valid, so no engine reports it; this check reads the
//! comment tokens the engine highlighted against the source lines they
//! cover. An error: the rule that deploys is not the one written, and
//! `opentide validate` fails on it.

use crate::{InjectedQuery, remap_span};
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use opentide_highlight::HighlightToken;

/// A `query_folded_comment` error for each `//` comment of `inj` that
/// folding joined to a later source line holding more than another comment.
pub(crate) fn folded_comments(
    source: &str,
    inj: &InjectedQuery,
    tokens: &[HighlightToken],
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for token in tokens {
        let span = token.span;
        if token.capture != "comment"
            || span.end <= span.start
            || inj.is_synthetic(span.start)
            || !inj
                .inner
                .get(span.start..span.end)
                .is_some_and(|text| text.starts_with("//"))
        {
            continue;
        }
        let host = remap_span(inj, span);
        let Some(covered) = source.get(host.start..host.end) else {
            continue;
        };
        // The source lines after the comment's own: blank or comment lines
        // fold away harmlessly; anything else is query text lost.
        let mut lines = covered.split('\n');
        let first = lines.next().unwrap_or_default();
        let Some(lost) = lines
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with("//"))
        else {
            continue;
        };
        let comment = ByteSpan::new(host.start, host.start + first.trim_end().len());
        let message = format!(
            "YAML folds this query's lines into one, so this `//` comment runs on and comments \
             out the lines after it, from `{}`: the platform runs the query without them; \
             write the query as a literal block (`|` or `|-`), which keeps its lines, or remove \
             the comment",
            shorten(lost)
        );
        out.push(
            Diagnostic::error(
                codes::QUERY_FOLDED_COMMENT,
                message,
                span_to_range(source, comment),
            )
            .with_field_path(inj.field_path.clone()),
        );
    }
    out
}

/// `line`'s first 40 characters, with `…` when it is longer.
fn shorten(line: &str) -> String {
    const MAX: usize = 40;
    match line.char_indices().nth(MAX) {
        Some((at, _)) => format!("{}…", &line[..at]),
        None => line.to_owned(),
    }
}
