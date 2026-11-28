//! Hover and completion for the Datadog search syntax: the reserved and standard attributes of
//! the catalogue, the operators and `CIDR`.

use crate::catalog::{self, Catalog};
use crate::syntax::{SyntaxKind as K, SyntaxToken};
use opentide_core::CompletionItem;
use rowan::TextSize;

const SEARCH_SYNTAX: &str = "https://docs.datadoghq.com/logs/explorer/search_syntax/";

/// The operators and `CIDR`, with what each does (RFC §6.3 to §6.5).
pub const KEYWORDS: [(&str, &str); 5] = [
    (
        "AND",
        "Both sides match. Juxtaposition is AND too (`a b`). AND binds tighter than OR, as VRL \
         reads it (unverified on Cloud SIEM).",
    ),
    ("OR", "Either side matches."),
    (
        "NOT",
        "The clause after it does not match; `-` before a clause is the same exclusion.",
    ),
    (
        "TO",
        "Separates a range's bounds: `[400 TO 499]` (inclusive), `{200 TO 299}` (exclusive).",
    ),
    (
        "CIDR",
        "`CIDR(@attribute, block, …)` matches an IP attribute inside any of the IPv4 or IPv6 CIDR \
         blocks.",
    ),
];

/// The hover of the token at byte `offset` of `source`: an attribute the catalogue lists, or an
/// operator.
#[must_use]
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let (root, _) = crate::parser::parse(source);
    let at = TextSize::from(u32::try_from(offset.min(source.len())).ok()?);
    let token: SyntaxToken = root.token_at_offset(at).right_biased()?;
    let parent = token.parent()?;
    match (token.kind(), parent.kind()) {
        (_, K::ATTRIBUTE) => {
            let text = crate::check::trimmed(&parent);
            let name = source.get(usize::from(text.start())..usize::from(text.end()))?;
            let attribute = Catalog::cached().attribute(name.strip_prefix('@')?)?;
            Some(catalog::markdown(attribute, false))
        }
        (_, K::TAG_KEY) => {
            let text = crate::check::trimmed(&parent);
            let name = source.get(usize::from(text.start())..usize::from(text.end()))?;
            Catalog::cached()
                .reserved(name)
                .map(|a| catalog::markdown(a, true))
        }
        (K::AND_KW | K::OR_KW | K::NOT_KW | K::TO_KW | K::CIDR_KW, _) => {
            let word = token.text().to_ascii_uppercase();
            let (name, text) = KEYWORDS.iter().find(|(name, _)| *name == word)?;
            Some(format!(
                "**{name}**: {text}\n\n[Search syntax]({SEARCH_SYNTAX})"
            ))
        }
        _ => None,
    }
}

/// Whether `c` can be part of an attribute path as completion reads it.
fn path_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '@' | '.' | '_' | '-')
}

/// The completions at byte `offset` of `source`: after `@`, the standard attributes; at the
/// start of a word, the reserved attributes and the operators.
#[must_use]
pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let offset = offset.min(source.len());
    let Some(before) = source.get(..offset) else {
        return Vec::new();
    };
    let start = opentide_core::word_start(before, path_char);
    // `word_start` starts on a char.
    let word = before.split_at_checked(start).map_or("", |(_, word)| word);
    let catalog = Catalog::cached();
    if word.starts_with('@') {
        return catalog
            .attributes
            .iter()
            .map(|a| {
                CompletionItem::new(format!("@{}", a.name), "property")
                    .with_detail(format!("{} ({})", a.domain, a.ty))
            })
            .collect();
    }
    let mut items: Vec<CompletionItem> = catalog
        .reserved
        .iter()
        .map(|a| {
            CompletionItem::new(a.name.clone(), "property")
                .with_detail(format!("reserved attribute ({})", a.ty))
        })
        .collect();
    items.extend(
        KEYWORDS
            .iter()
            .map(|(name, text)| CompletionItem::new(*name, "keyword").with_detail(*text)),
    );
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hover_names_a_standard_attribute() {
        let text = hover("@network.client.ip:10.0.0.1", 3).expect("hover");
        assert!(
            text.starts_with("**@network.client.ip** (string)"),
            "{text}"
        );
        assert_eq!(hover("@not.in.the.catalogue:x", 3), None);
    }

    #[test]
    fn hover_names_a_reserved_attribute_and_an_operator() {
        assert!(hover("host:web-1", 1).is_some_and(|t| t.starts_with("**host**")));
        assert!(hover("a OR b", 2).is_some_and(|t| t.starts_with("**OR**")));
        assert!(hover("CIDR(@ip, 10.0.0.0/8)", 1).is_some_and(|t| t.starts_with("**CIDR**")));
    }

    #[test]
    fn completion_after_at_lists_the_standard_attributes() {
        let items = completions("source:okta @net", 16);
        assert!(items.iter().any(|i| i.label == "@network.client.ip"));
        assert!(items.iter().all(|i| i.label.starts_with('@')));
        let items = completions("ser", 3);
        assert!(items.iter().any(|i| i.label == "service"));
        assert!(items.iter().any(|i| i.label == "AND"));
    }
}
