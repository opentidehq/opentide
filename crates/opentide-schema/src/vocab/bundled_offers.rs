//! The offers of the bundled vocabularies, made by `build.rs` ([`offer_of`](super::offer::offer_of) on
//! each bundled document, which is all an offer depends on) and decoded the
//! first time a field asks for one.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::offer::{Offer, OfferNames};

/// What decodes an offer, on the first call.
pub(super) type Load = fn() -> &'static Offer;

/// What decodes an offer's values with their names alone ([`OfferNames`]), on the first call.
pub(super) type LoadNames = fn() -> &'static OfferNames;

// `OFFERS`: `(reference, scoped, the offer's decoder, the decoder of its names)` for each offer
// the build script wrote.
include!(concat!(env!("OUT_DIR"), "/vocab_offers.rs"));

/// The offer of the bundled vocabulary `reference` (`field` or `field::M.m`, as
/// a field names it), for a field that does not ask for unwrapped hints; `None`
/// where the build script made none.
pub fn bundled_offer(reference: &str, scoped: bool) -> Option<&'static Offer> {
    OFFERS
        .iter()
        .find(|(name, is_scoped, _, _)| *name == reference && *is_scoped == scoped)
        .map(|(_, _, offer, _)| offer())
}

/// Every offer the build script made, as `(reference, scoped)`.
#[cfg(test)]
pub fn offered() -> impl Iterator<Item = (&'static str, bool)> {
    OFFERS
        .iter()
        .map(|(reference, scoped, _, _)| (*reference, *scoped))
}

/// One value of a bundled offer as an editor lists it: its entry's name and
/// the words it is found by besides the value ([`Offer::search`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedValue<'a> {
    /// The entry's display name.
    pub name: &'a str,
    /// The entry's name and aliases.
    pub search: &'a str,
}

/// A value's place in a list of values, by the value: its first place (a
/// search hint comes after the values).
type Places = HashMap<&'static str, usize>;

fn places(values: &'static [String]) -> Places {
    let mut places = HashMap::with_capacity(values.len());
    for (at, value) in values.iter().enumerate() {
        places.entry(value.as_str()).or_insert(at);
    }
    places
}

/// Each offer's values by their place in its [`OfferNames`], and in its
/// [`Offer`], made the first time a value of that offer is looked up.
static NAME_PLACES: [OnceLock<Places>; OFFERS.len()] = [const { OnceLock::new() }; OFFERS.len()];
static MARKDOWN_PLACES: [OnceLock<Places>; OFFERS.len()] =
    [const { OnceLock::new() }; OFFERS.len()];

fn offer_place(reference: &str, scoped: bool) -> Option<usize> {
    OFFERS
        .iter()
        .position(|(name, is_scoped, _, _)| *name == reference && *is_scoped == scoped)
}

/// The name and search text of the value `value` of the bundled offer
/// `reference` (as [`bundled_offer`] takes it): `None` where the build made no
/// such offer or it has no such value. A lookup, not a scan: a completion
/// asks for each of a thousand values. It decodes the offer's names alone,
/// never its Markdown ([`bundled_markdown`]).
pub fn bundled_value(reference: &str, scoped: bool, value: &str) -> Option<OfferedValue<'static>> {
    let place = offer_place(reference, scoped)?;
    let (_, _, _, load) = OFFERS[place];
    let names = load();
    let at = *NAME_PLACES[place]
        .get_or_init(|| places(&names.values))
        .get(value)?;
    let text = |list: &'static [String]| list.get(at).map_or("", String::as_str);
    Some(OfferedValue {
        name: text(&names.names),
        search: text(&names.search),
    })
}

/// The Markdown an editor documents the value `value` of the bundled offer
/// `reference` with (its entry's name, identifier, vocabulary, stages, link
/// and description), as [`bundled_value`] finds it.
pub fn bundled_markdown(reference: &str, scoped: bool, value: &str) -> Option<&'static str> {
    let place = offer_place(reference, scoped)?;
    let (_, _, load, _) = OFFERS[place];
    let offer = load();
    let at = *MARKDOWN_PLACES[place]
        .get_or_init(|| places(&offer.values))
        .get(value)?;
    offer.markdown.get(at).map(String::as_str)
}
