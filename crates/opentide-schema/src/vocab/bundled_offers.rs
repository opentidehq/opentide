//! The offers of the bundled vocabularies, made by `build.rs` ([`offer_of`] on
//! each bundled document, which is all an offer depends on) and decoded the
//! first time a field asks for one.

use super::offer::Offer;

/// What decodes an offer, on the first call.
pub(super) type Load = fn() -> &'static Offer;

// `OFFERS`: `(reference, scoped, the offer's decoder)` for each offer the build script wrote.
include!(concat!(env!("OUT_DIR"), "/vocab_offers.rs"));

/// The offer of the bundled vocabulary `reference` (`field` or `field::M.m`, as
/// a field names it), for a field that does not ask for unwrapped hints; `None`
/// where the build script made none.
pub fn bundled_offer(reference: &str, scoped: bool) -> Option<&'static Offer> {
    OFFERS
        .iter()
        .find(|(name, is_scoped, _)| *name == reference && *is_scoped == scoped)
        .map(|(_, _, offer)| offer())
}

/// Every offer the build script made, as `(reference, scoped)`.
#[cfg(test)]
pub fn offered() -> impl Iterator<Item = (&'static str, bool)> {
    OFFERS
        .iter()
        .map(|(reference, scoped, _)| (*reference, *scoped))
}
