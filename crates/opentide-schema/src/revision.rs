//! Revision structs (ADR 0001, "Revisions").
//!
//! Each schema revision is one concrete struct (`RuleV1_0`, `RuleV1_1`), with
//! an alias for the newest (`pub type Rule = RuleV1_1`). `#[pyclass]` accepts
//! no generic parameters (`tests/ui/pyclass_generic.rs` proves it), so a
//! revision cannot be `Rule<V>`. Fields shared by every revision of a family
//! are written once, in [`revisions!`], which repeats them into each struct.
//!
//! Field order is serde order, which is also the template and serialisation
//! order, and it is Pydantic's: a subclass's new fields come after the
//! inherited ones, and a field a subclass overrides keeps its parent's
//! position (`DetectionRule_v1_1.metadata` stays second, as in
//! `DetectionRule`). So the shared fields come in up to four groups, `@0` to
//! `@3`, placed where they belong in each struct; a field a revision overrides
//! sits between two groups, in every revision.

/// Declares a family's revision structs.
///
/// ```ignore
/// revisions! {
///     shared [
///         {
///             /// Display name.
///             #[garde(skip)]
///             pub name: String,
///         }
///         {
///             /// What the rule does.
///             #[garde(skip)]
///             pub description: String,
///         }
///     ]
///     /// Revision 1.0.
///     #[derive(Serialize, Deserialize)]
///     pub struct RuleV1_0 { @0, #[garde(dive)] pub metadata: ObjectMetadata, @1, }
///     /// Revision 1.1: `metadata` is overridden and keeps its position.
///     #[derive(Serialize, Deserialize)]
///     pub struct RuleV1_1 { @0, #[garde(dive)] pub metadata: RuleMetadata, @1, }
/// }
/// ```
///
/// Every field, shared or not, ends with a comma. The macro takes one field per
/// recursion step, so a struct can have about a hundred fields before the
/// default recursion limit (128).
macro_rules! revisions {
    (
        shared $groups:tt
        $( $(#[$meta:meta])* $vis:vis struct $name:ident { $($body:tt)* } )+
    ) => {
        $(
            $crate::revision::revision_struct! {
                $groups [$(#[$meta])* $vis struct $name] [] $($body)*
            }
        )+
    };
}

/// One struct of [`revisions!`]: munches its body a field at a time into the
/// accumulator, splicing shared group `n` at `@n,`.
macro_rules! revision_struct {
    ([{ $($g:tt)* } $($others:tt)*] [$($head:tt)*] [$($fields:tt)*] @0, $($rest:tt)*) => {
        $crate::revision::revision_struct! {
            [{ $($g)* } $($others)*] [$($head)*] [$($fields)* $($g)*] $($rest)*
        }
    };
    ([$a:tt { $($g:tt)* } $($others:tt)*] [$($head:tt)*] [$($fields:tt)*] @1, $($rest:tt)*) => {
        $crate::revision::revision_struct! {
            [$a { $($g)* } $($others)*] [$($head)*] [$($fields)* $($g)*] $($rest)*
        }
    };
    ([$a:tt $b:tt { $($g:tt)* } $($others:tt)*] [$($head:tt)*] [$($fields:tt)*] @2, $($rest:tt)*) => {
        $crate::revision::revision_struct! {
            [$a $b { $($g)* } $($others)*] [$($head)*] [$($fields)* $($g)*] $($rest)*
        }
    };
    ([$a:tt $b:tt $c:tt { $($g:tt)* } $($others:tt)*] [$($head:tt)*] [$($fields:tt)*] @3, $($rest:tt)*) => {
        $crate::revision::revision_struct! {
            [$a $b $c { $($g)* } $($others)*] [$($head)*] [$($fields)* $($g)*] $($rest)*
        }
    };
    (
        $groups:tt [$($head:tt)*] [$($fields:tt)*]
        $(#[$field_meta:meta])* $field_vis:vis $field:ident : $ty:ty, $($rest:tt)*
    ) => {
        $crate::revision::revision_struct! {
            $groups [$($head)*] [$($fields)* $(#[$field_meta])* $field_vis $field: $ty,] $($rest)*
        }
    };
    ($groups:tt [$($head:tt)*] [$($fields:tt)*]) => {
        $($head)* { $($fields)* }
    };
}

pub(crate) use revision_struct;
pub(crate) use revisions;
