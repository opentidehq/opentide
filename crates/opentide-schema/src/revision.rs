//! Revision structs (ADR 0001, "Revisions").
//!
//! Each schema revision is one concrete struct (`RuleV1_0`, `RuleV1_1`), with
//! an alias for the newest (`pub type Rule = RuleV1_1`). `#[pyclass]` accepts
//! no generic parameters (`tests/ui/pyclass_generic.rs` proves it), so a
//! revision cannot be `Rule<V>`. Fields shared by every revision of a family
//! are written once, in [`revisions!`], which repeats them into each struct
//! where the struct's body says `@shared,`. Field order is serde order, which
//! is also the template and serialisation order, so `@shared` sits where the
//! shared fields belong.

/// Declares a family's revision structs.
///
/// ```ignore
/// revisions! {
///     shared {
///         /// Display name.
///         #[garde(skip)]
///         pub name: String,
///     }
///     /// Revision 1.0.
///     #[derive(Serialize, Deserialize)]
///     pub struct ThingV1_0 { @shared, }
///     /// Revision 1.1: adds `tags` after the shared fields.
///     #[derive(Serialize, Deserialize)]
///     pub struct ThingV1_1 { @shared, #[garde(skip)] pub tags: Vec<String>, }
/// }
/// ```
///
/// Every field, shared or not, ends with a comma. The macro takes one field per
/// recursion step, so a struct can have about a hundred fields before the
/// default recursion limit (128).
macro_rules! revisions {
    (
        shared $shared:tt
        $( $(#[$meta:meta])* $vis:vis struct $name:ident { $($body:tt)* } )+
    ) => {
        $(
            $crate::revision::revision_struct! {
                $shared [$(#[$meta])* $vis struct $name] [] $($body)*
            }
        )+
    };
}

/// One struct of [`revisions!`]: munches its body a field at a time into the
/// accumulator, splicing the shared fields at `@shared,`.
macro_rules! revision_struct {
    ({ $($shared:tt)* } [$($head:tt)*] [$($fields:tt)*] @shared, $($rest:tt)*) => {
        $crate::revision::revision_struct! {
            { $($shared)* } [$($head)*] [$($fields)* $($shared)*] $($rest)*
        }
    };
    (
        $shared:tt [$($head:tt)*] [$($fields:tt)*]
        $(#[$field_meta:meta])* $field_vis:vis $field:ident : $ty:ty, $($rest:tt)*
    ) => {
        $crate::revision::revision_struct! {
            $shared [$($head)*] [$($fields)* $(#[$field_meta])* $field_vis $field: $ty,] $($rest)*
        }
    };
    ($shared:tt [$($head:tt)*] [$($fields:tt)*]) => {
        $($head)* { $($fields)* }
    };
}

pub(crate) use revision_struct;
pub(crate) use revisions;
