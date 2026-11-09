//! The 23 `tide.*` metadata keys (ADR 0001, "The `tide.*` metadata keys").
//!
//! Each key keeps its name: a field carries it as
//! `#[schemars(extend("tide.…" = value))]`, so the schema the struct derives
//! holds the same key with the same value as Pydantic's `json_schema_extra`,
//! and the generation pipeline (UC-1.8, #814) strips every `tide.*` key from
//! the editor schemas it writes, as `strip_framework_keywords` does today.
//!
//! The list is the oracle's (opentide 0.23.0, `src/opentide`): every `tide.*`
//! string that names metadata, which is every `tide.*` string literal except
//! the four highlight captures (`tide.keyword`, `tide.property`,
//! `tide.schema`, `tide.uuid`) and logger or module names. [`Origin`] says
//! where the oracle sets each key, which is where the Rust model sets it.

/// Where the oracle sets a metadata key, and so where the Rust model does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A model field declares it (`TideField(schema_extra=…)`,
    /// `VocabField`): a `#[schemars(extend(…))]` attribute on the field.
    Field,
    /// The schema pipeline adds it to a field's schema
    /// (`generation/pydantic_metaschema.py`, `models/platform_schema.py`): an
    /// attribute on the field where the value is static, or the pipeline's
    /// schemars transform where it depends on the revision's pins.
    Pipeline,
    /// The pipeline reads it, but nothing sets it at the oracle: the reader is
    /// ported with the key, so a field that sets it behaves as today.
    ReadOnly,
    /// Not a schema key: `lookup_schema_extra`'s request for a scope's whole
    /// property map.
    Lookup,
    /// A key of a vocabulary entry (`*.vocab.toml`) or of the object
    /// vocabulary the index builds, not of a schema: a serde field name.
    VocabularyEntry,
}

/// One `tide.*` metadata key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetadataKey {
    /// The key, as the oracle spells it.
    pub name: &'static str,
    /// Where it is set.
    pub origin: Origin,
}

macro_rules! keys {
    ($($(#[$doc:meta])* $ident:ident = $name:literal, $origin:ident;)+) => {
        $(
            $(#[$doc])*
            pub const $ident: &str = $name;
        )+
        /// Every metadata key, in the ADR table's order.
        pub const ALL: &[MetadataKey] = &[
            $(MetadataKey { name: $ident, origin: Origin::$origin },)+
        ];
    };
}

keys! {
    /// Templates and snippets write the value as a YAML block scalar (`|`).
    TEMPLATE_MULTILINE = "tide.template.multiline", Field;
    /// Templates leave a blank line before the key.
    TEMPLATE_SPACER = "tide.template.spacer", Field;
    /// Templates write the key although the model makes it optional.
    TEMPLATE_REQUIRED = "tide.template.required", Field;
    /// Templates and the field catalog leave the key out.
    TEMPLATE_HIDE = "tide.template.hide", Field;
    /// The vocabulary the value is drawn from (`true`: the field's own name).
    VOCAB = "tide.vocab", Field;
    /// Vocabulary values are `Stage::Value`.
    VOCAB_SCOPED = "tide.vocab.scoped", Field;
    /// The field's catalogue role: `techniques`, `actors` or `configurations`.
    FIELD_ROLE = "tide.field.role", Field;
    /// Values come from the workspace's configured responders.
    CONFIG_RESPONDERS = "tide.config.responders", Field;
    /// Values come from `visibility.toml`'s log source names.
    CONFIG_VISIBILITY_LOGSOURCE_NAMES = "tide.config.visibility.logsource-names", Field;
    /// The property is a shared definition (`metadata`, `references`) the
    /// pipeline rebuilds from its model.
    META_DEFINITION = "tide.meta.definition", Pipeline;
    /// Vocabulary pins below a `tide.meta.definition` property, by path.
    VOCAB_PINS = "tide.vocab.pins", Pipeline;
    /// Values come from the platform's configured statuses.
    CONFIG_STATUSES = "tide.config.statuses", Pipeline;
    /// Values come from the named platform's configured tenants.
    CONFIG_SYSTEM_TENANTS = "tide.config.system.tenants", Pipeline;
    /// The field is deprecated, with this message.
    META_DEPRECATION = "tide.meta.deprecation", ReadOnly;
    /// Vocabulary hover text is not wrapped.
    VOCAB_HINTS_NO_WRAP = "tide.vocab.hints.no-wrap", ReadOnly;
    /// Values come from `visibility.toml`'s detectors.
    CONFIG_VISIBILITY_DETECTORS = "tide.config.visibility.detectors", ReadOnly;
    /// Values come from the named configuration parameter list.
    CONFIG_PARAMETER_LIST = "tide.config.parameter-list", ReadOnly;
    /// Values are the enabled platforms.
    CONFIG_SYSTEMS_ENABLED = "tide.config.systems::enabled", ReadOnly;
    /// The platform's name for the parameter.
    MDR_PARAMETER = "tide.mdr.parameter", ReadOnly;
    /// A scope's whole property map, in `lookup_schema_extra`.
    META = "tide.meta", Lookup;
    /// The stages a vocabulary entry belongs to.
    VOCAB_STAGES = "tide.vocab.stages", VocabularyEntry;
    /// A chaining relation's direction (`from`, `to`).
    VOCAB_RELATION_TYPE = "tide.vocab.relation.type", VocabularyEntry;
    /// The objective a signal entry of the object vocabulary belongs to.
    OBJECT_PARENT = "tide.object.parent", VocabularyEntry;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn twenty_three_distinct_keys() {
        let names: BTreeSet<_> = ALL.iter().map(|key| key.name).collect();
        assert_eq!(ALL.len(), 23);
        assert_eq!(names.len(), 23);
        assert!(names.iter().all(|name| name.starts_with("tide.")));
    }

    #[test]
    fn origins_add_up() {
        let count = |origin| ALL.iter().filter(|key| key.origin == origin).count();
        assert_eq!(count(Origin::Field), 9);
        assert_eq!(count(Origin::Pipeline), 4);
        assert_eq!(count(Origin::ReadOnly), 6);
        assert_eq!(count(Origin::Lookup), 1);
        assert_eq!(count(Origin::VocabularyEntry), 3);
    }
}
