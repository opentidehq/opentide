//! Dispatch: `metadata.schema` selects the revision, then that revision's
//! conversion and checks run (`loading/object_loader.py`
//! `load_object_for_validation`, ADR 0009).
//!
//! | `metadata.schema` | Result |
//! | --- | --- |
//! | absent, `null` or empty (Python's falsy values) | [`Rejection::SchemaMissing`] |
//! | a registered revision of the expected family | [`Selection::Registered`]: that revision's model |
//! | another family's registered object revision | [`Rejection::OtherFamily`] |
//! | an unregistered revision of the expected family (`rule::7.0`, `Rule::1.1`) | [`Selection::Unknown`]: the family's newest model without the unknown-key check, and an error at `metadata.schema` |
//! | anything else | [`Rejection::Unknown`] |
//!
//! The oracle rejected every unregistered identifier before any model ran
//! (`unknown schema identifier`); the language server checked an unknown
//! revision against the family's newest. The registry takes the language
//! server's policy, keeping the error so the object still fails
//! (`tests/oracle/objects_cases.toml`, `unknown-revision`).

use serde::Serialize;

use super::{Kind, Revision, SchemaId, lookup, newest};
use crate::error::{ErrorKind, codes};
use crate::from_node::{self, messages};
use crate::node::{Document, Node, Value};
use crate::objects::{ObjectiveV1_0, RuleV1_0, RuleV1_1, ThreatVectorV1_0};
use crate::{PathSegment, SchemaError};

/// One Tide object, as the revision its `metadata.schema` names.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TideObject {
    /// `rule::1.0`.
    RuleV1_0(Box<RuleV1_0>),
    /// `rule::1.1`.
    RuleV1_1(Box<RuleV1_1>),
    /// `threat::1.0`.
    ThreatV1_0(Box<ThreatVectorV1_0>),
    /// `objective::1.0`.
    ObjectiveV1_0(Box<ObjectiveV1_0>),
}

impl TideObject {
    /// The revision's identifier.
    pub fn schema_identifier(&self) -> &'static str {
        match self {
            Self::RuleV1_0(_) => RuleV1_0::SCHEMA_IDENTIFIER,
            Self::RuleV1_1(_) => RuleV1_1::SCHEMA_IDENTIFIER,
            Self::ThreatV1_0(_) => ThreatVectorV1_0::SCHEMA_IDENTIFIER,
            Self::ObjectiveV1_0(_) => ObjectiveV1_0::SCHEMA_IDENTIFIER,
        }
    }

    /// The revision, from the registry.
    #[expect(
        clippy::expect_used,
        reason = "every variant's identifier is registered: revisions::tests::every_object_revision_has_a_struct_and_every_struct_a_revision"
    )]
    pub fn revision(&self) -> &'static Revision {
        lookup(self.schema_identifier()).expect("a registered revision")
    }
}

/// Which revision checks a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// `metadata.schema` names this registered revision.
    Registered(&'static Revision),
    /// `metadata.schema` names a revision of the expected family that the
    /// registry does not hold: the family's newest revision checks it, without
    /// the unknown-key check.
    Unknown {
        /// The identifier as written.
        written: String,
        /// The family's newest revision.
        newest: &'static Revision,
    },
}

impl Selection {
    /// The revision whose model runs.
    pub fn revision(&self) -> &'static Revision {
        match self {
            Self::Registered(revision)
            | Self::Unknown {
                newest: revision, ..
            } => revision,
        }
    }
}

/// Why no model ran: the loader's verdict, before any conversion.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Rejection {
    /// No `metadata.schema` (`SchemaMissingError`, `schema_missing`).
    #[error("missing metadata.schema on object")]
    SchemaMissing,
    /// `metadata` is not a mapping: the oracle's `dict_type` error at
    /// `metadata`, placed.
    #[error("{}", .0.message)]
    MetadataNotAMapping(Box<SchemaError>),
    /// A registered object revision of another family.
    #[error("'{identifier}' is not a {family} schema identifier")]
    OtherFamily {
        /// The identifier as written.
        identifier: String,
        /// The family expected.
        family: String,
    },
    /// An identifier that is neither registered nor a revision of the expected
    /// family.
    #[error("unknown schema identifier: '{identifier}'")]
    Unknown {
        /// The identifier as written.
        identifier: String,
    },
    /// The expected family has no object model.
    #[error("no registered schema for family '{family}'")]
    NoModel {
        /// The family asked for.
        family: String,
    },
    /// A rule cannot be read until its platform blocks have models (UC-1.4,
    /// #810): only with the `unchecked-platform-blocks` feature.
    #[error("'{identifier}': the platform blocks of a rule have no models yet (UC-1.4)")]
    Unchecked {
        /// The rule's identifier.
        identifier: &'static str,
    },
}

impl Rejection {
    /// The CLI's diagnostic code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaMissing => codes::SCHEMA_MISSING,
            _ => codes::SCHEMA_VALIDATION,
        }
    }
}

/// A document read through the registry: the revision that checked it, and
/// the object or every error.
#[derive(Debug, Clone, PartialEq)]
pub struct Read {
    /// The revision that checked it.
    pub selection: Selection,
    /// The object, or every error, placed.
    pub result: Result<TideObject, Vec<SchemaError>>,
}

/// Python's truthiness of a YAML value (`body.get("metadata") or {}`,
/// `if not schema_id`).
fn falsy(node: &Node) -> bool {
    match &node.value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Int(integer) => *integer == 0,
        Value::Float(float) => *float == 0.0,
        Value::Str(text) | Value::Datetime(text) => text.is_empty(),
        Value::Seq(items) => items.is_empty(),
        Value::Map(entries) => entries.is_empty(),
    }
}

/// The revision `metadata.schema` selects for an object of `family`
/// (`rule`, `threat`, `objective`).
pub fn select(document: &Document, family: &str) -> Result<Selection, Rejection> {
    let family = family.trim().to_lowercase();
    let Some(newest) = newest(&family).filter(|revision| revision.kind == Kind::Object) else {
        return Err(Rejection::NoModel { family });
    };
    let metadata = document
        .root()
        .and_then(|root| root.get("metadata"))
        .filter(|metadata| !falsy(metadata));
    let Some(metadata) = metadata else {
        return Err(Rejection::SchemaMissing);
    };
    if !matches!(metadata.value, Value::Map(_)) {
        return Err(Rejection::MetadataNotAMapping(Box::new(metadata_type(
            document, metadata,
        ))));
    }
    let Some(schema) = metadata.get("schema").filter(|schema| !falsy(schema)) else {
        return Err(Rejection::SchemaMissing);
    };
    let written = match &schema.value {
        Value::Str(text) => text.clone(),
        other => other.to_string(),
    };
    if let Some(revision) = lookup(&written).filter(|revision| revision.in_object_registry()) {
        return if revision.id().family() == family {
            Ok(Selection::Registered(revision))
        } else {
            Err(Rejection::OtherFamily {
                identifier: written,
                family,
            })
        };
    }
    match SchemaId::parse(&written) {
        Ok(id) if id.family() == family => Ok(Selection::Unknown { written, newest }),
        _ => Err(Rejection::Unknown {
            identifier: written,
        }),
    }
}

/// The `dict_type` error at `metadata`, placed as the conversion places one.
fn metadata_type(document: &Document, metadata: &Node) -> SchemaError {
    let mut error = SchemaError::new(
        ErrorKind::InvalidType("dict_type"),
        vec![PathSegment::Key("metadata".to_owned())],
        messages::DICT_TYPE,
    );
    error.input = metadata.value.as_str().map(str::to_owned);
    let locator = document.locator();
    let path = error.field_path();
    error.span = locator.span(&path, false);
    error.yaml_line = locator.yaml_line(&path);
    error
}

/// Reads `document` as an object of `family`: [`select`], then the selected
/// revision's conversion. For [`Selection::Unknown`], the newest revision's
/// conversion runs, its unknown-key errors are dropped, and the error at
/// `metadata.schema` says which revision checked the object.
pub fn read(document: &Document, family: &str) -> Result<Read, Rejection> {
    let selection = select(document, family)?;
    let mut result = convert(selection.revision(), document)?;
    if let Selection::Unknown { written, newest } = &selection
        && let Err(errors) = &mut result
    {
        errors.retain(|error| error.kind != ErrorKind::UnknownKey);
        for error in errors.iter_mut() {
            if error.kind == ErrorKind::InvalidValue("value_error")
                && error.field_path() == ["metadata", "schema"]
            {
                let text = format!(
                    "unknown schema identifier: '{written}'; checked against {}, the newest {} \
                     revision, without the unknown-key check",
                    newest.identifier,
                    newest.id().family()
                );
                error.message = format!("Value error, {text}");
                error.context.insert("error".to_owned(), text);
            }
        }
    }
    Ok(Read { selection, result })
}

/// The conversion of one registered object revision.
fn convert(
    revision: &'static Revision,
    document: &Document,
) -> Result<Result<TideObject, Vec<SchemaError>>, Rejection> {
    fn boxed<T>(
        result: Result<T, Vec<SchemaError>>,
        wrap: fn(Box<T>) -> TideObject,
    ) -> Result<TideObject, Vec<SchemaError>> {
        result.map(|value| wrap(Box::new(value)))
    }
    Ok(match revision.identifier {
        ThreatVectorV1_0::SCHEMA_IDENTIFIER => boxed(
            from_node::from_document::<ThreatVectorV1_0>(document),
            TideObject::ThreatV1_0,
        ),
        ObjectiveV1_0::SCHEMA_IDENTIFIER => boxed(
            from_node::from_document::<ObjectiveV1_0>(document),
            TideObject::ObjectiveV1_0,
        ),
        #[cfg(any(test, feature = "unchecked-platform-blocks"))]
        RuleV1_0::SCHEMA_IDENTIFIER => boxed(
            from_node::from_document::<RuleV1_0>(document),
            TideObject::RuleV1_0,
        ),
        #[cfg(any(test, feature = "unchecked-platform-blocks"))]
        RuleV1_1::SCHEMA_IDENTIFIER => boxed(
            from_node::from_document::<RuleV1_1>(document),
            TideObject::RuleV1_1,
        ),
        #[cfg(not(any(test, feature = "unchecked-platform-blocks")))]
        identifier @ (RuleV1_0::SCHEMA_IDENTIFIER | RuleV1_1::SCHEMA_IDENTIFIER) => {
            return Err(Rejection::Unchecked { identifier });
        }
        _ => {
            return Err(Rejection::NoModel {
                family: revision.id().family().to_owned(),
            });
        }
    })
}
