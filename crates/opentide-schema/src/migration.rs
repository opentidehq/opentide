//! Forward migrations between revisions (UC-1.7, #813; ADR 0009).
//!
//! Each family's revisions form a chain, oldest to newest
//! ([`crate::revisions::revisions_of`]). Each edge is a one-step `From` impl
//! (`From<RuleV1_0> for RuleV1_1`), and [`TideObject::step`] takes the one
//! edge out of a revision. [`TideObject::migrate_to`] walks the chain as
//! `SchemaVersionChain.migrate` does, and [`path`] lists it as
//! `SchemaVersionChain.path` does. Migration is in memory: the catalogue and
//! the compilers read [`TideObject::into_newest`]; only `opentide migrate`
//! changes a file, with span-based text edits (UC-3.5).
//!
//! A migrated object carries its new revision's identifier in
//! `metadata.schema`, as `stamp_schema_identifier` sets it after a migration;
//! [`stamp_schema_identifier`] is that function on an untyped document.
//!
//! The oracle registered no migration (its chains were empty, so loading a
//! `rule::1.0` object as `rule::1.1` raised `no migration registered`): the
//! steps here are new, and no command runs them yet.

use std::sync::Arc;

use crate::node::{Entry, Mark, Node, Value};
use crate::objects::{ObjectMetadata, RuleMetadata, RuleV1_0, RuleV1_1};
use crate::revisions::{Revision, SchemaId, TideObject, lookup, revisions_of};

/// Why a migration cannot run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationError {
    /// The identifier names no registered revision.
    #[error("unknown schema identifier: '{0}'")]
    Unregistered(String),
    /// Source and target are of different families.
    #[error("cannot migrate across families: '{source_id}' -> '{target}'")]
    CrossFamily {
        /// The source revision.
        source_id: String,
        /// The target revision.
        target: String,
    },
    /// The target is older than the source.
    #[error("cannot migrate backwards: '{source_id}' -> '{target}'")]
    Backwards {
        /// The source revision.
        source_id: String,
        /// The target revision.
        target: String,
    },
    /// No step leaves a revision older than the target.
    #[error("no migration registered from {0}")]
    NoStep(String),
}

impl From<RuleV1_0> for RuleV1_1 {
    /// `rule::1.0` to `rule::1.1`: the metadata gains the optional
    /// `reviewed`, left unset; every other field is the same.
    fn from(rule: RuleV1_0) -> Self {
        // Every field by name, with no `..`: a field added to either revision
        // fails to compile here until this step says what it becomes.
        let RuleV1_0 {
            name,
            metadata,
            description,
            status,
            severity,
            techniques,
            platforms,
            references,
            detection_model,
            response,
            configurations,
            file,
        } = rule;
        let ObjectMetadata {
            uuid,
            schema_id: _,
            version,
            created,
            modified,
            tlp,
            author,
            contributors,
            organisation,
        } = metadata;
        Self {
            name,
            metadata: RuleMetadata {
                uuid,
                schema_id: Self::SCHEMA_IDENTIFIER.to_owned(),
                version,
                created,
                modified,
                tlp,
                author,
                contributors,
                organisation,
                reviewed: None,
            },
            description,
            status,
            severity,
            techniques,
            platforms,
            references,
            detection_model,
            response,
            configurations,
            file,
        }
    }
}

impl TideObject {
    /// One step forward along the family's chain: `Ok` with the next
    /// revision, or `Err` with the object unchanged when its revision is the
    /// family's newest.
    pub fn step(self) -> Result<Self, Self> {
        match self {
            Self::RuleV1_0(rule) => Ok(Self::RuleV1_1(Box::new(RuleV1_1::from(*rule)))),
            newest @ (Self::RuleV1_1(_) | Self::ThreatV1_0(_) | Self::ObjectiveV1_0(_)) => {
                Err(newest)
            }
        }
    }

    /// The object as the revision `target` names, one step at a time
    /// (`SchemaVersionChain.migrate`). The target must be registered, of the
    /// same family and not older; its own revision returns the object as it
    /// is.
    pub fn migrate_to(self, target: &str) -> Result<Self, MigrationError> {
        let source = self.revision();
        let target = registered(target)?;
        check_direction(source, target)?;
        let goal = target.id();
        let mut current = self;
        while current.revision().id() < goal {
            let from = current.schema_identifier();
            current = current
                .step()
                .map_err(|_| MigrationError::NoStep(from.to_owned()))?;
        }
        if current.revision().id() == goal {
            Ok(current)
        } else {
            Err(MigrationError::NoStep(source.identifier.to_owned()))
        }
    }

    /// The object as its family's newest revision: every step, in memory.
    pub fn into_newest(self) -> Self {
        let mut current = self;
        loop {
            match current.step() {
                Ok(next) => current = next,
                Err(newest) => return newest,
            }
        }
    }
}

/// The revisions a migration from `source` to `target` passes through, both
/// included (`SchemaVersionChain.path`).
pub fn path(source: &str, target: &str) -> Result<Vec<&'static Revision>, MigrationError> {
    let source = registered(source)?;
    let target = registered(target)?;
    check_direction(source, target)?;
    let (from, to) = (source.id(), target.id());
    Ok(revisions_of(from.family())
        .into_iter()
        .filter(|revision| {
            let id = revision.id();
            from <= id && id <= to
        })
        .collect())
}

fn registered(identifier: &str) -> Result<&'static Revision, MigrationError> {
    lookup(identifier).ok_or_else(|| MigrationError::Unregistered(identifier.to_owned()))
}

fn check_direction(source: &Revision, target: &Revision) -> Result<(), MigrationError> {
    let (from, to): (SchemaId, SchemaId) = (source.id(), target.id());
    if from.family() != to.family() {
        return Err(MigrationError::CrossFamily {
            source_id: source.identifier.to_owned(),
            target: target.identifier.to_owned(),
        });
    }
    if from > to {
        return Err(MigrationError::Backwards {
            source_id: source.identifier.to_owned(),
            target: target.identifier.to_owned(),
        });
    }
    Ok(())
}

/// `root` with `metadata.schema` set to `schema_id`
/// (`models/migration.py` `stamp_schema_identifier`): an empty identifier
/// changes nothing; a `metadata` mapping keeps its other keys and their
/// order, `schema` staying where it was or coming last; any other
/// `metadata` becomes `{schema: <id>}` in its place, and a missing one is
/// added last. A root that is not a mapping is returned as it is (the
/// oracle's `dict()` of it failed).
pub fn stamp_schema_identifier(root: &Node, schema_id: &str) -> Node {
    let Value::Map(entries) = &root.value else {
        return root.clone();
    };
    if schema_id.is_empty() {
        return root.clone();
    }
    let schema = Entry {
        key: text("schema"),
        value: text(schema_id),
    };
    let stamped_metadata = |metadata: &Node| -> Arc<Node> {
        let entries = match &metadata.value {
            Value::Map(entries) => set(entries, schema.clone()),
            _ => vec![schema.clone()],
        };
        Arc::new(Node {
            value: Value::Map(entries),
            start: metadata.start,
            end: metadata.end,
            text: None,
        })
    };
    let entries = match entries
        .iter()
        .position(|entry| entry.key.value.as_str() == Some("metadata"))
    {
        Some(index) => {
            let mut entries = entries.clone();
            entries[index].value = stamped_metadata(&entries[index].value);
            entries
        }
        None => {
            let mut entries = entries.clone();
            entries.push(Entry {
                key: text("metadata"),
                value: Arc::new(Node {
                    value: Value::Map(vec![schema]),
                    start: Mark::default(),
                    end: Mark::default(),
                    text: None,
                }),
            });
            entries
        }
    };
    Node {
        value: Value::Map(entries),
        start: root.start,
        end: root.end,
        text: None,
    }
}

/// `entries` with `entry`'s key set: replaced in place, or appended.
fn set(entries: &[Entry], entry: Entry) -> Vec<Entry> {
    let mut entries = entries.to_vec();
    match entries
        .iter_mut()
        .find(|existing| existing.key.value.as_str() == entry.key.value.as_str())
    {
        Some(existing) => existing.value = entry.value,
        None => entries.push(entry),
    }
    entries
}

fn text(value: &str) -> Arc<Node> {
    Arc::new(Node {
        value: Value::Str(value.to_owned()),
        start: Mark::default(),
        end: Mark::default(),
        text: None,
    })
}

pub mod vocab_scope;

#[cfg(test)]
mod tests;
