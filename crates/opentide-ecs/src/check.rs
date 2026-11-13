//! What the Elastic query engines need to check a query against ECS, once the
//! caller knows the query reads ECS indices ([`indices_are_ecs`]): a field's
//! type ([`field_type`]), whether a literal can be a term of that type
//! ([`value_problem`]), and whether an unknown name is a near miss of an ECS
//! field ([`unknown_field`]).
//!
//! ECS stays an open list: a field outside it is a warning only when it sits
//! under an ECS field set and is a near miss of an ECS field, so the check
//! reads as a typo detector. Custom fields (`labels.*`, objects, flattened
//! fields, Elastic Defend's `*.Ext.*`) and integration namespaces
//! (`azure.*`, `okta.*`, `winlog.*`) are never checked.

use crate::{field, fields, version, with_prefix};
use opentide_core::datasets::{self, DatasetKind};
use opentide_core::{Diagnostic, Range, Severity, codes};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::OnceLock;

/// What Elasticsearch can do with a field of a type, in a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    /// `keyword`, `constant_keyword`, `wildcard`, `text`, `match_only_text`.
    String,
    /// `long`, `integer`, `float`, `scaled_float`, and the other numbers.
    Numeric,
    Ip,
    /// `date`, `date_nanos`.
    Date,
    Boolean,
}

impl ValueType {
    /// The ECS (or Elasticsearch mapping) type name's class; `None` for
    /// types whose query behaviour is not checked (`object`, `nested`,
    /// `flattened`, `geo_point`, ...).
    pub fn of(type_name: &str) -> Option<Self> {
        Some(match type_name {
            "keyword" | "constant_keyword" | "wildcard" | "text" | "match_only_text" => {
                Self::String
            }
            "long" | "integer" | "short" | "byte" | "unsigned_long" | "double" | "float"
            | "half_float" | "scaled_float" => Self::Numeric,
            "ip" => Self::Ip,
            "date" | "date_nanos" => Self::Date,
            "boolean" => Self::Boolean,
            _ => return None,
        })
    }

    /// An ES|QL parameter type's class (`keyword`, `long`, `ip`, ...).
    pub fn of_esql(type_name: &str) -> Option<Self> {
        Some(match type_name {
            "keyword" | "text" => Self::String,
            "integer" | "long" | "double" | "unsigned_long" | "float" | "counter_integer"
            | "counter_long" | "counter_double" => Self::Numeric,
            "ip" => Self::Ip,
            "date" | "date_nanos" => Self::Date,
            "boolean" => Self::Boolean,
            _ => return None,
        })
    }
}

/// The Elasticsearch field types `visibility.toml` columns may have, so a
/// declared type can be named with the catalog's `'static` strings.
const ELASTIC_TYPES: &[&str] = &[
    "binary",
    "boolean",
    "byte",
    "constant_keyword",
    "date",
    "date_nanos",
    "double",
    "flattened",
    "float",
    "geo_point",
    "half_float",
    "integer",
    "ip",
    "keyword",
    "long",
    "match_only_text",
    "nested",
    "object",
    "scaled_float",
    "short",
    "text",
    "unsigned_long",
    "version",
    "wildcard",
];

/// Declared field name to declared type.
type Fields = Rc<BTreeMap<String, Option<String>>>;

thread_local! {
    /// The fields the workspace declares for the indices of the query being
    /// checked ([`with_declared_fields`]): name to declared type.
    static DECLARED: RefCell<Option<Fields>> =
        const { RefCell::new(None) };
}

/// The columns elastic log sources in `visibility.toml` list for the indices
/// a query reads (`index` names, `FROM` patterns): those of every declared
/// index a read name or pattern covers, or that covers it. A comma-separated
/// entry is split; exclusions (`-x*`), a `::` selector and a cross-cluster
/// prefix are dropped. Columns on a pattern (`logs-custom.*`) apply to every
/// index it matches. Where several log sources declare a field, an exact
/// name's declaration wins over a pattern's, and an earlier one over a
/// later one.
pub fn declared_fields<S: AsRef<str>>(indices: &[S]) -> BTreeMap<String, Option<String>> {
    let datasets = datasets::current();
    let read: Vec<&str> = indices
        .iter()
        .flat_map(|i| i.as_ref().split(','))
        .map(str::trim)
        .filter(|n| !n.is_empty() && !n.starts_with('-'))
        .map(|n| n.split_once("::").map_or(n, |(n, _)| n))
        .map(|n| n.rsplit_once(':').map_or(n, |(_, n)| n))
        .collect();
    let mut out = BTreeMap::new();
    let mut sources: Vec<_> = datasets.sources_with_columns("elastic").collect();
    sources.sort_by_key(|s| s.name.contains('*'));
    for source in sources {
        if !read
            .iter()
            .any(|r| DatasetKind::Indices.covers(&source.name, r))
        {
            continue;
        }
        for column in &source.columns {
            out.entry(column.name.clone())
                .or_insert_with(|| column.type_name.clone());
        }
    }
    out
}

/// Run `f`, the ECS checks of a query that reads `indices`, with the fields
/// the workspace declares for them ([`declared_fields`]) counted as mapped:
/// [`unknown_field`] never reports one, and [`field_type`] gives its declared
/// type (#146).
pub fn with_declared_fields<S: AsRef<str>, R>(indices: &[S], f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Fields>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            DECLARED.with(|d| *d.borrow_mut() = previous);
        }
    }
    let fields = declared_fields(indices);
    let previous = DECLARED.with(|d| d.borrow_mut().replace(Rc::new(fields)));
    let _restore = Restore(previous);
    f()
}

/// The declared type of `name` in the current scope: `None` when the field
/// is not declared, `Some(None)` when it is, with a type the checks do not
/// know.
#[expect(
    clippy::option_option,
    reason = "three answers, as documented above: not declared, declared with an unknown type, declared with a known one"
)]
fn declared_type(name: &str) -> Option<Option<&'static str>> {
    DECLARED.with(|d| {
        let fields = d.borrow();
        let type_name = fields.as_ref()?.get(name)?;
        Some(
            type_name
                .as_deref()
                .and_then(|t| ELASTIC_TYPES.iter().find(|k| **k == t).copied()),
        )
    })
}

/// Multi-field suffixes ECS and Elastic integrations add under a field:
/// `.text` (ECS), `.keyword`, and Elastic Defend's `.caseless`.
const MULTI_FIELDS: &[&str] = &["text", "keyword", "caseless"];

/// The ECS type a query's field name reads: the field's own, or for a
/// multi-field of a string field (`process.name.caseless`) a string. `None`
/// for a field outside ECS, a multi-field of a non-string field, or a type
/// that is not checked.
pub fn field_type(name: &str) -> Option<(ValueType, &'static str)> {
    if let Some(declared) = declared_type(name) {
        let type_name = declared?;
        return ValueType::of(type_name).map(|t| (t, type_name));
    }
    if let Some((parent, suffix)) = name.rsplit_once('.')
        && MULTI_FIELDS.contains(&suffix)
        && let Some(declared) = declared_type(parent)
    {
        return declared
            .filter(|t| ValueType::of(t) == Some(ValueType::String))
            .map(|t| (ValueType::String, t));
    }
    if let Some(f) = field(name) {
        return ValueType::of(&f.type_name).map(|t| (t, f.type_name.as_str()));
    }
    let (parent, suffix) = name.rsplit_once('.')?;
    if !MULTI_FIELDS.contains(&suffix) {
        return None;
    }
    let parent = field(parent)?;
    (ValueType::of(&parent.type_name) == Some(ValueType::String))
        .then_some((ValueType::String, parent.type_name.as_str()))
}

/// Whether `name` is an object in ECS (a field set such as `host`, or an
/// `object` field such as `labels`) rather than a field that holds a value.
pub fn is_object(name: &str) -> bool {
    if let Some(declared) = declared_type(name) {
        return matches!(declared, Some("object" | "nested" | "flattened"));
    }
    match field(name) {
        Some(f) => f.type_name == "object",
        None => !with_prefix(&format!("{name}.")).is_empty(),
    }
}

/// Top-level ECS field sets (`process`, `source`, `host`, ...): names with
/// fields under them. Top-level fields (`message`, `tags`, `@timestamp`) and
/// `labels` (custom by design) are not field sets.
fn field_sets() -> &'static BTreeSet<&'static str> {
    static SETS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SETS.get_or_init(|| {
        fields()
            .iter()
            .filter_map(|f| f.name.split_once('.').map(|(root, _)| root))
            .filter(|root| *root != "labels")
            .collect()
    })
}

/// The ECS field `name` most likely meant, when `name` is not in ECS, sits
/// under an ECS field set, is not under a custom-allowed object, and is a
/// near miss of an ECS field (`process.nmae` → `process.name`). `None`
/// otherwise: ECS allows custom fields, so only a near miss is reported.
pub fn unknown_field(name: &str) -> Option<String> {
    // A field the workspace declares is mapped, and so are its multi-fields.
    if declared_type(name).is_some()
        || name
            .rsplit_once('.')
            .is_some_and(|(parent, s)| MULTI_FIELDS.contains(&s) && declared_type(parent).is_some())
    {
        return None;
    }
    // `process.nmae.caseless`: the near miss is in the parent.
    if let Some((parent, suffix)) = name.rsplit_once('.')
        && MULTI_FIELDS.contains(&suffix)
        && field(name).is_none()
        && field(parent).is_none()
    {
        return near_miss(parent).map(|p| format!("{p}.{suffix}"));
    }
    near_miss(name).map(str::to_string)
}

fn near_miss(name: &str) -> Option<&'static str> {
    if name.is_empty()
        || name.contains(['*', '?', '[', ' '])
        || name.starts_with('.')
        || name.ends_with('.')
        || field(name).is_some()
        || field_type(name).is_some()
    {
        return None;
    }
    let (root, _) = name.split_once('.')?;
    if !field_sets().contains(root) {
        return None;
    }
    let segments: Vec<&str> = name.split('.').collect();
    // Elastic Defend's extension namespace (`process.Ext.*`, `file.Ext.*`).
    if segments.contains(&"Ext") {
        return None;
    }
    // Under an object, flattened, or nested field, any child is custom. Under
    // a leaf, the name is a multi-field ECS does not list.
    if (1..segments.len()).any(|end| field(&segments[..end].join(".")).is_some()) {
        return None;
    }
    // Whether a near miss is reported at all is this check's threshold
    // (strsim's optimal string alignment distance, a swapped pair one edit);
    // among the fields within it, the shared rule chooses
    // ([`opentide_core::suggest::best`]).
    let limit = if name.len() >= 16 { 2 } else { 1 };
    let near = with_prefix(&format!("{root}."))
        .iter()
        .filter(|candidate| candidate.name.len().abs_diff(name.len()) <= limit)
        .map(|candidate| candidate.name.as_str())
        .filter(|candidate| strsim::osa_distance(candidate, name) <= limit);
    opentide_core::suggest::best(name, near)
}

/// `ecs_unknown_field` (warning) for `name` at `range`, when
/// [`unknown_field`] finds the ECS field it most likely meant. `range` is
/// computed only then: a range costs a scan of the source, and a query can
/// name thousands of fields.
pub fn unknown_field_diagnostic(name: &str, range: impl FnOnce() -> Range) -> Option<Diagnostic> {
    let suggestion = unknown_field(name)?;
    let range = range();
    Some(
        Diagnostic::warning(
            codes::ECS_UNKNOWN_FIELD,
            format!(
                "`{name}` is not an ECS {} field; did you mean `{suggestion}`? (ECS allows custom fields, so this is a warning)",
                version()
            ),
            range,
        )
        .with_suggestion(suggestion),
    )
}

/// `ecs_type_mismatch` (error): `name`, an ECS field of `type_name`, cannot
/// take `what` (`a wildcard`, `LIKE`, ...).
pub fn type_mismatch(name: &str, type_name: &str, what: &str, range: Range) -> Diagnostic {
    let parent = name
        .rsplit_once('.')
        .filter(|(_, s)| MULTI_FIELDS.contains(s))
        .map(|(p, _)| p);
    let source =
        if declared_type(name).is_some() || parent.is_some_and(|p| declared_type(p).is_some()) {
            "visibility.toml".to_string()
        } else {
            format!("ECS {}", version())
        };
    Diagnostic::error(
        codes::ECS_TYPE_MISMATCH,
        format!(
            "`{name}` is a `{type_name}` field in {source}: Elasticsearch rejects {what} on it"
        ),
        range,
    )
}

/// Why `value`, a literal compared with a field of `value_type`, cannot be
/// one of its terms; `None` when it can, or when that is not certain.
/// Elasticsearch fails the query (`failed to create query`) for such a term.
pub fn value_problem(value_type: ValueType, value: &str) -> Option<&'static str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    match value_type {
        ValueType::String => None,
        ValueType::Numeric => value.parse::<f64>().is_err().then_some("is not a number"),
        ValueType::Ip => {
            if is_ip_or_cidr(value) {
                return None;
            }
            let shaped = value
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/' | '%'));
            // An address with leading zeros or a zone id may be accepted by
            // Elasticsearch's parser and not by Rust's: only a value that
            // cannot be an address at all is reported.
            (!shaped || !value.contains(['.', ':'])).then_some("is not an IP address or CIDR block")
        }
        // Date formats and date math are many; only a value with no digit
        // that is not date math (`now`, `now/d`) is certainly not a date.
        ValueType::Date => (!value.bytes().any(|b| b.is_ascii_digit())
            && !value.to_ascii_lowercase().starts_with("now"))
        .then_some("is not a date"),
        ValueType::Boolean => (!value.eq_ignore_ascii_case("true")
            && !value.eq_ignore_ascii_case("false"))
        .then_some("is not true or false"),
    }
}

fn is_ip_or_cidr(value: &str) -> bool {
    let (address, prefix) = match value.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (value, None),
    };
    let Ok(ip) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    match prefix {
        None => true,
        Some(p) => p
            .parse::<u8>()
            .is_ok_and(|p| p <= if ip.is_ipv4() { 32 } else { 128 }),
    }
}

/// Whether one index name or pattern, as a rule or `FROM` names it, holds ECS
/// documents: an integration data stream (`logs-*`, `logs-endpoint.events.*`).
/// A cross-cluster prefix (`remote:`) is ignored; the failure store
/// (`::failures`) is not ECS.
pub fn is_ecs_index(name: &str) -> bool {
    let name = name.trim();
    let (name, selector) = match name.split_once("::") {
        Some((n, s)) => (n, Some(s)),
        None => (name, None),
    };
    if selector.is_some_and(|s| s != "data") {
        return false;
    }
    let name = name.rsplit_once(':').map_or(name, |(_, n)| n);
    name.starts_with("logs-")
}

/// Whether every index a query reads holds ECS documents: at least one name,
/// and each one ([`is_ecs_index`]) ECS. Exclusions (`-logs-test*`) only
/// narrow the set. A comma-separated entry is split.
pub fn indices_are_ecs<S: AsRef<str>>(indices: &[S]) -> bool {
    let names: Vec<&str> = indices
        .iter()
        .flat_map(|i| i.as_ref().split(','))
        .map(str::trim)
        .filter(|n| !n.is_empty() && !n.starts_with('-'))
        .collect();
    !names.is_empty() && names.iter().all(|n| is_ecs_index(n))
}

/// `elastic_dataset_not_declared` (warning) for an index name or pattern a
/// rule or `FROM` reads, when the workspace has elastic log sources and no
/// `name` of one covers or reaches it. Opt-in: a workspace with no elastic
/// log source gets nothing. An exclusion (`-logs-test*`) only narrows, and the `::data`
/// or `::failures` selector reads the same index.
pub fn index_not_declared(name: &str, range: Range) -> Option<Diagnostic> {
    let name = name.trim();
    if name.is_empty() || name.starts_with('-') {
        return None;
    }
    let bare = name.split_once("::").map_or(name, |(n, _)| n);
    let status = datasets::current().status("elastic", bare);
    (status == datasets::Declaration::Undeclared).then(|| {
        Diagnostic::warning(
            codes::ELASTIC_DATASET_NOT_DECLARED,
            format!(
                "index pattern `{bare}` is not declared: no elastic log source in visibility.toml names it or a pattern that covers it"
            ),
            range,
        )
    })
}

fn overlaps(a: Range, b: Range) -> bool {
    let key = |p: opentide_core::Position| (p.line, p.character);
    key(a.start) < key(b.end) && key(b.start) < key(a.end) || a == b
}

/// Add the ECS diagnostics to an engine's own. An ECS error where the engine
/// already reports an error says the same thing and is dropped; the
/// engine's hints at an ECS error (a type the engine could only suspect)
/// give way to it.
pub fn merge(found: &mut Vec<Diagnostic>, ecs: Vec<Diagnostic>) {
    for d in ecs {
        if d.severity == Severity::Error {
            if found
                .iter()
                .any(|f| f.severity == Severity::Error && overlaps(f.range, d.range))
            {
                continue;
            }
            found.retain(|f| !(f.severity == Severity::Hint && overlaps(f.range, d.range)));
        }
        if !found
            .iter()
            .any(|f| f.code == d.code && f.range == d.range && f.message == d.message)
        {
            found.push(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_fields_are_mapped_with_their_type() {
        // The only test in this crate that installs datasets.
        datasets::install(Some(
            datasets::DeclaredDatasets::from_visibility(
                r#"
[[logsources]]
name = "logs-custom.app-*"
description = "Custom app."
system = "elastic"

[logsources.columns]
"process.custom_flag" = { type = "boolean" }
"process.pid" = { type = "keyword" }
"process.nmae" = { type = "keyword" }
"#,
            )
            .unwrap(),
        ));
        assert_eq!(
            unknown_field("process.nmae").as_deref(),
            Some("process.name")
        );
        assert_eq!(field_type("process.pid").unwrap().0, ValueType::Numeric);
        for indices in [
            &["logs-custom.app-default"][..],
            &["logs-custom.*"],
            &["remote:logs-custom.app-x::data"],
        ] {
            with_declared_fields(indices, || {
                assert_eq!(unknown_field("process.nmae"), None);
                assert_eq!(unknown_field("process.nmae.keyword"), None);
                assert_eq!(
                    field_type("process.custom_flag"),
                    Some((ValueType::Boolean, "boolean"))
                );
                // The declared type replaces ECS's.
                assert_eq!(
                    field_type("process.pid"),
                    Some((ValueType::String, "keyword"))
                );
                let d = type_mismatch("process.pid", "keyword", "x", Range::point(0, 0));
                assert!(d.message.contains("in visibility.toml"), "{}", d.message);
            });
        }
        // Another index's fields are not declared, and the scope ends.
        with_declared_fields(&["logs-other-*"], || {
            assert_eq!(
                unknown_field("process.nmae").as_deref(),
                Some("process.name")
            );
        });
        assert_eq!(field_type("process.pid").unwrap().0, ValueType::Numeric);
        datasets::install(None);
    }

    #[test]
    fn types_and_multi_fields() {
        assert_eq!(
            field_type("source.ip"),
            Some((ValueType::Ip, "ip")),
            "ip field"
        );
        assert_eq!(field_type("process.pid").unwrap().0, ValueType::Numeric);
        assert_eq!(field_type("@timestamp").unwrap().0, ValueType::Date);
        assert_eq!(
            field_type("process.command_line.text").unwrap().0,
            ValueType::String
        );
        assert_eq!(
            field_type("process.name.caseless").unwrap().0,
            ValueType::String
        );
        assert_eq!(
            field_type("process.executable.keyword").unwrap().0,
            ValueType::String
        );
        // A multi-field of a non-string field is not typed.
        assert_eq!(field_type("process.pid.keyword"), None);
        assert_eq!(field_type("azure.signinlogs.properties.x"), None);
        assert!(is_object("host") && is_object("process.parent") && is_object("labels"));
        assert!(!is_object("host.name") && !is_object("custom"));
    }

    #[test]
    fn unknown_fields_are_near_misses_under_field_sets() {
        let suggest = |name: &str| unknown_field(name);
        assert_eq!(suggest("process.nmae").as_deref(), Some("process.name"));
        assert_eq!(suggest("process.Name").as_deref(), Some("process.name"));
        assert_eq!(
            suggest("process.parent.executabel").as_deref(),
            Some("process.parent.executable")
        );
        assert_eq!(
            suggest("process.nmae.caseless").as_deref(),
            Some("process.name.caseless")
        );
        // In ECS, a known multi-field, or a multi-field of a known field.
        for name in [
            "process.name",
            "process.command_line.text",
            "process.name.caseless",
            "file.path.keyword",
        ] {
            assert_eq!(unknown_field(name), None, "{name}");
        }
        // Custom fields ECS allows, integration namespaces, wildcards,
        // Elastic Defend's `Ext`, and names far from any ECS field.
        for name in [
            "labels.team",
            "container.labels.app",
            "azure.signinlogs.properties.app",
            "okta.event_type",
            "winlog.event_id",
            "process.Ext.api.name",
            "file.Ext.header_bytes",
            "process.*",
            "process.my_custom_field",
            "message",
            "nmae",
        ] {
            assert_eq!(unknown_field(name), None, "{name}");
        }
        let d = unknown_field_diagnostic("process.nmae", || Range::point(0, 0)).unwrap();
        assert_eq!(d.code, codes::ECS_UNKNOWN_FIELD);
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.suggestion.as_deref(), Some("process.name"));
    }

    #[test]
    fn values_that_cannot_be_terms() {
        use ValueType::*;
        assert!(value_problem(Numeric, "abc").is_some());
        assert!(value_problem(Numeric, "4624").is_none());
        assert!(value_problem(Numeric, "-1.5e3").is_none());
        assert!(value_problem(Ip, "abc").is_some());
        assert!(value_problem(Ip, "10").is_some());
        assert!(value_problem(Ip, "10.0.0.0/8").is_none());
        assert!(value_problem(Ip, "::1").is_none());
        assert!(value_problem(Ip, "fe80::/10").is_none());
        // Shaped like an address: left to Elasticsearch.
        assert!(value_problem(Ip, "010.0.0.1").is_none());
        assert!(value_problem(Date, "abc").is_some());
        assert!(value_problem(Date, "now/d").is_none());
        assert!(value_problem(Date, "2024-01-01").is_none());
        assert!(value_problem(Boolean, "abc").is_some());
        assert!(value_problem(Boolean, "true").is_none());
        assert!(value_problem(String, "anything").is_none());
    }

    #[test]
    fn ecs_indices() {
        assert!(indices_are_ecs(&["logs-*"]));
        assert!(indices_are_ecs(&[
            "logs-endpoint.events.*",
            "logs-windows.*"
        ]));
        assert!(indices_are_ecs(&["logs-*,-logs-test*"]));
        assert!(indices_are_ecs(&["remote:logs-*"]));
        assert!(!indices_are_ecs(&["logs-*", "winlogbeat-*"]));
        assert!(!indices_are_ecs(&["logs*"]));
        assert!(!indices_are_ecs(&["logs-*::failures"]));
        assert!(!indices_are_ecs::<&str>(&[]));
        assert!(!indices_are_ecs(&["-logs-*"]));
    }

    #[test]
    fn merge_drops_duplicates_and_hints() {
        let r = Range::point(0, 1);
        let mut hint = Diagnostic::warning("eql_argument_type", "maybe", r);
        hint.severity = Severity::Hint;
        let mut found = vec![hint];
        merge(&mut found, vec![type_mismatch("x", "long", "LIKE", r)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, codes::ECS_TYPE_MISMATCH);
        let mut found = vec![Diagnostic::error("eql_argument_type", "no", r)];
        merge(&mut found, vec![type_mismatch("x", "long", "LIKE", r)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, "eql_argument_type");
    }
}
