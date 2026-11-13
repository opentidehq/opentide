//! MISP push, preview, status and retract (`sharing/engine.py` `run_misp`).
//!
//! Preview and status make no request. Push and retract first probe each
//! destination (version, the key's organisation, the object template), then
//! work through the objects, `--workers` at a time for one destination, the
//! records kept in the objects' order. The ledger is written after each
//! object that changed the destination, never for a skip or a failure.

use std::path::PathBuf;
use std::sync::Mutex;

use opentide_compile::json::{Json, Object};
use opentide_connectors::misp::{Kind, Misp, MispCallError, RemoteEvent, TemplateView};
use opentide_workspace::Workspace;
use opentide_workspace::validate::{Check, Options as ValidateOptions, QueriesMode, Selection};

use super::config::{Block, INTEGRATION_MISP};
use super::document::{TideDocument, resolve};
use super::event::{self, REQUIRED_RELATIONS, TEMPLATE_VERSION, is_ours, uuid_pattern};
use super::ledger::Ledger;
use super::{Mode, TLP_ORDER};
use crate::json::Json as OutJson;

/// The run's filters (`ShareFilters`); `None` when the flag was not given.
#[derive(Clone, Debug, Default)]
pub struct Filters {
    /// `--uuid`.
    pub uuids: Option<Vec<String>>,
    /// `--type`.
    pub types: Option<Vec<String>>,
    /// `--file`, resolved.
    pub files: Option<Vec<PathBuf>>,
}

/// One object on one destination (`ShareRecord`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The object.
    pub object_uuid: String,
    /// The destination.
    pub target: String,
    /// What happened (`created`, `skipped_tlp`, `failed`, ...).
    pub action: String,
    /// The remote event's UUID.
    pub remote_event_uuid: Option<String>,
    /// The remote event's id.
    pub remote_event_id: Option<i64>,
    /// Why it was skipped or failed.
    pub reason: Option<String>,
    /// Notes.
    pub notes: Vec<String>,
    /// The failure's kind.
    pub kind: Option<Kind>,
}

impl Record {
    fn new(uuid: &str, block: &Block, action: &str) -> Self {
        Self {
            object_uuid: uuid.to_owned(),
            target: block.name.clone(),
            action: action.to_owned(),
            remote_event_uuid: None,
            remote_event_id: None,
            reason: None,
            notes: Vec::new(),
            kind: None,
        }
    }

    fn failed(uuid: &str, block: &Block, reason: &str, kind: Kind, notes: Vec<String>) -> Self {
        Self {
            reason: Some(reason.to_owned()),
            kind: Some(kind),
            notes,
            ..Self::new(uuid, block, "failed")
        }
    }

    fn skipped(uuid: &str, block: &Block, action: &str, reason: &str) -> Self {
        Self {
            reason: Some(reason.to_owned()),
            ..Self::new(uuid, block, action)
        }
    }

    fn with_remote(mut self, remote: &RemoteEvent) -> Self {
        self.remote_event_uuid = Some(remote.event_uuid.clone());
        self.remote_event_id = remote.event_id;
        self
    }

    fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.notes = notes;
        self
    }

    /// The record as the result lists it (`as_dict`).
    pub fn to_json(&self) -> OutJson {
        let mut members = vec![
            ("object_uuid".to_owned(), OutJson::str(&self.object_uuid)),
            ("integration".to_owned(), OutJson::str(INTEGRATION_MISP)),
            ("target".to_owned(), OutJson::str(&self.target)),
            ("action".to_owned(), OutJson::str(&self.action)),
        ];
        if let Some(uuid) = &self.remote_event_uuid {
            members.push(("remote_event_uuid".into(), OutJson::str(uuid)));
        }
        if let Some(id) = self.remote_event_id {
            members.push(("remote_event_id".into(), OutJson::Int(id)));
        }
        if let Some(reason) = &self.reason {
            members.push(("reason".into(), OutJson::str(reason)));
        }
        if !self.notes.is_empty() {
            members.push((
                "notes".into(),
                OutJson::Array(self.notes.iter().map(OutJson::str).collect()),
            ));
        }
        OutJson::Object(members)
    }
}

/// A run's result (`ShareRun`).
#[derive(Clone, Debug, Default)]
pub struct ShareRun {
    /// The records.
    pub records: Vec<Record>,
    /// The preflight that stopped the run.
    pub preflight: Option<String>,
}

impl ShareRun {
    fn stopped(preflight: &str, records: Vec<Record>) -> Self {
        Self {
            records,
            preflight: Some(preflight.to_owned()),
        }
    }

    /// The exit status sharing 1.0 defines (`exit_code`).
    pub fn exit_code(&self) -> i32 {
        if self.preflight.is_some() {
            return 1;
        }
        let success = self.records.iter().any(|record| {
            matches!(
                record.action.as_str(),
                "created" | "updated" | "unchanged" | "retracted"
            )
        });
        let failures: Vec<&Record> = self
            .records
            .iter()
            .filter(|record| record.action == "failed")
            .collect();
        if success && !failures.is_empty() {
            return 3;
        }
        if failures.is_empty() {
            return 0;
        }
        if failures
            .iter()
            .all(|record| matches!(record.kind, Some(Kind::Authentication | Kind::Connectivity)))
        {
            return 2;
        }
        1
    }
}

/// The schema and UUID checks a pushed object must pass (`_validator`).
pub struct Validator {
    by_uuid: Vec<(String, Vec<String>)>,
    by_file: Vec<(PathBuf, String)>,
    scope_no_match: Option<String>,
}

fn legacy(field_path: &[String], message: &str) -> String {
    if field_path.is_empty() {
        message.to_owned()
    } else {
        format!("{}: {message}", field_path.join("."))
    }
}

impl Validator {
    /// Checks the catalogue's objects once.
    pub fn new(workspace: &Workspace, documents: &[TideDocument]) -> Option<Self> {
        let mut uuids: Vec<String> = documents
            .iter()
            .filter_map(|document| document.uuid().map(str::to_owned))
            .collect();
        uuids.sort();
        uuids.dedup();
        if uuids.is_empty() {
            return None;
        }
        let selection = Selection {
            uuids,
            ..Selection::default()
        };
        let mut errors = Vec::new();
        for check in [Check::UuidFormat, Check::Schema] {
            let validation = workspace.validate(&ValidateOptions {
                check: Some(check),
                selection: Some(&selection),
                strict: false,
                queries: QueriesMode::Off,
                query_check: None,
                cve_check: None,
                platform_configurations: crate::plugins::configurations(),
                // The oracle's share checks each document alone: no compile check.
                compile_check: None,
            });
            for issue in validation.report.issues {
                if issue.severity == opentide_workspace::Severity::Error && !errors.contains(&issue)
                {
                    errors.push(issue);
                }
            }
        }
        errors.sort_by(|a, b| {
            (
                &a.file_path,
                a.yaml_line,
                &a.field_path,
                &a.object_uuid,
                &a.code,
                &a.message,
            )
                .cmp(&(
                    &b.file_path,
                    b.yaml_line,
                    &b.field_path,
                    &b.object_uuid,
                    &b.code,
                    &b.message,
                ))
        });
        let mut by_uuid: Vec<(String, Vec<String>)> = Vec::new();
        let mut by_file = Vec::new();
        let mut scope_no_match = None;
        for issue in &errors {
            let text = legacy(&issue.field_path, &issue.message);
            let key = if issue.object_uuid.is_empty() {
                "_global".to_owned()
            } else {
                issue.object_uuid.clone()
            };
            match by_uuid.iter_mut().find(|(uuid, _)| *uuid == key) {
                Some((_, messages)) => messages.push(text.clone()),
                None => by_uuid.push((key, vec![text.clone()])),
            }
            if let Some(path) = &issue.file_path {
                by_file.push((resolve(path), text.clone()));
            }
            if issue.code == "scope_no_match" && scope_no_match.is_none() {
                scope_no_match = Some(text);
            }
        }
        Some(Self {
            by_uuid,
            by_file,
            scope_no_match,
        })
    }

    /// The document's errors, joined; `None` when it passes.
    fn check(&self, document: &TideDocument) -> Option<String> {
        let mut messages: Vec<String> = self
            .by_uuid
            .iter()
            .find(|(uuid, _)| Some(uuid.as_str()) == document.uuid())
            .map(|(_, messages)| messages.clone())
            .unwrap_or_default();
        if let Some(path) = &document.path {
            let wanted = resolve(path);
            for (file, text) in &self.by_file {
                if *file == wanted && !messages.contains(text) {
                    messages.push(text.clone());
                }
            }
        }
        if messages.is_empty()
            && let Some(text) = &self.scope_no_match
        {
            messages.push(text.clone());
        }
        (!messages.is_empty()).then(|| messages.join("; "))
    }
}

/// What a run does (`run_misp`'s keywords).
pub struct Options<'a> {
    /// `push`, `preview`, `status` or `retract`.
    pub mode: Mode,
    /// The filters.
    pub filters: Option<&'a Filters>,
    /// `--publish` / `--no-publish`.
    pub publish: Option<bool>,
    /// `--workers`.
    pub workers: usize,
    /// `--delete`.
    pub delete: bool,
    /// `--yes`.
    pub confirmed: bool,
    /// The checks a pushed object passes, when there are objects.
    pub validator: Option<&'a Option<Validator>>,
    /// The time the ledger records, `YYYY-MM-DDTHH:MM:SSZ`.
    pub stamp: String,
}

/// Makes the client of a destination.
pub type Factory<'a> = dyn Fn(&Block) -> Result<Box<dyn Misp>, MispCallError> + 'a;

/// Runs one share command across `blocks` (`run_misp`).
pub fn run(
    documents: &[TideDocument],
    blocks: &[Block],
    options: &Options<'_>,
    ledger: Ledger,
    factory: &Factory<'_>,
) -> ShareRun {
    if blocks.is_empty() || blocks.iter().any(|block| !block.enabled) {
        return ShareRun::stopped("scope_no_match", Vec::new());
    }
    if options.delete && !options.confirmed {
        return ShareRun::stopped("retract_unconfirmed", Vec::new());
    }
    let selected = selected(documents, options.filters);
    if options.mode != Mode::Retract && selected.is_empty() {
        return ShareRun::stopped("scope_no_match", Vec::new());
    }
    if matches!(options.mode, Mode::Push | Mode::Retract)
        && blocks
            .iter()
            .any(|block| block.resolved_api_key().is_none())
    {
        return ShareRun::stopped("api_key_unset", Vec::new());
    }
    if options.mode == Mode::Retract
        && selected.is_empty()
        && ledger_uuids(&ledger, blocks, options.filters, documents).is_empty()
    {
        return ShareRun::stopped("scope_no_match", Vec::new());
    }
    match options.mode {
        Mode::Preview => {
            return ShareRun {
                records: preview(&selected, blocks, &ledger, options.publish),
                preflight: None,
            };
        }
        Mode::Status => {
            return ShareRun {
                records: status(&selected, blocks, &ledger),
                preflight: None,
            };
        }
        _ => {}
    }
    let probes: Vec<Probe> = blocks
        .iter()
        .map(|block| Probe::run(block, factory))
        .collect();
    if probes.iter().any(|probe| probe.mismatch) {
        let mut records = Vec::new();
        for probe in probes.iter().filter(|probe| probe.mismatch) {
            let (local, shareable) = split_local(&selected, &probe.block, None);
            records.extend(local);
            records.extend(shareable.iter().map(|document| {
                Record::failed(
                    document.uuid().unwrap_or_default(),
                    &probe.block,
                    "organisation_uuid_mismatch",
                    Kind::Other,
                    Vec::new(),
                )
            }));
        }
        return ShareRun::stopped("organisation_uuid_mismatch", records);
    }
    let ledger = Mutex::new(ledger);
    let mut records = Vec::new();
    for probe in &probes {
        if options.mode == Mode::Retract {
            records.extend(retract_block(probe, &selected, documents, &ledger, options));
        } else {
            records.extend(push_block(probe, &selected, &ledger, options));
        }
    }
    ShareRun {
        records,
        preflight: None,
    }
}

/// A destination probed before any object (`_Probe`).
struct Probe {
    block: Block,
    client: Option<Box<dyn Misp>>,
    org: Option<String>,
    template: Option<TemplateView>,
    error: Option<MispCallError>,
    mismatch: bool,
}

impl Probe {
    fn run(block: &Block, factory: &Factory<'_>) -> Self {
        let mut probe = Self {
            block: block.clone(),
            client: None,
            org: None,
            template: None,
            error: None,
            mismatch: false,
        };
        let client = match factory(block) {
            Ok(client) => client,
            Err(error) => {
                probe.error = Some(error);
                return probe;
            }
        };
        let outcome = (|| -> Result<(), MispCallError> {
            client.get_version()?;
            probe.org = Some(client.current_organisation_uuid()?);
            probe.template = Some(client.object_template()?);
            Ok(())
        })();
        probe.client = Some(client);
        match outcome {
            Err(error) => probe.error = Some(error),
            Ok(()) => {
                if let (Some(configured), Some(org)) = (&block.organisation_uuid, &probe.org)
                    && !configured.is_empty()
                    && !org.is_empty()
                    && configured.to_lowercase() != org.to_lowercase()
                {
                    probe.mismatch = true;
                }
            }
        }
        probe
    }
}

/// The documents the filters select (`_selected`).
fn selected<'d>(documents: &'d [TideDocument], filters: Option<&Filters>) -> Vec<&'d TideDocument> {
    let Some(filters) = filters else {
        return documents.iter().collect();
    };
    documents
        .iter()
        .filter(|document| {
            if let Some(uuids) = &filters.uuids
                && !document
                    .uuid()
                    .is_some_and(|uuid| uuids.iter().any(|u| u == uuid))
            {
                return false;
            }
            if let Some(types) = &filters.types
                && !document
                    .family()
                    .is_some_and(|family| types.iter().any(|t| t == family))
            {
                return false;
            }
            if let Some(files) = &filters.files
                && !document
                    .path
                    .as_ref()
                    .is_some_and(|path| files.contains(&resolve(path)))
            {
                return false;
            }
            true
        })
        .collect()
}

/// The shared objects no longer in the catalogue, narrowed by the filters
/// (`_ledger_uuids`).
fn ledger_uuids(
    ledger: &Ledger,
    blocks: &[Block],
    filters: Option<&Filters>,
    catalogue: &[TideDocument],
) -> Vec<String> {
    let present: Vec<&str> = catalogue.iter().filter_map(TideDocument::uuid).collect();
    let mut found: Vec<String> = Vec::new();
    for line in ledger.records() {
        if line.get("integration").and_then(Json::as_str) != Some(INTEGRATION_MISP) {
            continue;
        }
        let Some(target) = line.get("target").and_then(Json::as_str) else {
            continue;
        };
        if !blocks.iter().any(|block| block.name == target) {
            continue;
        }
        let Some(uuid) = line.get("object_uuid").and_then(Json::as_str) else {
            continue;
        };
        if present.contains(&uuid) {
            continue;
        }
        if let Some(filters) = filters {
            if let Some(uuids) = &filters.uuids
                && !uuids.iter().any(|wanted| wanted == uuid)
            {
                continue;
            }
            if filters.files.is_some() {
                continue;
            }
            if let Some(types) = &filters.types {
                let family = line
                    .get("object_schema")
                    .and_then(Json::as_str)
                    .map(|schema| schema.split("::").next().unwrap_or_default());
                if !family.is_some_and(|family| types.iter().any(|t| t == family)) {
                    continue;
                }
            }
        }
        if !found.iter().any(|seen| seen == uuid) {
            found.push(uuid.to_owned());
        }
    }
    found
}

/// The statuses a block's `rule_statuses` is matched against
/// (`_rule_statuses`): those of the enabled platform blocks, else the root's.
fn rule_statuses(document: &TideDocument) -> Vec<String> {
    let statuses: Vec<String> = match document.body.get("configurations") {
        Some(Json::Object(blocks)) => blocks
            .values()
            .filter_map(|block| {
                let block = block.as_object()?;
                (block.get("enabled") == Some(&Json::Bool(true)))
                    .then(|| block.get("status").and_then(Json::as_str))
                    .flatten()
                    .map(str::to_owned)
            })
            .collect(),
        _ => Vec::new(),
    };
    if !statuses.is_empty() {
        return statuses;
    }
    document
        .body
        .get("status")
        .and_then(Json::as_str)
        .map(|status| vec![status.to_owned()])
        .unwrap_or_default()
}

/// The TLPs at or below `max_tlp` (`_allowed`).
fn allowed(max_tlp: &str) -> &'static [&'static str] {
    match TLP_ORDER.iter().position(|name| *name == max_tlp) {
        Some(ceiling) => &TLP_ORDER[..=ceiling],
        None => &[],
    }
}

/// The records of the objects that never reach the destination, and the
/// ones that do (`_split_local`).
fn split_local<'d>(
    documents: &[&'d TideDocument],
    block: &Block,
    validator: Option<&Validator>,
) -> (Vec<Record>, Vec<&'d TideDocument>) {
    let mut local = Vec::new();
    let mut shareable = Vec::new();
    for document in documents {
        let uuid = document.uuid().unwrap_or_default();
        let (Some(family), true) = (
            document.family().filter(|_| document.uuid().is_some()),
            document.parse_error.is_none(),
        ) else {
            local.push(Record::failed(
                uuid,
                block,
                "invalid_document",
                Kind::Other,
                Vec::new(),
            ));
            continue;
        };
        if !block.object_types.iter().any(|kind| kind == family) {
            local.push(Record::skipped(uuid, block, "skipped_type", "object_type"));
            continue;
        }
        if family == "rule"
            && !rule_statuses(document)
                .iter()
                .any(|status| block.rule_statuses.contains(status))
        {
            local.push(Record::skipped(
                uuid,
                block,
                "skipped_status",
                "rule_status",
            ));
            continue;
        }
        if let Some(tlp) = document.meta("tlp").and_then(Json::as_str)
            && TLP_ORDER.contains(&tlp)
            && !allowed(&block.max_tlp).contains(&tlp)
        {
            local.push(Record::skipped(uuid, block, "skipped_tlp", "max_tlp"));
            continue;
        }
        if let Some(validator) = validator
            && let Some(message) = validator.check(document)
        {
            local.push(Record::failed(
                uuid,
                block,
                "validation_error",
                Kind::Other,
                vec![message],
            ));
            continue;
        }
        shareable.push(*document);
    }
    (local, shareable)
}

/// Where an object's events belong, and whether that was found
/// (`_organisation`): `block`, `object`, `invalid` or `missing`.
fn organisation(block: &Block, document: &TideDocument) -> (Option<String>, &'static str) {
    if let Some(org) = block
        .organisation_uuid
        .as_ref()
        .filter(|org| !org.is_empty())
    {
        return (Some(org.to_lowercase()), "block");
    }
    if let Some(Json::Object(org)) = document.meta("organisation")
        && let Some(Json::Str(raw)) = org.get("uuid")
        && !raw.trim().is_empty()
    {
        let text = raw.trim().to_lowercase();
        if uuid_pattern().is_match(&text) {
            return (Some(text), "object");
        }
        return (None, "invalid");
    }
    (None, "missing")
}

fn template_problem(
    template: Option<&TemplateView>,
    family: &str,
) -> (Option<&'static str>, Option<String>) {
    let Some(template) = template.filter(|template| template.found) else {
        return (Some("template_missing"), None);
    };
    let missing = REQUIRED_RELATIONS
        .iter()
        .any(|name| !template.relations.iter().any(|relation| relation == name));
    if missing
        || template
            .type_values
            .as_ref()
            .is_some_and(|values| !values.iter().any(|value| value == family))
    {
        return (Some("template_relation_missing"), None);
    }
    if template.version != Some(TEMPLATE_VERSION) {
        let version = template
            .version
            .map_or_else(|| "null".to_owned(), |version| version.to_string());
        return (None, Some(format!("template_version:{version}")));
    }
    (None, None)
}

/// The events this organisation owns, and the foreign ones (`_matched`).
fn matched<'e>(
    events: &'e [RemoteEvent],
    org: &str,
    tide_uuid: &str,
) -> (Vec<&'e RemoteEvent>, Vec<String>) {
    let mut ours = Vec::new();
    let mut foreign = Vec::new();
    for event in events {
        if !event.opentide_uuids.iter().any(|uuid| uuid == tide_uuid) {
            continue;
        }
        if event
            .orgc_uuid
            .as_ref()
            .is_some_and(|orgc| !orgc.is_empty() && orgc.to_lowercase() == org.to_lowercase())
        {
            ours.push(event);
        } else {
            foreign.push(event.event_uuid.clone());
        }
    }
    (ours, foreign)
}

/// The body of `events/edit` (`_edit_body`): this object's event, on the
/// remote's UUID, with the remote's other objects kept first.
fn edit_body(created: &Json, remote: &RemoteEvent, tide_uuid: &str) -> Result<Json, MispCallError> {
    let Some(Json::Object(raw)) = created.get("Event") else {
        return Err(MispCallError::new(
            Kind::Rejected,
            "remote_update_rejected",
            None,
        ));
    };
    let mut event = raw.clone();
    event.insert("uuid".into(), Json::Str(remote.event_uuid.clone()));
    if remote.event_attribute_count > 0 {
        event.shift_remove("Attribute");
    }
    let ours: Vec<Json> = match event.get("Object") {
        Some(Json::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let mut objects: Vec<Json> = remote
        .objects
        .iter()
        .filter(|object| !is_ours(object, tide_uuid))
        .map(|object| Json::Object(object.clone()))
        .collect();
    objects.extend(ours);
    event.insert("Object".into(), Json::Array(objects));
    let mut body = Object::new();
    body.insert("Event".into(), Json::Object(event));
    Ok(Json::Object(body))
}

/// Runs `work` over `items`, `workers` at a time, keeping their order
/// (`_map`).
fn map<T: Sync, R: Send>(workers: usize, items: &[T], work: &(dyn Fn(&T) -> R + Sync)) -> Vec<R> {
    if workers <= 1 || items.len() <= 1 || !crate::threads::AVAILABLE {
        return items.iter().map(work).collect();
    }
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..workers.min(items.len()) {
            scope.spawn(|| {
                loop {
                    let index = {
                        let Ok(mut next) = next.lock() else { return };
                        let index = *next;
                        *next += 1;
                        index
                    };
                    let Some(item) = items.get(index) else { return };
                    let result = work(item);
                    if let Ok(mut results) = results.lock()
                        && let Some(slot) = results.get_mut(index)
                    {
                        *slot = Some(result);
                    }
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect()
}

fn write_reason(error: &MispCallError, update: bool) -> String {
    if error.reason == "attribute_too_large"
        || matches!(error.kind, Kind::Authentication | Kind::Connectivity)
        || !update
    {
        return error.reason.clone();
    }
    "remote_update_rejected".to_owned()
}

/// The reason and kind of a destination that failed its probe (`_failure`).
fn failure(error: Option<&MispCallError>) -> (String, Kind) {
    match error {
        None => ("connectivity_failed".into(), Kind::Connectivity),
        Some(error) if error.kind == Kind::Authentication => {
            ("authentication_failed".into(), Kind::Authentication)
        }
        Some(error) if error.reason == "organisation_uuid_unverified" => {
            (error.reason.clone(), error.kind)
        }
        Some(error) if error.kind == Kind::Connectivity => {
            ("connectivity_failed".into(), Kind::Connectivity)
        }
        Some(error) => (error.reason.clone(), error.kind),
    }
}

fn push_block(
    probe: &Probe,
    documents: &[&TideDocument],
    ledger: &Mutex<Ledger>,
    options: &Options<'_>,
) -> Vec<Record> {
    let block = &probe.block;
    let validator = options.validator.and_then(Option::as_ref);
    let (mut local, shareable) = split_local(documents, block, validator);
    let Some(client) = probe.client.as_deref().filter(|_| probe.error.is_none()) else {
        let (reason, kind) = failure(probe.error.as_ref());
        local.extend(shareable.iter().map(|document| {
            Record::failed(
                document.uuid().unwrap_or_default(),
                block,
                &reason,
                kind,
                Vec::new(),
            )
        }));
        return local;
    };
    let publish = options.publish.unwrap_or(block.publish);
    let known: Vec<&str> = shareable
        .iter()
        .filter_map(|document| document.uuid())
        .collect();
    let work = |document: &&TideDocument| {
        upsert(
            document,
            probe,
            client,
            ledger,
            publish,
            &options.stamp,
            &known,
        )
    };
    local.extend(map(options.workers, &shareable, &work));
    local
}

#[expect(
    clippy::too_many_lines,
    reason = "the oracle's `_upsert`, step by step, in one place"
)]
fn upsert(
    document: &TideDocument,
    probe: &Probe,
    client: &dyn Misp,
    ledger: &Mutex<Ledger>,
    publish: bool,
    stamp: &str,
    known: &[&str],
) -> Record {
    let block = &probe.block;
    let uuid = document.uuid().unwrap_or_default();
    let fail = |reason: &str, kind: Kind, notes: &[String]| {
        Record::failed(uuid, block, reason, kind, notes.to_vec())
    };
    let (org, source) = organisation(block, document);
    if source == "missing" {
        return fail("organisation_uuid_missing", Kind::Other, &[]);
    }
    let Some(org) = org.filter(|_| source != "invalid") else {
        return fail("organisation_uuid_invalid", Kind::Other, &[]);
    };
    if let Some(probed) = probe.org.as_ref().filter(|probed| !probed.is_empty())
        && org.to_lowercase() != probed.to_lowercase()
    {
        return fail("organisation_uuid_mismatch", Kind::Other, &[]);
    }
    let built = event::build(document, &[]);
    if built.event.is_none() || built.reason.is_some() {
        return fail(built.reason.unwrap_or("invalid_document"), Kind::Other, &[]);
    }
    let family = document.family().unwrap_or_default();
    let (template_reason, template_note) = template_problem(probe.template.as_ref(), family);
    if let Some(reason) = template_reason {
        return fail(reason, Kind::Other, &[]);
    }
    let resolved = match event::resolve_clusters(client, &built.cluster_sources) {
        Ok(resolved) => resolved,
        Err(error) => return fail("galaxy_lookup_failed", error.kind, &[]),
    };
    let built = event::build(document, &resolved.tags);
    let Some(created_event) = built.event.clone() else {
        return fail(built.reason.unwrap_or("invalid_document"), Kind::Other, &[]);
    };
    let mut notes = resolved.notes;
    notes.extend(template_note);
    notes.extend(
        built
            .relations
            .iter()
            .filter(|relation| !known.contains(&relation.as_str()))
            .map(|relation| format!("relation_not_shared:{relation}")),
    );
    let found = match client.search_opentide_events(uuid) {
        Ok(found) => found,
        Err(error) => return fail("remote_lookup_failed", error.kind, &notes),
    };
    let (ours, foreign) = matched(&found, &org, uuid);
    notes.extend(foreign.iter().map(|event| format!("foreign_event:{event}")));
    if ours.len() > 1 {
        let listed: Vec<&str> = ours.iter().map(|event| event.event_uuid.as_str()).collect();
        notes.push(format!("ambiguous_remote_event:{}", listed.join(",")));
        return fail("ambiguous_remote_event", Kind::Other, &notes);
    }
    let line = ledger
        .lock()
        .ok()
        .and_then(|ledger| ledger.get(uuid, INTEGRATION_MISP, &block.name));
    let hash = document.content_hash();
    let remember = |remote: &RemoteEvent, published: bool| -> Result<(), String> {
        let version = match document.meta("version") {
            Some(Json::Int(number)) => Json::Int(*number),
            Some(other) => other.clone(),
            None => Json::Null,
        };
        let mut record = Object::new();
        for (key, value) in [
            ("state", Json::Str("synced".into())),
            ("object_uuid", Json::Str(uuid.to_owned())),
            (
                "object_schema",
                document
                    .schema_id()
                    .map_or(Json::Null, |schema| Json::Str(schema.to_owned())),
            ),
            ("object_version", version),
            ("content_hash", Json::Str(hash.clone())),
            ("integration", Json::Str(INTEGRATION_MISP.into())),
            ("target", Json::Str(block.name.clone())),
            ("organisation_uuid", Json::Str(org.clone())),
            ("remote_event_uuid", Json::Str(remote.event_uuid.clone())),
            (
                "remote_event_id",
                remote.event_id.map_or(Json::Null, Json::Int),
            ),
            ("published", Json::Bool(published)),
            ("shared_at", Json::Str(stamp.to_owned())),
        ] {
            record.insert(key.to_owned(), value);
        }
        let mut ledger = ledger
            .lock()
            .map_err(|_| "ledger_write_failed".to_owned())?;
        ledger.put(record);
        ledger.save().map_err(|_| "ledger_write_failed".to_owned())
    };
    let written = |result: Result<(), String>, record: Record, notes: &[String]| match result {
        Ok(()) => record,
        Err(reason) => fail(&reason, Kind::Other, notes),
    };
    if let ([remote], Some(line)) = (ours.as_slice(), &line)
        && line.get("state").and_then(Json::as_str) == Some("synced")
        && line.get("content_hash").and_then(Json::as_str) == Some(hash.as_str())
    {
        if publish && !remote.published {
            if let Err(error) = client.publish_event(&remote.address()) {
                return fail("publish_failed", error.kind, &notes);
            }
            let record = Record::new(uuid, block, "updated")
                .with_remote(remote)
                .with_notes(notes.clone());
            return written(remember(remote, true), record, &notes);
        }
        return Record::new(uuid, block, "unchanged")
            .with_remote(remote)
            .with_notes(notes);
    }
    let Some(remote) = ours.first() else {
        let remote = match client.add_event(&created_event) {
            Ok(remote) => remote,
            Err(error) => return fail(&write_reason(&error, false), error.kind, &notes),
        };
        let mut published = false;
        if publish {
            if let Err(error) = client.publish_event(&remote.address()) {
                return fail("publish_failed", error.kind, &notes);
            }
            published = true;
        }
        let record = Record::new(uuid, block, "created")
            .with_remote(&remote)
            .with_notes(notes.clone());
        return written(remember(&remote, published), record, &notes);
    };
    if remote.event_attribute_count > 0
        || remote.objects.iter().any(|object| !is_ours(object, uuid))
    {
        notes.push("remote_extra_content".to_owned());
    }
    let body = match edit_body(&created_event, remote, uuid) {
        Ok(body) => body,
        Err(error) => return fail(&error.reason, error.kind, &notes),
    };
    let remote = match client.edit_event(&remote.address(), &body) {
        Ok(remote) => remote,
        Err(error) => return fail(&write_reason(&error, true), error.kind, &notes),
    };
    let mut published = false;
    if publish {
        if let Err(error) = client.publish_event(&remote.address()) {
            return fail("publish_failed", error.kind, &notes);
        }
        published = true;
    }
    let record = Record::new(uuid, block, "updated")
        .with_remote(&remote)
        .with_notes(notes.clone());
    written(remember(&remote, published), record, &notes)
}

fn retract_block(
    probe: &Probe,
    documents: &[&TideDocument],
    catalogue: &[TideDocument],
    ledger: &Mutex<Ledger>,
    options: &Options<'_>,
) -> Vec<Record> {
    let block = &probe.block;
    let mut by_uuid: Vec<(String, &TideDocument)> = Vec::new();
    for document in documents {
        if let Some(uuid) = document.uuid() {
            match by_uuid.iter_mut().find(|(seen, _)| seen == uuid) {
                Some((_, existing)) => *existing = document,
                None => by_uuid.push((uuid.to_owned(), document)),
            }
        }
    }
    let mut candidates: Vec<String> = by_uuid.iter().map(|(uuid, _)| uuid.clone()).collect();
    let gone = ledger.lock().map_or_else(
        |_| Vec::new(),
        |ledger| {
            ledger_uuids(
                &ledger,
                std::slice::from_ref(block),
                options.filters,
                catalogue,
            )
        },
    );
    for uuid in gone {
        if !by_uuid.iter().any(|(seen, _)| *seen == uuid) {
            candidates.push(uuid);
        }
    }
    let Some(client) = probe.client.as_deref().filter(|_| probe.error.is_none()) else {
        let (reason, kind) = failure(probe.error.as_ref());
        return candidates
            .iter()
            .map(|uuid| Record::failed(uuid, block, &reason, kind, Vec::new()))
            .collect();
    };
    let work = |uuid: &String| {
        let document = by_uuid
            .iter()
            .find(|(seen, _)| seen == uuid)
            .map(|(_, document)| *document);
        retract_one(uuid, document, probe, client, ledger, options)
    };
    map(options.workers, &candidates, &work)
        .into_iter()
        .flatten()
        .collect()
}

fn retract_one(
    uuid: &str,
    document: Option<&TideDocument>,
    probe: &Probe,
    client: &dyn Misp,
    ledger: &Mutex<Ledger>,
    options: &Options<'_>,
) -> Option<Record> {
    let block = &probe.block;
    let line = ledger
        .lock()
        .ok()
        .and_then(|ledger| ledger.get(uuid, INTEGRATION_MISP, &block.name));
    let org = block
        .organisation_uuid
        .as_ref()
        .filter(|org| !org.is_empty())
        .map(|org| org.to_lowercase())
        .or_else(|| document.and_then(|document| organisation(block, document).0))
        .or_else(|| {
            line.as_ref()
                .and_then(|line| line.get("organisation_uuid"))
                .and_then(Json::as_str)
                .map(str::to_lowercase)
        });
    let failed =
        |reason: &str, kind: Kind| Some(Record::failed(uuid, block, reason, kind, Vec::new()));
    let found = match client.search_opentide_events(uuid) {
        Ok(found) => found,
        Err(error) => return failed("remote_lookup_failed", error.kind),
    };
    let Some(org) = org else {
        if line.is_none() && found.is_empty() {
            return None;
        }
        return failed("organisation_uuid_missing", Kind::Other);
    };
    let (ours, _) = matched(&found, &org, uuid);
    if ours.len() > 1 {
        return failed("ambiguous_remote_event", Kind::Other);
    }
    let Some(remote) = ours.first() else {
        line.as_ref()?;
        let discarded = ledger.lock().map(|mut ledger| {
            if ledger.discard(uuid, INTEGRATION_MISP, &block.name) {
                ledger.save()
            } else {
                Ok(())
            }
        });
        if !matches!(discarded, Ok(Ok(()))) {
            return failed("ledger_write_failed", Kind::Other);
        }
        return Some(
            Record::new(uuid, block, "retracted").with_notes(vec!["remote_absent".into()]),
        );
    };
    let address = remote.address();
    let outcome = (|| -> Result<Result<(), String>, MispCallError> {
        if options.delete {
            client.delete_event(&address)?;
            let saved = ledger
                .lock()
                .map_err(|_| "ledger_write_failed".to_owned())
                .and_then(|mut ledger| {
                    if ledger.discard(uuid, INTEGRATION_MISP, &block.name) {
                        ledger.save().map_err(|_| "ledger_write_failed".to_owned())
                    } else {
                        Ok(())
                    }
                });
            return Ok(saved);
        }
        if remote.published {
            client.unpublish_event(&address)?;
        }
        let mut record: Object = line.clone().unwrap_or_default();
        for (key, value) in [
            ("state", Json::Str("retracted".into())),
            ("object_uuid", Json::Str(uuid.to_owned())),
            ("integration", Json::Str(INTEGRATION_MISP.into())),
            ("target", Json::Str(block.name.clone())),
            ("organisation_uuid", Json::Str(org.clone())),
            ("remote_event_uuid", Json::Str(remote.event_uuid.clone())),
            (
                "remote_event_id",
                remote.event_id.map_or(Json::Null, Json::Int),
            ),
            ("published", Json::Bool(false)),
            ("shared_at", Json::Str(options.stamp.clone())),
        ] {
            record.insert(key.to_owned(), value);
        }
        if let Some(document) = document {
            record.insert(
                "object_schema".into(),
                document
                    .schema_id()
                    .map_or(Json::Null, |schema| Json::Str(schema.to_owned())),
            );
            record.insert("content_hash".into(), Json::Str(document.content_hash()));
            record.insert(
                "object_version".into(),
                document.meta("version").cloned().unwrap_or(Json::Null),
            );
        }
        let saved = ledger
            .lock()
            .map_err(|_| "ledger_write_failed".to_owned())
            .and_then(|mut ledger| {
                ledger.put(record);
                ledger.save().map_err(|_| "ledger_write_failed".to_owned())
            });
        Ok(saved)
    })();
    match outcome {
        Err(error) => failed(&error.reason, error.kind),
        Ok(Err(reason)) => failed(&reason, Kind::Other),
        Ok(Ok(())) => Some(Record::new(uuid, block, "retracted").with_remote(remote)),
    }
}

/// What a push would do, from the ledger alone (`_predict`).
fn predict(ledger: &Ledger, document: &TideDocument, target: &str, publish: bool) -> &'static str {
    let Some(line) = ledger.get(
        document.uuid().unwrap_or_default(),
        INTEGRATION_MISP,
        target,
    ) else {
        return "created";
    };
    let state = line.get("state").and_then(Json::as_str);
    if state == Some("retracted") {
        return "updated";
    }
    if state == Some("synced")
        && line.get("content_hash").and_then(Json::as_str) == Some(document.content_hash().as_str())
        && (!publish || line.get("published") == Some(&Json::Bool(true)))
    {
        return "unchanged";
    }
    "updated"
}

fn preview(
    documents: &[&TideDocument],
    blocks: &[Block],
    ledger: &Ledger,
    publish: Option<bool>,
) -> Vec<Record> {
    let mut records = Vec::new();
    for block in blocks {
        let publish = publish.unwrap_or(block.publish);
        let (local, shareable) = split_local(documents, block, None);
        records.extend(local);
        let known: Vec<&str> = shareable
            .iter()
            .filter_map(|document| document.uuid())
            .collect();
        for document in shareable {
            let uuid = document.uuid().unwrap_or_default();
            let (org, source) = organisation(block, document);
            if source == "missing" {
                records.push(Record::failed(
                    uuid,
                    block,
                    "organisation_uuid_missing",
                    Kind::Other,
                    Vec::new(),
                ));
                continue;
            }
            if source == "invalid" || org.is_none() {
                records.push(Record::failed(
                    uuid,
                    block,
                    "organisation_uuid_invalid",
                    Kind::Other,
                    Vec::new(),
                ));
                continue;
            }
            let built = event::build(document, &[]);
            if built.event.is_none() {
                records.push(Record::failed(
                    uuid,
                    block,
                    built.reason.unwrap_or("invalid_document"),
                    Kind::Other,
                    Vec::new(),
                ));
                continue;
            }
            let mut notes = vec!["organisation_unverified".to_owned()];
            if !built.cluster_sources.is_empty() {
                notes.push("cluster_not_resolved".to_owned());
            }
            notes.extend(
                built
                    .relations
                    .iter()
                    .filter(|relation| !known.contains(&relation.as_str()))
                    .map(|relation| format!("relation_not_shared:{relation}")),
            );
            records.push(
                Record::new(uuid, block, predict(ledger, document, &block.name, publish))
                    .with_notes(notes),
            );
        }
    }
    records
}

fn status(documents: &[&TideDocument], blocks: &[Block], ledger: &Ledger) -> Vec<Record> {
    let mut records = Vec::new();
    for block in blocks {
        let (local, shareable) = split_local(documents, block, None);
        records.extend(local);
        for document in shareable {
            let uuid = document.uuid().unwrap_or_default();
            let line = ledger.get(uuid, INTEGRATION_MISP, &block.name);
            let mut record =
                Record::new(uuid, block, predict(ledger, document, &block.name, false));
            record.remote_event_uuid = line
                .as_ref()
                .and_then(|line| line.get("remote_event_uuid"))
                .and_then(Json::as_str)
                .map(str::to_owned);
            record.remote_event_id =
                match line.as_ref().and_then(|line| line.get("remote_event_id")) {
                    Some(Json::Int(id)) => Some(*id),
                    _ => None,
                };
            records.push(record);
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use opentide_connectors::misp::GalaxyCluster;

    use super::*;
    use crate::commands::share::documents_for_test;

    const ORG: &str = "11111111-1111-4111-8111-111111111111";

    /// An instance in memory: its events by id, and the calls it was sent.
    #[derive(Default)]
    struct Fake {
        events: StdMutex<Vec<RemoteEvent>>,
        calls: StdMutex<Vec<String>>,
        refuse: Option<(&'static str, MispCallError)>,
        org: Option<String>,
        template: Option<TemplateView>,
    }

    impl Fake {
        fn call(&self, name: &str) -> Result<(), MispCallError> {
            self.calls.lock().unwrap().push(name.to_owned());
            match &self.refuse {
                Some((refused, error)) if *refused == name => Err(error.clone()),
                _ => Ok(()),
            }
        }
    }

    fn template() -> TemplateView {
        TemplateView {
            found: true,
            version: Some(TEMPLATE_VERSION),
            relations: REQUIRED_RELATIONS.iter().map(|r| (*r).to_owned()).collect(),
            type_values: None,
        }
    }

    impl Misp for Fake {
        fn get_version(&self) -> Result<String, MispCallError> {
            self.call("version").map(|()| "2.5".into())
        }
        fn current_organisation_uuid(&self) -> Result<String, MispCallError> {
            self.call("org")
                .map(|()| self.org.clone().unwrap_or_else(|| ORG.into()))
        }
        fn object_template(&self) -> Result<TemplateView, MispCallError> {
            self.call("template")
                .map(|()| self.template.clone().unwrap_or_else(template))
        }
        fn search_opentide_events(&self, uuid: &str) -> Result<Vec<RemoteEvent>, MispCallError> {
            self.call("search")?;
            Ok(self
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.opentide_uuids.iter().any(|u| u == uuid))
                .cloned()
                .collect())
        }
        fn add_event(&self, _event: &Json) -> Result<RemoteEvent, MispCallError> {
            self.call("add")?;
            Ok(remote("e-new", 100, ORG, "x", false))
        }
        fn edit_event(&self, id: &str, _event: &Json) -> Result<RemoteEvent, MispCallError> {
            self.call(&format!("edit {id}"))?;
            Ok(remote("e-edit", 7, ORG, "x", false))
        }
        fn publish_event(&self, id: &str) -> Result<(), MispCallError> {
            self.call(&format!("publish {id}"))
        }
        fn unpublish_event(&self, id: &str) -> Result<(), MispCallError> {
            self.call(&format!("unpublish {id}"))
        }
        fn delete_event(&self, id: &str) -> Result<(), MispCallError> {
            self.call(&format!("delete {id}"))
        }
        fn galaxy_clusters(&self, galaxy: &str) -> Result<Vec<GalaxyCluster>, MispCallError> {
            self.call(galaxy)?;
            Ok(Vec::new())
        }
    }

    fn remote(uuid: &str, id: i64, org: &str, tide: &str, published: bool) -> RemoteEvent {
        RemoteEvent {
            event_id: Some(id),
            event_uuid: uuid.into(),
            orgc_uuid: Some(org.into()),
            published,
            opentide_uuids: vec![tide.into()],
            event_attribute_count: 0,
            objects: Vec::new(),
        }
    }

    fn block(name: &str) -> Block {
        Block {
            name: name.into(),
            url: "https://misp.example".into(),
            max_tlp: "amber".into(),
            api_key: Some("k".into()),
            enabled: true,
            object_types: vec!["threat".into(), "objective".into(), "rule".into()],
            rule_statuses: vec!["PRODUCTION".into()],
            organisation_uuid: Some(ORG.into()),
            publish: false,
            verify_ssl: true,
        }
    }

    fn rule(uuid: &str, tlp: &str) -> String {
        format!(
            "name: R {uuid}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\n  version: 1\n  \
             created: 2026-01-01\n  tlp: {tlp}\nstatus: PRODUCTION\ntechniques: [T1059]\n"
        )
    }

    fn options(mode: Mode, stamp: &str) -> Options<'static> {
        Options {
            mode,
            filters: None,
            publish: None,
            workers: 1,
            delete: false,
            confirmed: false,
            validator: None,
            stamp: stamp.into(),
        }
    }

    fn ledger() -> (tempfile::TempDir, Ledger) {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::load(&super::super::ledger::path(dir.path()));
        (dir, ledger)
    }

    fn run_with(
        fake: Fake,
        texts: &[(&str, &str)],
        opts: &Options<'_>,
        ledger: Ledger,
    ) -> (ShareRun, Vec<String>) {
        let documents = documents_for_test(texts);
        let shared = std::sync::Arc::new(fake);
        let handle = std::sync::Arc::clone(&shared);
        struct Shared(std::sync::Arc<Fake>);
        impl Misp for Shared {
            fn get_version(&self) -> Result<String, MispCallError> {
                self.0.get_version()
            }
            fn current_organisation_uuid(&self) -> Result<String, MispCallError> {
                self.0.current_organisation_uuid()
            }
            fn object_template(&self) -> Result<TemplateView, MispCallError> {
                self.0.object_template()
            }
            fn search_opentide_events(&self, u: &str) -> Result<Vec<RemoteEvent>, MispCallError> {
                self.0.search_opentide_events(u)
            }
            fn add_event(&self, e: &Json) -> Result<RemoteEvent, MispCallError> {
                self.0.add_event(e)
            }
            fn edit_event(&self, i: &str, e: &Json) -> Result<RemoteEvent, MispCallError> {
                self.0.edit_event(i, e)
            }
            fn publish_event(&self, i: &str) -> Result<(), MispCallError> {
                self.0.publish_event(i)
            }
            fn unpublish_event(&self, i: &str) -> Result<(), MispCallError> {
                self.0.unpublish_event(i)
            }
            fn delete_event(&self, i: &str) -> Result<(), MispCallError> {
                self.0.delete_event(i)
            }
            fn galaxy_clusters(&self, g: &str) -> Result<Vec<GalaxyCluster>, MispCallError> {
                self.0.galaxy_clusters(g)
            }
        }
        let factory = move |_block: &Block| -> Result<Box<dyn Misp>, MispCallError> {
            Ok(Box::new(Shared(std::sync::Arc::clone(&shared))))
        };
        let outcome = run(&documents, &[block("t")], opts, ledger, &factory);
        let calls = handle.calls.lock().unwrap().clone();
        (outcome, calls)
    }

    #[test]
    fn a_push_creates_publishes_and_records() {
        let (dir, ledger) = ledger();
        let mut opts = options(Mode::Push, "2026-01-01T00:00:00Z");
        opts.publish = Some(true);
        opts.workers = 2;
        let a = rule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "green");
        let b = rule("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "red");
        let (outcome, calls) = run_with(
            Fake::default(),
            &[("a.yaml", &a), ("b.yaml", &b)],
            &opts,
            ledger,
        );
        let actions: Vec<&str> = outcome.records.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(actions, ["skipped_tlp", "created"]);
        assert_eq!(outcome.exit_code(), 0);
        assert!(calls.contains(&"publish 100".to_owned()), "{calls:?}");
        let written = std::fs::read_to_string(super::super::ledger::path(dir.path())).unwrap();
        assert!(written.contains("\"published\":true"), "{written}");
    }

    #[test]
    fn an_owned_event_is_updated_and_a_second_one_is_ambiguous() {
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let fake = Fake::default();
        let mut event = remote("e1", 7, ORG, uuid, true);
        event.event_attribute_count = 1;
        fake.events.lock().unwrap().push(event);
        fake.events.lock().unwrap().push(remote(
            "e9",
            9,
            "99999999-9999-4999-8999-999999999999",
            uuid,
            true,
        ));
        let (_dir, ledger) = ledger();
        let a = rule(uuid, "green");
        let (outcome, calls) = run_with(fake, &[("a.yaml", &a)], &options(Mode::Push, "s"), ledger);
        let record = &outcome.records[0];
        assert_eq!(record.action, "updated", "{record:?}");
        assert!(record.notes.contains(&"foreign_event:e9".to_owned()));
        assert!(record.notes.contains(&"remote_extra_content".to_owned()));
        assert!(calls.contains(&"edit 7".to_owned()));

        let fake = Fake::default();
        fake.events
            .lock()
            .unwrap()
            .push(remote("e1", 7, ORG, uuid, true));
        fake.events
            .lock()
            .unwrap()
            .push(remote("e2", 8, ORG, uuid, true));
        let (_dir, ledger) = self::ledger();
        let (outcome, _) = run_with(fake, &[("a.yaml", &a)], &options(Mode::Push, "s"), ledger);
        assert_eq!(
            outcome.records[0].reason.as_deref(),
            Some("ambiguous_remote_event")
        );
        assert_eq!(outcome.exit_code(), 1);
    }

    #[test]
    fn probes_that_fail_fail_every_object() {
        let a = rule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "green");
        let refused = Fake {
            refuse: Some((
                "version",
                MispCallError::new(Kind::Authentication, "authentication_failed", Some(401)),
            )),
            ..Fake::default()
        };
        let (_dir, ledger) = ledger();
        let (outcome, _) = run_with(
            refused,
            &[("a.yaml", &a)],
            &options(Mode::Push, "s"),
            ledger,
        );
        assert_eq!(
            outcome.records[0].reason.as_deref(),
            Some("authentication_failed")
        );
        assert_eq!(outcome.exit_code(), 2);

        let mismatch = Fake {
            org: Some("22222222-2222-4222-8222-222222222222".into()),
            ..Fake::default()
        };
        let (_dir, ledger) = self::ledger();
        let (outcome, _) = run_with(
            mismatch,
            &[("a.yaml", &a)],
            &options(Mode::Push, "s"),
            ledger,
        );
        assert_eq!(
            outcome.preflight.as_deref(),
            Some("organisation_uuid_mismatch")
        );

        let old = Fake {
            template: Some(TemplateView {
                version: Some(4),
                ..template()
            }),
            ..Fake::default()
        };
        let (_dir, ledger) = self::ledger();
        let (outcome, _) = run_with(old, &[("a.yaml", &a)], &options(Mode::Push, "s"), ledger);
        assert!(
            outcome.records[0]
                .notes
                .contains(&"template_version:4".to_owned())
        );

        let missing = Fake {
            template: Some(TemplateView::default()),
            ..Fake::default()
        };
        let (_dir, ledger) = self::ledger();
        let (outcome, _) = run_with(
            missing,
            &[("a.yaml", &a)],
            &options(Mode::Push, "s"),
            ledger,
        );
        assert_eq!(
            outcome.records[0].reason.as_deref(),
            Some("template_missing")
        );

        let galaxy = Fake {
            refuse: Some((
                "mitre-attack-pattern",
                MispCallError::new(Kind::Connectivity, "connectivity_failed", Some(502)),
            )),
            ..Fake::default()
        };
        let (_dir, ledger) = self::ledger();
        let (outcome, _) = run_with(galaxy, &[("a.yaml", &a)], &options(Mode::Push, "s"), ledger);
        assert_eq!(
            outcome.records[0].reason.as_deref(),
            Some("galaxy_lookup_failed")
        );
    }

    #[test]
    fn a_retract_unpublishes_deletes_and_forgets() {
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let a = rule(uuid, "green");
        let fake = Fake::default();
        fake.events
            .lock()
            .unwrap()
            .push(remote("e1", 7, ORG, uuid, true));
        let (_dir, ledger) = ledger();
        let (outcome, calls) = run_with(
            fake,
            &[("a.yaml", &a)],
            &options(Mode::Retract, "s"),
            ledger,
        );
        assert_eq!(outcome.records[0].action, "retracted");
        assert!(calls.contains(&"unpublish 7".to_owned()));

        let fake = Fake::default();
        fake.events
            .lock()
            .unwrap()
            .push(remote("e1", 7, ORG, uuid, false));
        let mut opts = options(Mode::Retract, "s");
        opts.delete = true;
        let (_dir, ledger) = self::ledger();
        let (outcome, _) = run_with(Fake::default(), &[("a.yaml", &a)], &opts, ledger);
        assert_eq!(outcome.preflight.as_deref(), Some("retract_unconfirmed"));
        opts.confirmed = true;
        let (_dir, ledger) = self::ledger();
        let (outcome, calls) = run_with(fake, &[("a.yaml", &a)], &opts, ledger);
        assert_eq!(outcome.records[0].action, "retracted");
        assert!(calls.contains(&"delete 7".to_owned()));
    }

    #[test]
    fn preview_and_status_read_the_ledger() {
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let a = rule(uuid, "green");
        let documents = documents_for_test(&[("a.yaml", &a)]);
        let (dir, mut ledger) = ledger();
        let mut line = Object::new();
        for (key, value) in [
            ("state", Json::Str("synced".into())),
            ("object_uuid", Json::Str(uuid.into())),
            ("integration", Json::Str("misp".into())),
            ("target", Json::Str("t".into())),
            ("content_hash", Json::Str(documents[0].content_hash())),
            ("remote_event_id", Json::Int(7)),
            ("published", Json::Bool(false)),
        ] {
            line.insert(key.into(), value);
        }
        ledger.put(line);
        let selected: Vec<&TideDocument> = documents.iter().collect();
        assert_eq!(
            preview(&selected, &[block("t")], &ledger, Some(false))[0].action,
            "unchanged"
        );
        assert_eq!(
            preview(&selected, &[block("t")], &ledger, Some(true))[0].action,
            "updated"
        );
        let records = status(&selected, &[block("t")], &ledger);
        assert_eq!(records[0].remote_event_id, Some(7));
        drop(dir);
        let mut no_org = block("t");
        no_org.organisation_uuid = None;
        assert_eq!(
            preview(&selected, &[no_org], &ledger, None)[0]
                .reason
                .as_deref(),
            Some("organisation_uuid_missing")
        );
    }

    #[test]
    fn filters_and_exit_codes() {
        let a = rule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "green");
        let documents = documents_for_test(&[("a.yaml", &a), ("b.yaml", "not: [valid")]);
        let filters = Filters {
            uuids: Some(vec!["nope".into()]),
            ..Filters::default()
        };
        assert!(selected(&documents, Some(&filters)).is_empty());
        let filters = Filters {
            types: Some(vec!["rule".into()]),
            ..Filters::default()
        };
        assert_eq!(selected(&documents, Some(&filters)).len(), 1);
        let (local, shareable) =
            split_local(&documents.iter().collect::<Vec<_>>(), &block("t"), None);
        assert_eq!(local[0].reason.as_deref(), Some("invalid_document"));
        assert_eq!(shareable.len(), 1);
        let partial = ShareRun {
            records: vec![
                Record::new("a", &block("t"), "created"),
                Record::failed("b", &block("t"), "x", Kind::Other, Vec::new()),
            ],
            preflight: None,
        };
        assert_eq!(partial.exit_code(), 3);
        assert_eq!(
            write_reason(
                &MispCallError::new(Kind::Rejected, "remote_rejected", None),
                true
            ),
            "remote_update_rejected"
        );
        assert_eq!(map(3, &[1, 2, 3, 4], &|n: &i32| n * 2), [2, 4, 6, 8]);
    }
}
