//! CIM data model checks: the data model and dataset a search reads, and the
//! `<Dataset>.<field>` names it uses (#115, tier 1 of #110).
//!
//! `| tstats ... from datamodel=Endpoint.Processes`, `| datamodel Endpoint
//! Processes`, `| from datamodel:Endpoint.Processes` and `| pivot Endpoint
//! Processes` name a data model and dataset. After them, `Processes.<field>`
//! names a field of the dataset's root, until
//! `` `drop_dm_object_name(Processes)` `` (or `rename Processes.* as *`)
//! strips the prefix.
//!
//! The catalog (`catalogs/spl/datamodels.toml`) lists every CIM data model,
//! dataset and field. Sites extend their CIM models with fields and datasets
//! of their own, and Enterprise Security and apps add data models, so a name
//! the catalog lacks is not an error by itself. Precision over recall: a
//! name is an error only when the catalog lacks it **and** it is a near miss
//! of one the catalog has (`proces_name` for `process_name`, `Endpont` for
//! `Endpoint`). CIM has no strict types, and its expected values are
//! recommendations that real add-ons do not always follow
//! (`reply_code=NXDOMAIN`), so values are offered as completions, never
//! checked.

use super::scan::{
    command_word, end_of_brackets, end_of_macro, end_quoted, skip_comment, skip_hidden, skip_ws,
    split_segments, subsearches,
};
use super::{Catalog, DatamodelRow};
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Fields every dataset has: the CIM base event's, and the default fields a
/// search can read on any event.
const BASE_FIELDS: &[&str] = &[
    "_time",
    "_raw",
    "_indextime",
    "host",
    "source",
    "sourcetype",
    "index",
    "splunk_server",
    "linecount",
    "punct",
    "eventtype",
    "tag",
];

/// The data models the catalog knows, built once from [`Catalog::cached`].
pub(crate) struct Cim {
    models: Vec<Model>,
}

pub(crate) struct Model {
    pub name: String,
    /// Every dataset row is `complete`: its datasets and fields are checked.
    pub complete: bool,
    pub datasets: Vec<&'static DatamodelRow>,
}

impl Model {
    fn dataset(&self, object: &str) -> Option<&'static DatamodelRow> {
        self.datasets
            .iter()
            .copied()
            .find(|d| d.object().eq_ignore_ascii_case(object))
    }

    fn has_object(&self, object: &str) -> bool {
        self.datasets.iter().any(|d| d.object() == object)
    }

    fn roots(&self) -> impl Iterator<Item = &'static DatamodelRow> + '_ {
        self.datasets
            .iter()
            .copied()
            .filter(|d| !d.lineage().contains('.'))
    }

    /// Every field the datasets under `root` define, with the base fields.
    fn tree_fields(&self, root: &str) -> BTreeSet<&'static str> {
        let mut out: BTreeSet<&'static str> = BASE_FIELDS.iter().copied().collect();
        for d in &self.datasets {
            if d.prefix == root {
                out.extend(d.fields.iter().map(String::as_str));
            }
        }
        out
    }
}

impl Cim {
    pub(crate) fn cached() -> &'static Self {
        static CIM: OnceLock<Cim> = OnceLock::new();
        CIM.get_or_init(|| Self::build(Catalog::cached()))
    }

    fn build(catalog: &'static Catalog) -> Self {
        let mut models: Vec<Model> = Vec::new();
        for row in &catalog.datamodels {
            let name = row.model_name();
            match models.iter_mut().find(|m| m.name == name) {
                Some(m) => {
                    m.complete &= row.complete;
                    m.datasets.push(row);
                }
                None => models.push(Model {
                    name: name.to_string(),
                    complete: row.complete,
                    datasets: vec![row],
                }),
            }
        }
        for name in &catalog.extra_models {
            if !models.iter().any(|m| m.name.eq_ignore_ascii_case(name)) {
                models.push(Model {
                    name: name.clone(),
                    complete: false,
                    datasets: Vec::new(),
                });
            }
        }
        Self { models }
    }

    pub(crate) fn model(&self, name: &str) -> Option<&Model> {
        self.models
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }

    /// The dataset a `Model.Dataset` reference names (`Endpoint` alone: its
    /// first root dataset).
    pub(crate) fn dataset(&self, reference: &str) -> Option<&'static DatamodelRow> {
        let (model, path) = match reference.split_once('.') {
            Some((model, path)) => (self.model(model)?, Some(path)),
            None => (self.model(reference)?, None),
        };
        match path.and_then(|p| p.rsplit('.').next()) {
            Some(object) => model.dataset(object),
            None => model.roots().next(),
        }
    }
}

/// A data model a search reads: `text` is `Model.Dataset`; the authored
/// span separates the model from the dataset with `sep` (`.`, or a space in
/// `| datamodel Endpoint Processes`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DatamodelRef {
    start: usize,
    end: usize,
    text: String,
    sep: char,
}

/// A prefix the search's field names carry, and the model it belongs to.
struct Prefix<'a> {
    alias: String,
    root: String,
    model: &'a Model,
}

pub(crate) fn collect(source: &str, out: &mut Vec<Diagnostic>) {
    if source.is_empty() {
        return;
    }
    let cim = Cim::cached();
    walk(source, 0, source.len(), cim, out);
}

fn walk(source: &str, start: usize, end: usize, cim: &Cim, out: &mut Vec<Diagnostic>) {
    let mut prefixes: Vec<Prefix> = Vec::new();
    for (seg_start, seg_end) in split_segments(source, start, end) {
        for (inner_start, inner_end) in subsearches(source, seg_start, seg_end) {
            walk(source, inner_start, inner_end, cim, out);
        }
        let word = command(source, seg_start, seg_end);
        let refs = refs_in_segment(source, seg_start, seg_end, &word);
        for r in &refs {
            if let Some(diag) = check_ref(source, r, cim) {
                out.push(diag);
                continue;
            }
            activate(r, cim, &mut prefixes);
        }
        if let Some(dropped) = dropped_prefix(source, seg_start, seg_end) {
            prefixes.retain(|p| p.alias != dropped);
            continue;
        }
        if prefixes.is_empty() {
            continue;
        }
        for (tok_start, tok_end) in field_tokens(source, seg_start, seg_end, &word) {
            if refs.iter().any(|r| tok_start < r.end && r.start < tok_end) {
                continue;
            }
            if let Some(diag) = check_field(source, tok_start, tok_end, &prefixes) {
                out.push(diag);
            }
        }
        if word == "rename" {
            let text = &source[seg_start..seg_end];
            prefixes.retain(|p| !text.contains(&format!("{}.*", p.alias)));
        }
    }
}

/// The lowercase command word of a segment (`tstats`), empty for a search.
fn command(source: &str, start: usize, end: usize) -> String {
    command_word(source, start, end).0.to_ascii_lowercase()
}

/// The data models a segment reads: `tstats ... from datamodel=X`,
/// `datamodel X Y`, `from datamodel:X` and `pivot X Y`.
fn refs_in_segment(source: &str, start: usize, end: usize, word: &str) -> Vec<DatamodelRef> {
    match word {
        "tstats" => tstats_refs(source, start, end),
        "datamodel" | "pivot" => {
            let words = plain_words(source, start, end, 3);
            // words[0] is the command itself.
            match words.as_slice() {
                [_, model, dataset, ..] if is_name(source, *model) && is_name(source, *dataset) => {
                    vec![DatamodelRef {
                        start: model.0,
                        end: dataset.1,
                        text: format!(
                            "{}.{}",
                            &source[model.0..model.1],
                            &source[dataset.0..dataset.1]
                        ),
                        sep: ' ',
                    }]
                }
                [_, model, ..] if is_name(source, *model) => vec![DatamodelRef {
                    start: model.0,
                    end: model.1,
                    text: source[model.0..model.1].to_string(),
                    sep: ' ',
                }],
                _ => Vec::new(),
            }
        }
        "from" => from_refs(source, start, end),
        _ => Vec::new(),
    }
}

fn is_name(source: &str, (start, end): (usize, usize)) -> bool {
    let text = &source[start..end];
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        && !matches!(
            text.to_ascii_lowercase().as_str(),
            "search" | "flat" | "acceleration_search" | "summariesonly"
        )
}

/// Whitespace-separated words of a segment, at most `limit`, stopping at the
/// first word that is not a plain name (an option `x=y`, a string, a macro).
fn plain_words(source: &str, start: usize, end: usize, limit: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = start;
    while i < end && out.len() < limit {
        while i < end && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if let Some(next) = skip_comment(source, i, end) {
            i = next;
            continue;
        }
        let word_start = i;
        while i < end && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if word_start == i {
            break;
        }
        let word = &source[word_start..i];
        if !word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            break;
        }
        out.push((word_start, i));
    }
    out
}

/// `datamodel=X` (with optional spaces and quotes) anywhere in a tstats
/// segment.
fn tstats_refs(source: &str, start: usize, end: usize) -> Vec<DatamodelRef> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = start;
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        if bytes[i] == b'[' {
            i = end_of_brackets(source, i, end);
            continue;
        }
        if keyword_at(source, i, end, "datamodel") {
            let mut j = skip_ws(bytes, i + "datamodel".len(), end);
            if j < end && bytes[j] == b'=' {
                j = skip_ws(bytes, j + 1, end);
                if let Some(r) = value_at(source, j, end) {
                    i = r.end;
                    out.push(r);
                    continue;
                }
            }
            i += "datamodel".len();
            continue;
        }
        i += 1;
    }
    out
}

/// `from datamodel:X`, `from datamodel X`, `from datamodel="X"`.
fn from_refs(source: &str, start: usize, end: usize) -> Vec<DatamodelRef> {
    let bytes = source.as_bytes();
    let words = plain_words(source, start, end, 1);
    let Some(&(_, after_from)) = words.first() else {
        return Vec::new();
    };
    let i = skip_ws(bytes, after_from, end);
    if !keyword_at(source, i, end, "datamodel") {
        return Vec::new();
    }
    let mut j = i + "datamodel".len();
    if j < end && (bytes[j] == b':' || bytes[j] == b'=') {
        j += 1;
    } else if j < end && !bytes[j].is_ascii_whitespace() {
        return Vec::new();
    }
    let j = skip_ws(bytes, j, end);
    value_at(source, j, end).into_iter().collect()
}

/// A data model name at `i`: quoted or bare.
fn value_at(source: &str, i: usize, end: usize) -> Option<DatamodelRef> {
    let bytes = source.as_bytes();
    if i >= end {
        return None;
    }
    let (start, stop) = if bytes[i] == b'"' || bytes[i] == b'\'' {
        let close = end_quoted(bytes, i, end);
        (i + 1, close.saturating_sub(1).max(i + 1))
    } else {
        let mut j = i;
        while j < end && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'_' | b'.')) {
            j += 1;
        }
        (i, j)
    };
    let text = source.get(start..stop)?.trim_end_matches('.');
    if text.is_empty()
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
    {
        return None;
    }
    Some(DatamodelRef {
        start,
        end: start + text.len(),
        text: text.to_string(),
        sep: '.',
    })
}

fn keyword_at(source: &str, i: usize, end: usize, keyword: &str) -> bool {
    let bytes = source.as_bytes();
    let stop = i + keyword.len();
    if stop > end || !bytes[i..stop].eq_ignore_ascii_case(keyword.as_bytes()) {
        return false;
    }
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (i == 0 || !ident(bytes[i - 1])) && (stop >= bytes.len() || !ident(bytes[stop]))
}

/// The smallest edit that turns `name` into a candidate, when `name` is a
/// near miss: one edit for names of up to five characters, two for longer
/// ones, nothing for names shorter than four. Exact matches are not misses.
pub(crate) fn near_miss<'a>(
    name: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    fold_case: bool,
) -> Option<&'a str> {
    let len = name.chars().count();
    if len < 4 {
        return None;
    }
    let budget = if len <= 5 { 1 } else { 2 };
    let norm = |s: &str| {
        if fold_case {
            s.to_ascii_lowercase()
        } else {
            s.to_string()
        }
    };
    let wanted = norm(name);
    let mut best: Option<(&str, usize)> = None;
    for candidate in candidates {
        if candidate.chars().count() < 4 {
            continue;
        }
        let dist = edit_distance(&wanted, &norm(candidate));
        if dist == 0 {
            return None;
        }
        if dist <= budget && best.is_none_or(|(_, d)| dist < d) {
            best = Some((candidate, dist));
        }
    }
    best.map(|(c, _)| c)
}

/// Edits (insert, delete, substitute, or swap two adjacent characters) that
/// turn `a` into `b`: a swapped pair (`qeury`) is one typo, not two.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

fn range(source: &str, start: usize, end: usize) -> opentide_core::Range {
    span_to_range(source, ByteSpan::new(start, end.max(start + 1)))
}

/// An error when the reference names a data model or dataset that is a near
/// miss of a CIM one.
fn check_ref(source: &str, r: &DatamodelRef, cim: &Cim) -> Option<Diagnostic> {
    let mut parts = r.text.split('.');
    let model_name = parts.next()?;
    let path: Vec<&str> = parts.collect();
    // The reference as authored, with the model and path replaced.
    let fixed = |model: &str, path: &[&str]| {
        if path.is_empty() {
            model.to_string()
        } else {
            format!("{model}{}{}", r.sep, path.join("."))
        }
    };
    let Some(model) = cim.model(model_name) else {
        let best = near_miss(model_name, cim.models.iter().map(|m| m.name.as_str()), true)?;
        return Some(
            Diagnostic::error(
                codes::SPL_UNKNOWN_DATAMODEL,
                format!("`{model_name}` is not a CIM data model; did you mean `{best}`?"),
                range(source, r.start, r.end),
            )
            .with_suggestion(fixed(best, &path)),
        );
    };
    if !model.complete {
        return None;
    }
    for (i, segment) in path.iter().enumerate() {
        if model.dataset(segment).is_some() {
            continue;
        }
        let best = near_miss(segment, model.datasets.iter().map(|d| d.object()), true)?;
        let mut corrected = path.clone();
        corrected[i] = best;
        return Some(
            Diagnostic::error(
                codes::SPL_UNKNOWN_DATAMODEL,
                format!(
                    "`{segment}` is not a dataset of the CIM {} data model; did you mean `{best}`?",
                    model.name
                ),
                range(source, r.start, r.end),
            )
            .with_suggestion(fixed(model_name, &corrected)),
        );
    }
    None
}

/// The prefixes a data model reference brings into scope: the root dataset
/// (`Processes`), and the dataset's own name and lineage for a child dataset.
fn activate<'a>(r: &DatamodelRef, cim: &'a Cim, prefixes: &mut Vec<Prefix<'a>>) {
    let mut parts = r.text.split('.');
    let Some(model) = parts.next().and_then(|m| cim.model(m)) else {
        return;
    };
    if !model.complete {
        return;
    }
    let path: Vec<&str> = parts.collect();
    let mut add = |alias: &str, root: &str| {
        if !prefixes.iter().any(|p| p.alias == alias) {
            prefixes.push(Prefix {
                alias: alias.to_string(),
                root: root.to_string(),
                model,
            });
        }
    };
    if path.is_empty() {
        for d in model.roots() {
            add(&d.prefix, &d.prefix);
        }
        return;
    }
    let Some(dataset) = path.last().and_then(|object| model.dataset(object)) else {
        return;
    };
    for segment in dataset.lineage().split('.') {
        add(segment, &dataset.prefix);
    }
}

/// `drop_dm_object_name(X)` alone in a segment strips the `X.` prefix.
fn dropped_prefix(source: &str, start: usize, end: usize) -> Option<String> {
    let text = source[start..end].trim();
    let inner = text.strip_prefix('`')?.strip_suffix('`')?;
    let args = inner
        .strip_prefix("drop_dm_object_name(")?
        .strip_suffix(')')?;
    Some(
        args.trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .trim()
            .to_string(),
    )
}

/// Dotted names in a segment that can be field references: not in a string,
/// macro, comment or subsearch, not a value (`x=Processes.y`), not the target
/// of `as` or of an `eval` assignment, and not a wildcard or a call.
fn field_tokens(source: &str, start: usize, end: usize, word: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let assigns = matches!(word, "eval" | "fieldformat");
    let mut out = Vec::new();
    let mut i = start;
    let mut prev_sig = b' ';
    let mut prev_word_as = false;
    let is_tok = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.';
    while i < end {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if let Some(next) = skip_comment(source, i, end) {
            i = next;
            prev_sig = b'`';
            prev_word_as = false;
            continue;
        }
        if b == b'"' || b == b'\'' {
            i = end_quoted(bytes, i, end);
            prev_sig = b'"';
            prev_word_as = false;
            continue;
        }
        if b == b'`' {
            i = end_of_macro(bytes, i, end);
            prev_sig = b'`';
            prev_word_as = false;
            continue;
        }
        if b == b'[' {
            i = end_of_brackets(source, i, end);
            prev_sig = b']';
            prev_word_as = false;
            continue;
        }
        if !is_tok(b) {
            prev_sig = b;
            prev_word_as = false;
            i += 1;
            continue;
        }
        let tok_start = i;
        while i < end && is_tok(bytes[i]) {
            i += 1;
        }
        let tok = &source[tok_start..i];
        let adjacent = if tok_start > start {
            bytes[tok_start - 1]
        } else {
            b' '
        };
        let next = if i < end { bytes[i] } else { b' ' };
        let after = skip_ws(bytes, i, end);
        let assignment = assigns
            && after < end
            && bytes[after] == b'='
            && bytes.get(after + 1).copied() != Some(b'=');
        let candidate = tok.contains('.')
            && (adjacent.is_ascii_whitespace() || matches!(adjacent, b'(' | b',' | b'|'))
            && !matches!(prev_sig, b'=' | b'<' | b'>' | b'!')
            && !matches!(next, b'*' | b'(' | b':')
            && !prev_word_as
            && !assignment;
        if candidate {
            out.push((tok_start, i));
        }
        prev_word_as = tok.eq_ignore_ascii_case("as");
        prev_sig = bytes[i - 1];
    }
    out
}

/// An error when `Prefix.field` names a near miss of a field the dataset has.
fn check_field(source: &str, start: usize, end: usize, prefixes: &[Prefix]) -> Option<Diagnostic> {
    let token = &source[start..end];
    let segments: Vec<&str> = token.split('.').collect();
    let prefix = prefixes.iter().find(|p| p.alias == segments[0])?;
    let model = prefix.model;
    // Child dataset names between the prefix and the field
    // (`All_Changes.Account_Management.src_user`).
    let mut i = 1;
    while i < segments.len() && model.has_object(segments[i]) {
        i += 1;
    }
    if i != segments.len() - 1 {
        // A dataset path (`nodename=All_Traffic.Traffic_By_Action`), or a
        // dotted name the model does not define.
        return None;
    }
    let field = segments[i];
    if field.is_empty() {
        return None;
    }
    let known = model.tree_fields(&prefix.root);
    if known.contains(field) {
        return None;
    }
    let best = near_miss(field, known.iter().copied(), false)?;
    let mut fixed = segments[..i].join(".");
    fixed.push('.');
    fixed.push_str(best);
    let dataset = model
        .datasets
        .iter()
        .find(|d| d.prefix == prefix.root)
        .map(|d| d.name.as_str())
        .unwrap_or(model.name.as_str());
    Some(
        Diagnostic::error(
            codes::SPL_UNKNOWN_DATAMODEL_FIELD,
            format!(
                "`{field}` is not a field of the CIM {dataset} dataset; did you mean `{fixed}`?"
            ),
            range(source, start, end),
        )
        .with_suggestion(fixed),
    )
}

/// The first data model the search reads, for completion and hover.
pub(crate) fn first_dataset(source: &str) -> Option<&'static DatamodelRow> {
    let cim = Cim::cached();
    first_ref(source, 0, source.len()).and_then(|r| cim.dataset(&r.text))
}

fn first_ref(source: &str, start: usize, end: usize) -> Option<DatamodelRef> {
    for (seg_start, seg_end) in split_segments(source, start, end) {
        let word = command(source, seg_start, seg_end);
        if let Some(r) = refs_in_segment(source, seg_start, seg_end, &word)
            .into_iter()
            .next()
        {
            return Some(r);
        }
    }
    None
}

/// The values CIM expects for the `Prefix.field` that `before` ends with an
/// `=` after (`Authentication.action=`), for completion.
pub(crate) fn expected_values(source: &str, before: &str) -> Option<&'static [String]> {
    let trimmed = before.trim_end();
    let left = trimmed.strip_suffix('=')?;
    if left.ends_with(['=', '!', '<', '>']) {
        return None;
    }
    let left = left.trim_end();
    let token = left
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .next()?;
    let (alias, field) = token.split_once('.')?;
    let field = field.rsplit('.').next()?;
    let dataset = first_dataset(source)?;
    let model = Cim::cached().model(dataset.model_name())?;
    let mut rows: Vec<&&'static DatamodelRow> = model
        .datasets
        .iter()
        .filter(|d| d.prefix == alias || d.lineage().split('.').any(|s| s == alias))
        .collect();
    rows.sort_by_key(|d| d.lineage().matches('.').count());
    rows.into_iter()
        .find_map(|d| d.values.get(field))
        .map(Vec::as_slice)
}

/// The fields a search can name on `dataset`: its root's and ancestors'
/// fields under the root prefix, its own under its lineage.
pub(crate) fn visible_fields(dataset: &DatamodelRow) -> Vec<(String, &'static str)> {
    let cim = Cim::cached();
    let Some(model) = cim.model(dataset.model_name()) else {
        return Vec::new();
    };
    let lineage = dataset.lineage();
    let mut out = Vec::new();
    for d in &model.datasets {
        let l = d.lineage();
        let ancestor = lineage == l || lineage.starts_with(&format!("{l}."));
        if ancestor {
            for f in &d.fields {
                out.push((format!("{l}.{f}"), f.as_str()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;
    use opentide_core::Severity;

    fn diags(src: &str, code: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == code)
            .collect()
    }

    fn field_errors(src: &str) -> Vec<Diagnostic> {
        diags(src, codes::SPL_UNKNOWN_DATAMODEL_FIELD)
    }

    #[test]
    fn misspelled_field_is_an_error_with_a_suggestion() {
        let src = "| tstats count from datamodel=Endpoint.Processes by Processes.proces_name";
        let found = field_errors(src);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].severity, Severity::Error);
        assert_eq!(
            found[0].suggestion.as_deref(),
            Some("Processes.process_name")
        );
        let at = src.find("Processes.proces_name").unwrap() as u32;
        assert_eq!(found[0].range.start.character, at);
        assert_eq!(
            found[0].range.end.character,
            at + "Processes.proces_name".len() as u32
        );
    }

    #[test]
    fn real_fields_and_custom_fields_are_not_errors() {
        for src in [
            "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest Processes.user Processes.parent_process_name _time span=1h",
            // A field a site adds to its model is not a near miss of a CIM one.
            "| tstats count from datamodel=Endpoint.Processes by Processes.my_custom_field",
            // Asset and identity fields Enterprise Security adds.
            "| tstats count from datamodel=Endpoint.Processes by Processes.dest_bunit Processes.user_category",
            // Child dataset lineage.
            "| tstats count from datamodel=Change.All_Changes by All_Changes.Account_Management.src_user All_Changes.user",
            "| tstats count from datamodel=Email.All_Email by All_Email.Filtering.filter_action",
            // nodename is a dataset path, not a field.
            "| tstats count from datamodel=Network_Traffic.All_Traffic where nodename=All_Traffic.Traffic_By_Action.Blocked_Traffic by All_Traffic.src",
            // Prefix of a model the search does not read.
            "index=main | stats count by Processes.proces_name",
            // A value, not a field.
            "| tstats count from datamodel=Web where Web.url=Web.confg by Web.src",
        ] {
            assert!(
                field_errors(src).is_empty(),
                "{src}: {:?}",
                field_errors(src)
            );
        }
    }

    #[test]
    fn drop_dm_object_name_ends_the_prefix() {
        let src = "| tstats count from datamodel=Endpoint.Processes by Processes.process_name | `drop_dm_object_name(Processes)` | where process_name=\"cmd.exe\" | table process_name Processes.proces_name";
        assert!(field_errors(src).is_empty(), "{:?}", field_errors(src));
        let quoted = "| tstats count from datamodel=Web by Web.src | `drop_dm_object_name(\"Web\")` | stats count by Web.srcc";
        assert!(
            field_errors(quoted).is_empty(),
            "{:?}",
            field_errors(quoted)
        );
        let before = "| tstats count from datamodel=Endpoint.Processes by Processes.process_name | where Processes.proces_name=\"x\" | `drop_dm_object_name(Processes)`";
        assert_eq!(field_errors(before).len(), 1);
    }

    #[test]
    fn model_only_reference_checks_every_root() {
        let src = "| tstats count from datamodel=Network_Resolution by DNS.qeury";
        let found = field_errors(src);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].suggestion.as_deref(), Some("DNS.query"));
        let upper = "| tstats count FROM datamodel = \"Web\" WHERE Web.url_domian!=\"\" BY Web.src";
        let found = field_errors(upper);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].suggestion.as_deref(), Some("Web.url_domain"));
    }

    #[test]
    fn unknown_datamodel_only_for_near_misses() {
        let typo = diags(
            "| tstats count from datamodel=Endpont.Processes by Processes.dest",
            codes::SPL_UNKNOWN_DATAMODEL,
        );
        assert_eq!(typo.len(), 1, "{typo:?}");
        assert_eq!(typo[0].severity, Severity::Error);
        assert_eq!(typo[0].suggestion.as_deref(), Some("Endpoint.Processes"));
        let dataset = diags(
            "| tstats count from datamodel=Endpoint.Process by Processes.dest",
            codes::SPL_UNKNOWN_DATAMODEL,
        );
        assert_eq!(dataset.len(), 1, "{dataset:?}");
        assert_eq!(dataset[0].suggestion.as_deref(), Some("Endpoint.Processes"));
        for src in [
            // Enterprise Security and site data models.
            "| tstats count from datamodel=Risk.All_Risk by All_Risk.risk_object",
            "| tstats count from datamodel=Threat_Intelligence.Threat_Activity by Threat_Activity.threat_match_field",
            "| tstats count from datamodel=My_Custom_Model.Things by Things.whatever",
            "| tstats count from datamodel=Authentication.Failed_Authentication by Authentication.user",
            "| tstats count from datamodel=Network_Traffic.All_Traffic.Traffic_By_Action.Blocked_Traffic by All_Traffic.dest",
            "| datamodel Endpoint Processes search | stats count by Processes.process_name",
            "| from datamodel:\"Endpoint.Registry\" | stats count by registry_path",
            "| from datamodel Risk.All_Risk | search risk_score>0",
        ] {
            let found = analyze(src)
                .diagnostics
                .into_iter()
                .filter(|d| {
                    d.code == codes::SPL_UNKNOWN_DATAMODEL
                        || d.code == codes::SPL_UNKNOWN_DATAMODEL_FIELD
                })
                .collect::<Vec<_>>();
            assert!(found.is_empty(), "{src}: {found:?}");
        }
    }

    #[test]
    fn datamodel_and_from_commands_are_checked() {
        let found = field_errors(
            "| datamodel Endpoint Processes search | stats count by Processes.parent_proces_name",
        );
        assert_eq!(found.len(), 1, "{found:?}");
        let found = diags(
            "| from datamodel:Endpoint.Registy | stats count",
            codes::SPL_UNKNOWN_DATAMODEL,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].suggestion.as_deref(), Some("Endpoint.Registry"));
        // The suggestion keeps the authored separator.
        let src = "| datamodel Endpont Processes search";
        let found = diags(src, codes::SPL_UNKNOWN_DATAMODEL);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].suggestion.as_deref(), Some("Endpoint Processes"));
        let at = src.find("Endpont").unwrap() as u32;
        assert_eq!(found[0].range.start.character, at);
        assert_eq!(
            found[0].range.end.character,
            at + "Endpont Processes".len() as u32
        );
    }

    #[test]
    fn subsearches_have_their_own_data_model() {
        let src = "| tstats count from datamodel=Web by Web.src | append [| tstats count from datamodel=Endpoint.Processes by Processes.proces_name] | stats count by Web.srcc";
        let found = field_errors(src);
        let names: Vec<_> = found.iter().map(|d| d.suggestion.clone()).collect();
        assert_eq!(names.len(), 1, "{found:?}");
        assert_eq!(names[0].as_deref(), Some("Processes.process_name"));
    }

    #[test]
    fn eval_targets_and_aliases_are_not_checked() {
        let src = "| tstats values(Processes.process) as Processes.proces from datamodel=Endpoint.Processes by Processes.dest | eval Processes.proces_nam=1";
        assert!(field_errors(src).is_empty(), "{:?}", field_errors(src));
    }

    #[test]
    fn non_ascii_text_before_a_keyword_does_not_panic() {
        // Comparing `datamodel` against the next nine bytes once sliced
        // through a Cyrillic character.
        let src = "| tstats count from datamodel=Endpoint.Processes where Processes.process=\"*администратор*\" by Processes.proces_name";
        assert_eq!(field_errors(src).len(), 1);
        let src = "index=x \"администраторы\" | from datamodel:Endpoint.Processes";
        assert!(diags(src, codes::SPL_UNKNOWN_DATAMODEL).is_empty());
        let src = "| tstats count FROM datamodel=Endpoint.Processes WHERE Processes.process IN (\"*Rendszergazda*\", \"*Администратор*\", \"*Administratör*\") BY Processes.dest";
        assert!(field_errors(src).is_empty());
    }

    #[test]
    fn completion_offers_lineage_fields_and_expected_values() {
        let src = "| tstats count from datamodel=Email.Filtering by ";
        let labels: Vec<String> = crate::completions(src, src.len())
            .into_iter()
            .map(|i| i.label)
            .collect();
        assert!(
            labels
                .iter()
                .any(|l| l == "All_Email.Filtering.filter_action"),
            "{labels:?}"
        );
        assert!(
            labels.iter().any(|l| l == "All_Email.recipient"),
            "{labels:?}"
        );
        let src = "| tstats count from datamodel=Authentication where Authentication.action=";
        let labels: Vec<String> = crate::completions(src, src.len())
            .into_iter()
            .map(|i| i.label)
            .collect();
        assert!(labels.iter().any(|l| l == "success"), "{labels:?}");
        assert!(labels.iter().any(|l| l == "failure"), "{labels:?}");
    }

    #[test]
    fn near_miss_thresholds() {
        let c = ["process_name", "user", "dest"];
        assert_eq!(near_miss("proces_name", c, false), Some("process_name"));
        assert_eq!(near_miss("users", c, false), Some("user"));
        assert_eq!(near_miss("usr", c, false), None);
        assert_eq!(near_miss("process_name", c, false), None);
        assert_eq!(near_miss("totally_different", c, false), None);
        assert_eq!(near_miss("Endpont", ["Endpoint"], true), Some("Endpoint"));
    }

    #[test]
    fn catalog_covers_every_cim_model() {
        let cim = Cim::cached();
        for name in [
            "Alerts",
            "Authentication",
            "Certificates",
            "Change",
            "Compute_Inventory",
            "DLP",
            "Data_Access",
            "Databases",
            "Email",
            "Endpoint",
            "Event_Signatures",
            "Interprocess_Messaging",
            "Intrusion_Detection",
            "JVM",
            "Malware",
            "Network_Resolution",
            "Network_Sessions",
            "Network_Traffic",
            "Performance",
            "Ticket_Management",
            "Updates",
            "Vulnerabilities",
            "Web",
        ] {
            let model = cim.model(name).unwrap_or_else(|| panic!("{name}"));
            assert!(model.complete, "{name}");
        }
        let processes = cim.dataset("Endpoint.Processes").unwrap();
        for f in [
            "process_name",
            "process_integrity_level",
            "parent_process_exec",
            "original_file_name",
        ] {
            assert!(processes.fields.iter().any(|x| x == f), "{f}");
        }
        assert!(!cim.model("Risk").unwrap().complete);
    }
}
