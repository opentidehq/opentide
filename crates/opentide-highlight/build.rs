//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The bundled Tide field catalog (`fields.json`, 1.1 MB of JSON) is parsed here, once, into the
//!   models of `src/tide_model.rs`, and stored pre-parsed (postcard, then zstd), with each string
//!   stored once (`fields.json` repeats its names, titles and descriptions for each revision of
//!   each schema), and the lists of enum values (440 KB of the file, the same list for each
//!   revision of each schema that has it) stored once each in a blob of their own, decoded when a
//!   field's list is first read: the first Tide
//!   document of a process used to parse all of it, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

// The crate reads the lists of the bundled table (`Repr::Bundled`); this script only writes it.
#[allow(
    dead_code,
    reason = "`Repr::Bundled` is the crate's, built when the stored catalog is read"
)]
#[path = "src/tide_model.rs"]
mod tide_model;

use std::collections::{BTreeMap, HashMap};
use tide_model::{Repr, StoredCatalog, StoredField, StoredVocab, TideFieldsFile};

const FIELDS: &str = "data/catalogs/tide/generated/fields.json";

/// Each distinct string once, by place.
#[derive(Default)]
struct Strings {
    places: HashMap<String, u32>,
    all: Vec<String>,
}

impl Strings {
    fn at(&mut self, text: &str) -> Result<u32, std::num::TryFromIntError> {
        if let Some(&place) = self.places.get(text) {
            return Ok(place);
        }
        let place = u32::try_from(self.all.len())?;
        self.places.insert(text.to_owned(), place);
        self.all.push(text.to_owned());
        Ok(place)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let text = std::fs::read_to_string(datasets.root().join(FIELDS))
        .map_err(|error| format!("{FIELDS}: {error}"))?;
    let file: TideFieldsFile =
        serde_json::from_str(&text).map_err(|error| format!("{FIELDS}: {error}"))?;

    let mut strings = Strings::default();
    let mut choice_places: BTreeMap<Vec<String>, u32> = BTreeMap::new();
    let mut choices: Vec<Vec<String>> = Vec::new();
    let mut fields = Vec::with_capacity(file.fields.len());
    for f in &file.fields {
        let Repr::Own(list) = &f.enum_values.0 else {
            return Err("fields.json read a list of the bundled table".into());
        };
        let values: Vec<String> = list.to_vec();
        let choice = if values.is_empty() {
            0
        } else {
            let next = u32::try_from(choices.len() + 1)?;
            *choice_places.entry(values.clone()).or_insert_with(|| {
                choices.push(values);
                next
            })
        };
        fields.push(StoredField {
            schema: strings.at(&f.schema)?,
            path: strings.at(&f.path)?,
            name: strings.at(&f.name)?,
            title: strings.at(&f.title)?,
            description: strings.at(&f.description)?,
            type_name: strings.at(&f.type_name)?,
            required: f.required,
            markdown: f.markdown,
            hidden: f.hidden,
            capture: strings.at(&f.capture)?,
            choices: choice,
            enum_docs: f
                .enum_docs
                .iter()
                .map(|v| strings.at(v))
                .collect::<Result<_, _>>()?,
            ref_kind: f.ref_kind.as_deref().map(|v| strings.at(v)).transpose()?,
            const_value: f
                .const_value
                .as_deref()
                .map(|v| strings.at(v))
                .transpose()?,
            array: f.array,
            default_value: f
                .default_value
                .as_deref()
                .map(|v| strings.at(v))
                .transpose()?,
            min_items: f.min_items,
            recommended: f.recommended,
            closed: f.closed,
            legacy: f
                .legacy
                .iter()
                .map(|(key, value)| {
                    Ok((
                        strings.at(key)?,
                        value.as_deref().map(|v| strings.at(v)).transpose()?,
                    ))
                })
                .collect::<Result<_, std::num::TryFromIntError>>()?,
        });
    }
    let vocabs: Vec<StoredVocab> = file
        .fields
        .iter()
        .filter(|f| !f.vocab.is_empty())
        .map(|f| StoredVocab {
            schema: f.schema.clone(),
            path: f.path.clone(),
            references: f.vocab.clone(),
            scoped: f.vocab_scoped,
        })
        .collect();
    datasets.value("tide-vocabs", &[FIELDS], &vocabs)?;
    datasets.value("tide-choices", &[FIELDS], &choices)?;
    datasets.value(
        "tide-fields",
        &[FIELDS],
        &StoredCatalog {
            opentide: file.opentide,
            schemas: file.schemas,
            strings: strings.all,
            fields,
        },
    )?;
    Ok(())
}
