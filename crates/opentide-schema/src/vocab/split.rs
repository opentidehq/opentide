//! A bundled vocabulary's text split in two (#1743): the document **without** its entries'
//! descriptions, and the descriptions.
//!
//! The descriptions are most of a vocabulary's text (ATT&CK's: 1.2 of its 1.45 MB), and a
//! validation reads keys, names and versions, never a description (#1071). Stored as two blobs,
//! a command that never asks for one decodes the first only. Shared by the crate's tests and by
//! its build script (`#[path]`): this file depends on nothing.
//!
//! The form is the one the vocabulary sync writes (`cargo xtask vocab`): an entry is a `[[keys]]`
//! table, and its description a single line that starts `description = `. Every such line inside
//! a `[[keys]]` entry is moved; the second text holds them in entry order, one line each, an empty
//! line for an entry without one. A line of any other table (the stages' descriptions, the
//! document's own) stays where it is.

/// The line of an entry that holds its description.
const DESCRIPTION_LINE: &str = "description = ";

/// `text` without its entries' descriptions, and those descriptions, a line for each entry.
pub fn split(text: &str) -> (String, String) {
    let mut lean = String::with_capacity(text.len() / 4);
    let mut descriptions = String::with_capacity(text.len());
    let mut in_keys = false;
    let mut entries = 0_usize;
    let mut described = false;
    for line in text.split_inclusive('\n') {
        if line.starts_with('[') {
            let header = line.trim_end();
            if header == "[[keys]]" {
                if entries > 0 && !described {
                    descriptions.push('\n');
                }
                entries += 1;
                described = false;
                in_keys = true;
            } else {
                in_keys = false;
            }
        } else if in_keys && line.starts_with(DESCRIPTION_LINE) {
            descriptions.push_str(line.trim_end_matches('\n'));
            descriptions.push('\n');
            described = true;
            continue;
        }
        lean.push_str(line);
    }
    if entries > 0 && !described {
        descriptions.push('\n');
    }
    (lean, descriptions)
}
