//! Falco rule exceptions, as Falco's rule loader reads them
//! (falcosecurity/falco `userspace/engine/rule_loader_collector.cpp`
//! `validate_exception_info`, and `rule_loader_compiler.cpp`
//! `build_rule_exception_infos`, Apache-2.0):
//!
//! - **tuple form** (`fields` a list): `comps` defaults to `=` for each field;
//!   `fields` and `comps` have the same length; every comparison is an operator
//!   the parser knows or a string operator with a modifier
//!   (`startswith oneof`); every row of `values` has one item per field;
//! - **single-field form** (`fields` a string): `comps` defaults to `in`, is a
//!   string, and is `in`, `pmatch`, `intersects`, or a string operator with a
//!   modifier; every value is a scalar;
//! - each field is one the source knows (a field with a transformer is
//!   compiled as `<field> exists`);
//! - then Falco writes the exception into the condition as text (`and not
//!   ((f1 c1 v1 and f2 c2 v2) or ...)`, quoting an item with a space) and
//!   compiles it with the rule: a value the field's type cannot hold, or an
//!   item the text breaks on, refuses the rule.

use crate::compile::{Compiler, Level};
use crate::{Catalog, Context, expand_lists, parser};
use opentide_core::codes;

/// A YAML string or list of strings (`fields`, `comps`).
#[derive(Debug, Clone, PartialEq)]
pub enum Strs {
    One(String),
    Many(Vec<String>),
}

/// One item of `values`: a scalar, or a list (a tuple row, or the list an
/// `in` item takes).
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Scalar(String),
    List(Vec<Item>),
}

/// One `exceptions[]` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Exception {
    pub name: String,
    pub fields: Option<Strs>,
    pub comps: Option<Strs>,
    pub values: Vec<Item>,
}

/// A finding on one exception: the key it is about (`fields`, `comps`,
/// `values`, or `name`), the code, the level, the message.
#[derive(Debug, Clone, PartialEq)]
pub struct ExceptionFinding {
    pub index: usize,
    pub key: &'static str,
    pub code: &'static str,
    pub level: Level,
    pub message: String,
}

fn is_operator(op: &str) -> bool {
    parser::OPERATORS.contains(&op)
}

/// `is_str_operator_with_modifier`.
fn is_modifier_op(op: &str) -> bool {
    let Some((base, modifier)) = op.split_once(' ') else {
        return false;
    };
    parser::MODIFIERS.contains(&modifier)
        && matches!(
            base,
            "=" | "=="
                | "!="
                | "contains"
                | "icontains"
                | "bcontains"
                | "startswith"
                | "bstartswith"
                | "endswith"
                | "glob"
                | "iglob"
                | "regex"
        )
}

fn is_list_op(op: &str) -> bool {
    parser::LIST_OPERATORS.contains(&op) || is_modifier_op(op)
}

/// Falco's `normalize_comp`.
fn normalize(op: &str) -> String {
    op.trim_matches([' ', '\t', '\r', '\n']).to_string()
}

fn quote_item(item: &str) -> String {
    crate::quote_item(item)
}

fn paren_item(item: &str) -> String {
    if item.starts_with('(') {
        item.to_string()
    } else {
        format!("({item})")
    }
}

/// `source->is_valid_lhs_field`.
fn valid_lhs(field: &str, source: &str) -> Result<(), String> {
    let catalog = Catalog::cached();
    if field.contains('(') {
        let ast = parser::parse(&format!("{field} exists")).map_err(|e| e.message)?;
        let mut compiler = Compiler::new(catalog, source);
        compiler.condition(&ast);
        return match compiler.findings.iter().find(|f| f.level == Level::Error) {
            Some(f) => Err(f.message.clone()),
            None => Ok(()),
        };
    }
    let (name, arg) = match field.split_once('[') {
        Some((n, a)) if a.ends_with(']') => (n, Some(&a[..a.len() - 1])),
        _ => (field, None),
    };
    crate::compile::resolve(catalog, source, name, arg)
        .map(|_| ())
        .map_err(|e| match e {
            crate::compile::FieldError::Unknown => {
                format!("'{field}' is not a supported filter field")
            }
            crate::compile::FieldError::Argument(m) => m,
        })
}

/// Check the block's exceptions; *ctx* gives the source and the lists Falco
/// expands in the text.
pub fn check(exceptions: &[Exception], ctx: &Context) -> Vec<ExceptionFinding> {
    let mut out = Vec::new();
    let source = ctx.source();
    let known_source = Catalog::cached().source(source).is_some();
    let mut seen = std::collections::BTreeSet::new();
    for (index, ex) in exceptions.iter().enumerate() {
        let mut push = |key: &'static str, code: &'static str, level: Level, message: String| {
            out.push(ExceptionFinding {
                index,
                key,
                code,
                level,
                message,
            })
        };
        if !seen.insert(ex.name.clone()) {
            push(
                "name",
                codes::FALCO_EXCEPTION,
                Level::Warning,
                format!(
                    "Multiple definitions of exception '{}' in the same rule",
                    ex.name
                ),
            );
        }
        let Some(fields) = &ex.fields else {
            continue;
        };
        // Validate, as validate_exception_info.
        let comps: Vec<String> = match (fields, &ex.comps) {
            (Strs::Many(fs), None) => vec!["=".to_string(); fs.len()],
            (Strs::Many(fs), Some(Strs::Many(cs))) => {
                if fs.len() != cs.len() {
                    push(
                        "comps",
                        codes::FALCO_EXCEPTION,
                        Level::Error,
                        "Fields and comps lists must have equal length".into(),
                    );
                    continue;
                }
                cs.iter().map(|c| normalize(c)).collect()
            }
            (Strs::Many(_), Some(Strs::One(c))) => {
                // Falco reads a scalar `comps` with list `fields` as one item.
                vec![normalize(c)]
            }
            (Strs::One(_), None) => vec!["in".to_string()],
            (Strs::One(_), Some(Strs::Many(_))) => {
                push(
                    "comps",
                    codes::FALCO_EXCEPTION,
                    Level::Error,
                    "Fields and comps must both be strings".into(),
                );
                continue;
            }
            (Strs::One(_), Some(Strs::One(c))) => vec![normalize(c)],
        };
        let field_list: Vec<&str> = match fields {
            Strs::Many(fs) => fs.iter().map(String::as_str).collect(),
            Strs::One(f) => vec![f.as_str()],
        };
        if let Strs::Many(fs) = fields
            && fs.len() != comps.len()
        {
            push(
                "comps",
                codes::FALCO_EXCEPTION,
                Level::Error,
                "Fields and comps lists must have equal length".into(),
            );
            continue;
        }
        let mut bad = false;
        match fields {
            Strs::Many(_) => {
                for c in &comps {
                    if !is_operator(c) && !is_modifier_op(c) {
                        push(
                            "comps",
                            codes::FALCO_EXCEPTION,
                            Level::Error,
                            format!("'{c}' is not a supported comparison operator"),
                        );
                        bad = true;
                    }
                }
            }
            Strs::One(_) => {
                let c = &comps[0];
                if !matches!(c.as_str(), "in" | "pmatch" | "intersects") && !is_modifier_op(c) {
                    push(
                        "comps",
                        codes::FALCO_EXCEPTION,
                        Level::Error,
                        "When fields is a single value, comps must be one of (in, pmatch, intersects) or a modifier operator (e.g. startswith oneof)".into(),
                    );
                    bad = true;
                }
            }
        }
        if known_source {
            for f in &field_list {
                if let Err(message) = valid_lhs(f, source) {
                    let unknown = message.ends_with("is not a supported filter field");
                    push(
                        "fields",
                        if unknown {
                            codes::FALCO_UNKNOWN_FIELD
                        } else {
                            codes::FALCO_EXCEPTION
                        },
                        Level::Error,
                        message,
                    );
                    bad = true;
                }
            }
        }
        if bad {
            continue;
        }
        // Build the text, as build_rule_exception_infos.
        let icond = match fields {
            Strs::One(field) => {
                let mut items = Vec::new();
                let mut scalar = true;
                for v in &ex.values {
                    match v {
                        Item::Scalar(s) => items.push(quote_item(s)),
                        Item::List(_) => scalar = false,
                    }
                }
                if !scalar {
                    push(
                        "values",
                        codes::FALCO_EXCEPTION,
                        Level::Error,
                        "Expected values array to contain a list of strings".into(),
                    );
                    continue;
                }
                if items.is_empty() {
                    continue;
                }
                format!("({field} {} ({}))", comps[0], items.join(", "))
            }
            Strs::Many(fs) => {
                let mut rows = Vec::new();
                let mut broken = false;
                for row in &ex.values {
                    let Item::List(items) = row else {
                        broken = true;
                        break;
                    };
                    if items.len() != fs.len() {
                        broken = true;
                        break;
                    }
                    let parts: Vec<String> = fs
                        .iter()
                        .zip(&comps)
                        .zip(items)
                        .map(|((f, c), item)| {
                            let value = match item {
                                Item::List(vs) => format!(
                                    "({})",
                                    vs.iter()
                                        .map(|v| match v {
                                            Item::Scalar(s) => quote_item(s),
                                            Item::List(_) => String::new(),
                                        })
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                                Item::Scalar(s) if is_list_op(c) => paren_item(s),
                                Item::Scalar(s) => quote_item(s),
                            };
                            format!(" {f} {c} {value}")
                        })
                        .collect();
                    rows.push(format!("({})", parts.join(" and ")));
                }
                if broken {
                    push(
                        "values",
                        codes::FALCO_EXCEPTION,
                        Level::Error,
                        "Fields and values lists must have equal length".into(),
                    );
                    continue;
                }
                if rows.is_empty() {
                    continue;
                }
                format!("({})", rows.join(" or "))
            }
        };
        // Compile the exception's text as Falco does, inside the rule.
        let expanded = expand_lists(&icond, ctx);
        match parser::parse(&expanded.text) {
            Err(e) => push(
                "values",
                codes::FALCO_EXCEPTION,
                Level::Error,
                format!(
                    "the exception writes `{icond}` into the condition, which does not parse: {} (libsinsp)",
                    e.message
                ),
            ),
            Ok(ast) => {
                if !known_source {
                    continue;
                }
                let mut compiler = Compiler::new(Catalog::cached(), source);
                compiler.condition(&ast);
                for f in compiler.findings {
                    if f.level == Level::Error {
                        push(
                            "values",
                            codes::FALCO_EXCEPTION,
                            Level::Error,
                            format!("{} (in `{icond}`)", f.message),
                        );
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Item {
        Item::Scalar(v.into())
    }

    fn many(v: &[&str]) -> Option<Strs> {
        Some(Strs::Many(v.iter().map(|x| x.to_string()).collect()))
    }

    fn codes_of(ex: Exception) -> Vec<(&'static str, &'static str)> {
        check(&[ex], &Context::default())
            .into_iter()
            .map(|f| (f.key, f.code))
            .collect()
    }

    #[test]
    fn tuple_and_single_forms() {
        let tuple = Exception {
            name: "e".into(),
            fields: many(&["proc.name", "proc.pname"]),
            comps: many(&["=", "in"]),
            values: vec![Item::List(vec![
                s("bash"),
                Item::List(vec![s("sshd"), s("sudo su")]),
            ])],
        };
        assert!(codes_of(tuple).is_empty());
        let single = Exception {
            name: "e".into(),
            fields: Some(Strs::One("proc.name".into())),
            comps: None,
            values: vec![s("bash"), s("sh")],
        };
        assert!(codes_of(single).is_empty());
        let modifier = Exception {
            name: "e".into(),
            fields: Some(Strs::One("fd.name".into())),
            comps: Some(Strs::One("startswith oneof".into())),
            values: vec![s("/etc"), s("/usr")],
        };
        assert!(codes_of(modifier).is_empty());
    }

    #[test]
    fn falco_refusals() {
        let ex = |fields, comps, values| Exception {
            name: "e".into(),
            fields,
            comps,
            values,
        };
        assert_eq!(
            codes_of(ex(many(&["proc.name", "proc.pname"]), many(&["="]), vec![])),
            [("comps", codes::FALCO_EXCEPTION)]
        );
        assert_eq!(
            codes_of(ex(many(&["proc.name"]), many(&["~"]), vec![])),
            [("comps", codes::FALCO_EXCEPTION)]
        );
        assert_eq!(
            codes_of(ex(
                Some(Strs::One("proc.name".into())),
                Some(Strs::One("=".into())),
                vec![s("x")]
            )),
            [("comps", codes::FALCO_EXCEPTION)]
        );
        assert_eq!(
            codes_of(ex(
                many(&["proc.name", "proc.pid"]),
                None,
                vec![Item::List(vec![s("a")])]
            )),
            [("values", codes::FALCO_EXCEPTION)]
        );
        // A value the field's type cannot hold.
        assert_eq!(
            codes_of(ex(
                many(&["proc.pid"]),
                None,
                vec![Item::List(vec![s("abc")])]
            )),
            [("values", codes::FALCO_EXCEPTION)]
        );
        // A field the source does not know: an error, as Falco refuses it.
        assert_eq!(
            codes_of(ex(Some(Strs::One("proc.nmae".into())), None, vec![s("x")])),
            [("fields", codes::FALCO_UNKNOWN_FIELD)]
        );
        // A comma in an unquoted item breaks Falco's text.
        assert_eq!(
            codes_of(ex(
                Some(Strs::One("proc.name".into())),
                None,
                vec![s("a,b(")]
            )),
            [("values", codes::FALCO_EXCEPTION)]
        );
    }
}
