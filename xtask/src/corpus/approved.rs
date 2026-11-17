//! The approved classes of difference between the Rust engine's findings
//! and the oracle's, which `corpus faults --check --engine rust` applies
//! (`super::queries`). Moved here from `xtask validate diff` and `xtask lint
//! diff`, deleted with the golden recordings (#1142).

use opentide_cli::commands::validate::{Args as CliArgs, refuse};
use opentide_cli::mode::Mode;
use opentide_cli::render::report::ReportFormat;
use opentide_cli::tree::RootCommand;
use opentide_workspace::validate::{Check, QueriesMode, Selection};
use std::collections::BTreeMap;

use serde_json::{Value as Json, json};

/// An approved class of difference: where it applies, and why.
pub struct Approved {
    /// The rule's id.
    pub id: &'static str,
    /// Why the Rust result is right.
    pub reason: &'static str,
    /// The bold lead of its CHANGELOG.md entry.
    pub changelog: &'static str,
    /// Whether it explains this finding of the oracle (`None`: none) and
    /// this finding of the Rust run (`None`: none) as one difference; the
    /// last argument is the oracle's whole list (issues or warnings) in the
    /// same case.
    pub applies: fn(oracle: Option<&Json>, rust: Option<&Json>, oracle_list: &[Json]) -> bool,
}

/// The approved differences. A count or verdict that differs (`summary`,
/// `stats.objects_checked`) is approved as derived when every finding that
/// differs in its case is.
pub const APPROVED: &[Approved] = &[
    Approved {
        id: "suggestions",
        reason: "\"did you mean\" is opentide_core::suggest's one rule (the engines', the \
                 configuration's and the vocabularies'), not difflib's ratio: `Host::Gizmo` \
                 and `Big incident` suggest nothing, where the oracle offered unrelated words \
                 that share letters (`Host::File`, `Substantial incident`); the finding, its \
                 code and place are the same, with no suggestion, help or fix",
        changelog: "**\"Did you mean\" suggests what a typo meant, not a word that shares letters**",
        applies: suggestions,
    },
    Approved {
        id: "yaml-error-text",
        reason: "a file that is not YAML is reported in the words of the YAML 1.2 parser \
                 (saphyr), at the line and column the oracle names (one column later where \
                 saphyr names the tab it refuses, or at the plain scalar a tab interrupts, \
                 where the oracle named the tab's line); the code, the file and the help are \
                 the same (as in `cargo xtask registry diff`)",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_error_text,
    },
    Approved {
        id: "yaml-1-2-dates",
        reason: "an unquoted impossible date (`reviewed: 2026-02-30`) no longer stops the file \
                 from loading: the object is indexed and checked, and the field's own \
                 `schema_validation` reports the date, where the oracle refused the whole file \
                 as `yaml_parse` (UC-1.3, `yaml-1-2-dates`)",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_1_2_dates,
    },
    Approved {
        id: "invalid-uuid-every-file",
        reason: "KG-04: every file that writes an invalid UUID gets its `invalid_uuid`, also a \
                 file whose object a later file with the same UUID displaced from the index; \
                 the oracle reported it once per value, on another file, in the same words",
        changelog: "**Every file with an invalid UUID is reported**",
        applies: invalid_uuid_every_file,
    },
    Approved {
        id: "engine-suggestions",
        reason: "the query engines suggest by opentide_core::suggest's one rule (#812): a name \
                 far from every choice (ES|QL `::foo`) suggests nothing, where the oracle's \
                 engine offered an unrelated one (`bool`); the finding, its code and place are \
                 the same, and its help is the language reference",
        changelog: "**The query engines suggest by the same rule**",
        applies: engine_suggestions,
    },
    Approved {
        id: "crowdstrike-cql",
        reason: "CrowdStrike queries are checked as CQL (language-server 0.12.0): each one \
                 counts in `queries_checked`, and a query Next-Gen SIEM would refuse is a \
                 `cql_*` error the oracle, which never checked them, does not report; the \
                 count also holds the queries of a file the oracle could not read and the \
                 Rust run reads (`yaml-1-2-dates`), never otherwise",
        changelog: "**`opentide validate` checks CrowdStrike queries, and fails a rule whose \
                    query Next-Gen SIEM would refuse**",
        applies: crowdstrike_cql,
    },
    Approved {
        id: "messages-quote-values",
        reason: "a message and its help quote a value in double quotes with Rust's escapes, \
                 where the oracle used Python's repr ('x', None, True): the finding is the \
                 same but for the quote characters around its values",
        changelog: "**Messages quote values the same way everywhere**",
        applies: quoting_only,
    },
    Approved {
        id: "sentinel-durations",
        reason: "KG-01 (#810): a Sentinel duration deploy cannot read (`frequency: hourly`) is \
                 the model's `schema_validation` on the field, from every run, where the oracle \
                 reported it only from the compile check, as `compile_invalid_rule` on the \
                 platform's block, in the same words",
        changelog: "**Sentinel durations are checked when the rule is validated**",
        applies: sentinel_durations,
    },
    Approved {
        id: "elastic-severity-mapping",
        reason: "KG-09 (#817): the Elastic compiler reads a `severity` block without `mapping` \
                 as no mapping, as the documented shape allows, so the compile check passes the \
                 rule, where the oracle's compiler failed on the missing key (`compile_failed`, \
                 `'mapping'`)",
        changelog: "**An Elastic rule whose `severity` has no `mapping` validates and deploys**",
        applies: elastic_severity_mapping,
    },
    Approved {
        id: "compile-empty-key-frame",
        reason: "a compile finding on a key left empty (`response:`) is framed at that key, \
                 where the oracle's ruamel placed the empty value on the next key's line; the \
                 finding, its `field_path` and its `yaml_line` (the key's line) are the same \
                 (#817)",
        changelog: "**`opentide validate` fails a rule a deploy cannot compile, as 0.23.0 did**",
        applies: compile_empty_key_frame,
    },
];

/// The difference in `stats.queries_checked`, as a rule reads it: the
/// oracle's count, and the Rust run's with how many of its queries were
/// CrowdStrike's, how many HarfangLab YARA rules, and how many were in files
/// the oracle could not read (`yaml-1-2-dates`).
#[cfg(test)]
fn queries_checked(
    oracle: &Json,
    rust: &Json,
    crowdstrike: usize,
    yara: usize,
    yaml_1_2: usize,
) -> (Json, Json) {
    (
        json!({"queries_checked": oracle}),
        json!({
            "queries_checked": rust,
            "crowdstrike": crowdstrike,
            "yara": yara,
            "yaml_1_2": yaml_1_2,
        }),
    )
}

fn engine_suggestions(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    let reference = opentide_cli::queries::engine_help(
        code(rust),
        rust["message"].as_str().unwrap_or(""),
        None,
    );
    oracle.pointer("/context/source") == Some(&json!("engine"))
        && !oracle["suggestion"].is_null()
        && rust["suggestion"].is_null()
        && rust["help"] == json!(reference)
        && without(oracle, &["suggestion", "help"]) == without(rust, &["suggestion", "help"])
}

pub(crate) fn crowdstrike_cql(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    match (oracle, rust) {
        // A CrowdStrike query's finding, which the oracle did not check.
        (None, Some(rust)) => {
            code(rust).starts_with("cql_")
                && rust.pointer("/context/source") == Some(&json!("engine"))
                && rust.pointer("/context/platform") == Some(&json!("crowdstrike"))
        }
        // The count: the oracle's, and the CrowdStrike queries (0.28.1
        // checks HarfangLab's YARA as Rust does, so YARA rules are on both
        // sides).
        (Some(oracle), Some(rust)) => {
            let (Some(before), Some(after), Some(added), Some(read)) = (
                oracle["queries_checked"].as_u64(),
                rust["queries_checked"].as_u64(),
                rust["crowdstrike"].as_u64(),
                rust["yaml_1_2"].as_u64(),
            ) else {
                return false;
            };
            added > 0 && before + added + read == after
        }
        _ => false,
    }
}

/// `finding` without the keys `drop` names.
fn without(finding: &Json, drop: &[&str]) -> Json {
    let mut copy = finding.clone();
    if let Some(map) = copy.as_object_mut() {
        for key in drop {
            map.remove(*key);
        }
    }
    copy
}

fn code(finding: &Json) -> &str {
    finding["code"].as_str().unwrap_or("")
}

fn suggestions(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    const VALUE_CODES: [&str; 4] = [
        "vocab_unknown",
        "invalid_ref",
        "chaining_relation_unknown",
        "config_enum_unknown",
    ];
    VALUE_CODES.contains(&code(oracle))
        && !oracle["suggestion"].is_null()
        // Rust suggests nothing: a different suggestion is not this rule's.
        && rust["suggestion"].is_null()
        && rust["help"].is_null()
        && rust["fix"].is_null()
        // The message's quotes are `messages-quote-values`' business.
        && unquoted_json(&without(oracle, &["suggestion", "help", "fix"]))
            == unquoted_json(&without(rust, &["suggestion", "help", "fix"]))
}

fn yaml_error_text(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    let message = rust["message"].as_str().unwrap_or("");
    // The same column, or one later where saphyr names the tab it refuses
    // (the oracle placed the error at the tab's line start).
    let shift = |key: &str| {
        let (Some(o), Some(r)) = (oracle[key].as_u64(), rust[key].as_u64()) else {
            return None;
        };
        r.checked_sub(o)
    };
    let columns = match (shift("column"), shift("end_column")) {
        (Some(0), Some(0)) => true,
        (Some(1), Some(1)) => message.contains("tab"),
        _ => false,
    };
    let place = ["message", "column", "end_column"];
    // A tab inside a multi-line plain scalar: the oracle places the error at
    // the tab, saphyr at the scalar it interrupts ([`tab_in_scalar`]).
    let scalar = ["message", "line", "column", "end_line", "end_column"];
    code(oracle) == "yaml_parse"
        && code(rust) == "yaml_parse"
        && message.starts_with("Could not parse object YAML: ")
        && ((columns && without(oracle, &place) == without(rust, &place))
            || (tab_in_scalar(oracle, rust) && without(oracle, &scalar) == without(rust, &scalar)))
}

fn yaml_1_2_dates(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    match (oracle, rust) {
        (Some(oracle), None) => {
            code(oracle) == "yaml_parse"
                && oracle["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("is not a valid date"))
        }
        (None, Some(rust)) => {
            code(rust) == "schema_validation"
                && rust["field_path"] == json!(["metadata", "reviewed"])
                && rust["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("is not a valid date or time"))
        }
        _ => false,
    }
}

/// A Rust-only `invalid_uuid` whose value the oracle itself reported as
/// invalid, in the same words, on another file: the UUID is invalid and
/// shared, and only the file the index kept was reported.
fn invalid_uuid_every_file(
    oracle: Option<&Json>,
    rust: Option<&Json>,
    oracle_list: &[Json],
) -> bool {
    let (None, Some(rust)) = (oracle, rust) else {
        return false;
    };
    code(rust) == "invalid_uuid"
        && rust["object_uuid"].is_string()
        && oracle_list.iter().any(|reported| {
            code(reported) == "invalid_uuid"
                && reported["object_uuid"] == rust["object_uuid"]
                // In the same words but for the quotes (`messages-quote-values`).
                && unquoted_json(&reported["message"]) == unquoted_json(&rust["message"])
                && reported["field_path"] == rust["field_path"]
                && reported["file_path"] != rust["file_path"]
        })
}

/// KG-01: the oracle's `compile_invalid_rule` on a Sentinel block for a
/// duration it cannot read, and the Rust model's `schema_validation` on the
/// duration's own field, in the same words.
fn sentinel_durations(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    const DURATION: &str = "is not an ISO 8601 duration";
    match (oracle, rust) {
        (Some(oracle), None) => {
            code(oracle) == "compile_invalid_rule"
                && oracle["field_path"] == json!(["configurations", "sentinel"])
                && oracle["message"]
                    .as_str()
                    .is_some_and(|m| m.starts_with("Duration ") && m.contains(DURATION))
        }
        (None, Some(rust)) => {
            code(rust) == "schema_validation"
                && rust["field_path"].as_array().is_some_and(|path| {
                    path.len() > 2 && path[..2] == [json!("configurations"), json!("sentinel")]
                })
                && rust["message"]
                    .as_str()
                    .is_some_and(|m| m.contains(DURATION))
        }
        _ => false,
    }
}

/// KG-09: the oracle's `compile_failed` on an Elastic block whose `severity`
/// has no `mapping`, which the Rust compiler compiles.
fn elastic_severity_mapping(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), None) = (oracle, rust) else {
        return false;
    };
    code(oracle) == "compile_failed"
        && oracle["context"]["platform"] == "elastic"
        && oracle["message"] == "Elastic cannot compile this rule: 'mapping'"
}

/// The same compile finding, framed at the empty key the oracle framed on
/// the next key's line: everything but the frame is the oracle's.
fn compile_empty_key_frame(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    let frame = ["line", "column", "end_line", "end_column"];
    let unframed = |finding: &Json| {
        finding.as_object().map(|object| {
            object
                .iter()
                .filter(|(key, _)| !frame.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
        })
    };
    code(oracle).starts_with("compile_")
        && unframed(oracle) == unframed(rust)
        && rust["line"].as_u64().is_some_and(|line| {
            rust["yaml_line"].as_u64() == Some(line - 1)
                && oracle["line"].as_u64().is_some_and(|theirs| theirs > line)
        })
}

/// The arguments of a recorded case, as `validate` options.
#[derive(Debug, Default)]
pub(crate) struct Args {
    pub(crate) check: Option<Check>,
    pub(crate) selection: Selection,
    pub(crate) strict: bool,
    pub(crate) queries: QueriesMode,
    /// `--fix`: `Some(dry_run)`.
    pub(crate) fix: Option<bool>,
}

/// `argv`'s `validate` options, as the product reads them; `None` when it
/// holds another (`--format`, `--output`, `--watch`, a global flag, ...), the
/// command line's usage errors (UC-3.5: `--dry-run` without `--fix`, another
/// `--type` spelling, `--queries` with another `--check`: the product's
/// `refuse`) or no `validate`.
pub(crate) fn parse_args(argv: &[String]) -> Option<Args> {
    let Some(RootCommand::Validate(parsed)) = crate::recorded::command(argv, "validate") else {
        return None;
    };
    let flags = CliArgs::from(&parsed);
    let replayed = parsed.command.is_none()
        && !flags.watch
        && flags.format == ReportFormat::Text
        && flags.output.is_none()
        && refuse(&flags, Mode::Json).is_none();
    replayed.then(|| Args {
        check: flags.check,
        selection: flags.selection,
        strict: flags.strict,
        queries: flags.queries.unwrap_or_default(),
        fix: flags.fix.then_some(flags.dry_run),
    })
}

/// `text` without quote characters and backslashes.
fn unquoted(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect()
}

/// A JSON value with every string [`unquoted`].
pub(crate) fn unquoted_json(value: &Json) -> Json {
    match value {
        Json::String(text) => Json::String(unquoted(text)),
        Json::Array(items) => Json::Array(items.iter().map(unquoted_json).collect()),
        Json::Object(map) => Json::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), unquoted_json(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `messages-quote-values`: the two findings differ only in the quote
/// characters of their strings.
pub fn quoting_only(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    oracle != rust && unquoted_json(oracle) == unquoted_json(rust)
}

/// A tab inside a multi-line plain scalar: the oracle places the error at
/// the tab and names the scalar it interrupts (`while scanning a plain
/// scalar that starts at line L, column C`); saphyr places it at that
/// scalar, L:C, one column wide.
pub(crate) fn tab_in_scalar(oracle: &Json, rust: &Json) -> bool {
    let words = oracle["message"].as_str().unwrap_or("");
    let Some(start) = words
        .split("while scanning a plain scalar that starts at line ")
        .nth(1)
    else {
        return false;
    };
    let mut numbers = start
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(str::parse::<u64>);
    let (Some(Ok(line)), Some(Ok(column))) = (numbers.next(), numbers.next()) else {
        return false;
    };
    rust["message"]
        .as_str()
        .is_some_and(|m| m.contains("found a tab"))
        && words.contains("found a tab character")
        && rust["line"].as_u64() == Some(line)
        && rust["end_line"].as_u64() == Some(line)
        && rust["column"].as_u64() == Some(column)
        && rust["end_column"].as_u64() == Some(column + 1)
}

#[cfg(test)]
mod tests {

    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        ["opentide", "--json", "validate"]
            .iter()
            .chain(args)
            .map(|s| (*s).to_owned())
            .collect()
    }

    #[test]
    fn only_checking_cases_are_run() {
        let args = parse_args(&argv(&["--check", "schema", "--uuid", "u", "--strict"])).unwrap();
        assert_eq!(args.check, Some(Check::Schema));
        assert_eq!(args.selection.uuids, vec!["u".to_owned()]);
        assert!(args.strict);
        assert_eq!(parse_args(&argv(&["--fix"])).unwrap().fix, Some(false));
        assert_eq!(
            parse_args(&argv(&["--fix", "--dry-run"])).unwrap().fix,
            Some(true)
        );
        assert!(parse_args(&argv(&["--dry-run"])).is_none());
        assert!(parse_args(&argv(&["--format", "sarif"])).is_none());
        assert!(parse_args(&argv(&["--check", "nope"])).is_none());
        // The usage errors the product reports are not cases to replay.
        assert!(parse_args(&argv(&["--type", "RULE"])).is_none());
        assert!(parse_args(&argv(&["--check", "schema", "--queries", "warn"])).is_none());
        assert!(parse_args(&argv(&["--watch"])).is_none());
        assert!(parse_args(&argv(&["--output", "r.sarif"])).is_none());
        assert!(parse_args(&argv(&["--verbose"])).is_none());
        assert!(parse_args(&argv(&["query"])).is_none());
        assert_eq!(
            parse_args(&argv(&["--type", "rule", "--queries", "off"]))
                .unwrap()
                .queries,
            QueriesMode::Off
        );
    }

    /// A count the CrowdStrike queries (and the files the oracle could not
    /// read) explain is `crowdstrike-cql`'s, YARA rules or not (0.28.1 counts
    /// them too); a count they do not add up to is no one's.
    #[test]
    fn the_query_count_is_explained_by_the_crowdstrike_queries() {
        let (oracle, with_yara) = queries_checked(&json!(1531), &json!(1610), 75, 69, 4);
        assert!(crowdstrike_cql(Some(&oracle), Some(&with_yara), &[]));
        let (oracle, crowdstrike) = queries_checked(&json!(1531), &json!(1610), 75, 0, 4);
        assert!(crowdstrike_cql(Some(&oracle), Some(&crowdstrike), &[]));
        // YARA rules no longer explain a count: the oracle checks them too.
        let (oracle, yara) = queries_checked(&json!(1531), &json!(1679), 75, 69, 4);
        assert!(!crowdstrike_cql(Some(&oracle), Some(&yara), &[]));
        let (oracle, none) = queries_checked(&json!(1531), &json!(1535), 0, 0, 4);
        assert!(!crowdstrike_cql(Some(&oracle), Some(&none), &[]));
    }

    fn uuid_finding(file: &str, value: &str) -> Json {
        json!({
            "code": "invalid_uuid",
            "file_path": file,
            "field_path": ["metadata", "uuid"],
            "object_uuid": value,
            "message": format!("UUID '{value}' is not a valid UUIDv4"),
        })
    }

    #[test]
    fn only_a_shared_invalid_uuid_the_oracle_reported_elsewhere_is_approved() {
        let kept = uuid_finding("a.yaml", "not-a-uuid");
        let displaced = uuid_finding("b.yaml", "not-a-uuid");
        let oracle = [kept.clone()];
        assert!(invalid_uuid_every_file(None, Some(&displaced), &oracle));
        // A spurious invalid_uuid: no file's value is reported by the oracle.
        let spurious = uuid_finding("c.yaml", "7b8864a9-890e-4e58-8a56-ae78cd82796b");
        assert!(!invalid_uuid_every_file(None, Some(&spurious), &oracle));
        assert!(!invalid_uuid_every_file(None, Some(&spurious), &[]));
        // The oracle's finding on the same file is not another file's.
        assert!(!invalid_uuid_every_file(None, Some(&kept), &oracle));
        // The same words in Rust's quotes are the oracle's.
        let mut requoted = displaced.clone();
        requoted["message"] = json!("UUID \"not-a-uuid\" is not a valid UUIDv4");
        assert!(invalid_uuid_every_file(None, Some(&requoted), &oracle));
        // Other words for the same value are not the oracle's.
        let mut reworded = displaced.clone();
        reworded["message"] = json!("UUID 'not-a-uuid' is bad");
        assert!(!invalid_uuid_every_file(None, Some(&reworded), &oracle));
        // A finding the oracle has too is a different rule's business.
        assert!(!invalid_uuid_every_file(
            Some(&kept),
            Some(&displaced),
            &oracle
        ));
        assert!(
            APPROVED
                .iter()
                .all(|rule| !(rule.applies)(None, Some(&spurious), &oracle,))
        );
    }

    fn vocab_finding(suggestion: Option<&str>) -> Json {
        json!({
            "code": "invalid_ref",
            "file_path": "a.yaml",
            "field_path": ["threat", "actors"],
            "message": "unknown",
            "suggestion": suggestion,
            "help": suggestion.map(|s| format!("did you mean '{s}'?")),
            "fix": suggestion.map(|s| json!({"edits": [{"replacement": s}], "safe": false})),
        })
    }

    #[test]
    fn only_a_lost_suggestion_is_approved() {
        let oracle = vocab_finding(Some("Host::File"));
        assert!(suggestions(Some(&oracle), Some(&vocab_finding(None)), &[]));
        // Lost along with the oracle's quotes in the message.
        let mut quoted = (vocab_finding(Some("Host::File")), vocab_finding(None));
        quoted.0["message"] = json!("Value 'Host::Gizmo' is unknown");
        quoted.1["message"] = json!("Value \"Host::Gizmo\" is unknown");
        assert!(suggestions(Some(&quoted.0), Some(&quoted.1), &[]));
        quoted.1["message"] = json!("Value \"Host::Other\" is unknown");
        assert!(!suggestions(Some(&quoted.0), Some(&quoted.1), &[]));
        // A different suggestion (another object's UUID) needs review.
        let other = vocab_finding(Some("e305cca1-c265-4ae9-a34e-2ffaee82a359"));
        assert!(!suggestions(Some(&oracle), Some(&other), &[]));
        // A help or fix left without a suggestion is not a lost suggestion.
        let mut stray = vocab_finding(None);
        stray["help"] = json!("did you mean 'Host::Gizmo'?");
        assert!(!suggestions(Some(&oracle), Some(&stray), &[]));
        let mut stray = vocab_finding(None);
        stray["fix"] = json!({"edits": [], "safe": false});
        assert!(!suggestions(Some(&oracle), Some(&stray), &[]));
    }

    fn yaml_finding(column: u64, message: &str) -> Json {
        json!({
            "code": "yaml_parse",
            "file_path": "a.yaml",
            "line": 68,
            "column": column,
            "end_column": column + 1,
            "message": format!("Could not parse object YAML: {message}"),
        })
    }

    #[test]
    fn a_yaml_error_keeps_its_column_but_for_a_tab() {
        let oracle = yaml_finding(1, "found character that cannot start any token");
        let same = yaml_finding(1, "while parsing a flow sequence, expected ',' or ']'");
        assert!(yaml_error_text(Some(&oracle), Some(&same), &[]));
        let tab = yaml_finding(2, "tabs disallowed within this context (block indentation)");
        assert!(yaml_error_text(Some(&oracle), Some(&tab), &[]));
        // One column later without a tab, or anywhere else on the line: no.
        let later = yaml_finding(2, "while parsing a flow sequence, expected ',' or ']'");
        assert!(!yaml_error_text(Some(&oracle), Some(&later), &[]));
        let far = yaml_finding(9, "tabs disallowed within this context (block indentation)");
        assert!(!yaml_error_text(Some(&oracle), Some(&far), &[]));
        let earlier = yaml_finding(1, "tab");
        assert!(!yaml_error_text(
            Some(&yaml_finding(2, "x")),
            Some(&earlier),
            &[]
        ));
    }

    /// A tab inside a multi-line plain scalar: the oracle names the tab's
    /// line, saphyr the scalar it interrupts (0.28.1's fault workspace).
    #[test]
    fn a_tab_in_a_plain_scalar_is_placed_at_the_scalar() {
        let oracle = json!({
            "code": "yaml_parse",
            "file_path": "a.yaml",
            "line": 45,
            "end_line": 45,
            "column": 1,
            "end_column": 2,
            "message": "Could not parse object YAML: found a tab character that violates \
                        indentation at line 45, column 1 (while scanning a plain scalar that \
                        starts at line 44, column 18)",
        });
        let mut rust = oracle.clone();
        rust["line"] = json!(44);
        rust["end_line"] = json!(44);
        rust["column"] = json!(18);
        rust["end_column"] = json!(19);
        rust["message"] = json!(
            "Could not parse object YAML: while scanning a plain scalar, found a tab at line 44, column 18"
        );
        assert!(yaml_error_text(Some(&oracle), Some(&rust), &[]));
        // Anywhere but the scalar the oracle names: no.
        let mut elsewhere = rust.clone();
        elsewhere["column"] = json!(17);
        assert!(!yaml_error_text(Some(&oracle), Some(&elsewhere), &[]));
        let mut other_file = rust;
        other_file["file_path"] = json!("b.yaml");
        assert!(!yaml_error_text(Some(&oracle), Some(&other_file), &[]));
    }
}
