//! `validate` over a workspace in memory: each check's findings, their
//! places and steps, the scope options, the verdict and the counts. The
//! oracle comparison is `cargo xtask validate diff` (every recorded
//! `validate --json` case); `diagnostic_json` holds the finding shape to the
//! recordings byte for byte.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace they open resolves"
)]

mod validate {
    use std::path::PathBuf;
    use std::sync::Arc;

    use opentide_workspace::validate::{Check, Options, Selection, Validation};
    use opentide_workspace::{Diagnostic, FileSystem, MemoryFs, RootOptions, Severity, Workspace};

    const ROOT: &str = "/ws";
    const U1: &str = "11111111-1111-4111-8111-111111111111";
    const U2: &str = "22222222-2222-4222-8222-222222222222";

    fn open(fs: &Arc<MemoryFs>) -> Workspace {
        Workspace::open(
            Arc::clone(fs) as Arc<dyn FileSystem>,
            opentide_workspace::Options {
                roots: RootOptions {
                    repo: Some(PathBuf::from(ROOT)),
                    cwd: PathBuf::from(ROOT),
                    ..RootOptions::default()
                },
            },
        )
        .unwrap()
    }

    fn workspace() -> Arc<MemoryFs> {
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/ws/.opentide/configurations");
        fs.create_dir("/ws/objects/rules");
        fs.create_dir("/ws/objects/threats");
        fs.create_dir("/ws/objects/objectives");
        fs
    }

    fn rule(uuid: &str, name: &str) -> String {
        format!("name: {name}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.1\n")
    }

    fn run(fs: &Arc<MemoryFs>, options: &Options<'_>) -> Validation {
        open(fs).validate(options)
    }

    fn all(validation: &Validation) -> Vec<&Diagnostic> {
        validation
            .report
            .issues
            .iter()
            .chain(&validation.report.warnings)
            .collect()
    }

    fn with_code<'v>(validation: &'v Validation, code: &str) -> Vec<&'v Diagnostic> {
        all(validation)
            .into_iter()
            .filter(|d| d.code == code)
            .collect()
    }

    fn status(validation: &Validation, check: Check) -> &'static str {
        validation
            .checks
            .iter()
            .find(|(c, _)| *c == check)
            .map(|(_, s)| *s)
            .unwrap()
    }

    #[test]
    fn a_uuid_written_twice_is_one_duplicate_on_the_later_file_naming_the_first() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        fs.write("/ws/objects/rules/b.yaml", rule(U1, "B"));
        fs.write("/ws/objects/rules/c.yaml", rule(U2, "C"));
        let validation = run(&fs, &Options::default());
        let duplicates = with_code(&validation, "duplicate_id");
        assert_eq!(duplicates.len(), 1);
        let duplicate = duplicates[0];
        assert_eq!(
            duplicate.message,
            format!("Duplicated ID {U1} on 'B' @ b.yaml; already used by 'A' @ a.yaml")
        );
        assert_eq!(
            duplicate.file_path.as_deref(),
            Some(PathBuf::from("/ws/objects/rules/b.yaml").as_path())
        );
        assert_eq!(duplicate.path.as_deref(), Some("objects/rules/b.yaml"));
        assert_eq!((duplicate.line, duplicate.column), (Some(3), Some(9)));
        assert_eq!(duplicate.end_column, Some(9 + U1.len()));
        assert_eq!(
            duplicate.notes,
            [("also".to_owned(), "objects/rules/a.yaml:3:9".to_owned())]
        );
        let context = serde_json::to_string(&duplicate.context).unwrap();
        assert_eq!(
            context,
            format!(
                r#"{{"value":"{U1}","original":{{"name":"A","file_name":"a.yaml","file_path":"/ws/objects/rules/a.yaml","field_path":["metadata","uuid"]}}}}"#
            )
        );
        assert_eq!(status(&validation, Check::IdUniqueness), "failed");
        assert_eq!(status(&validation, Check::UuidFormat), "passed");
        assert!(validation.failed);
    }

    #[test]
    fn signals_share_the_uuid_space_of_objects() {
        let fs = workspace();
        let objective = |uuid: &str| {
            format!(
                "name: O\nmetadata:\n  uuid: {uuid}\n  schema: objective::1.0\nobjective:\n  signals:\n    - uuid: {U2}\n      name: S\n"
            )
        };
        fs.write("/ws/objects/objectives/a.yaml", objective(U1));
        fs.write(
            "/ws/objects/objectives/b.yaml",
            objective("33333333-3333-4333-8333-333333333333"),
        );
        let validation = run(&fs, &Options::default());
        let duplicates = with_code(&validation, "duplicate_id");
        assert_eq!(duplicates.len(), 1);
        assert_eq!(duplicates[0].object_type, "signal");
        assert_eq!(
            duplicates[0].field_path,
            ["objective", "signals", "0", "uuid"]
        );
    }

    #[test]
    fn every_file_with_an_invalid_uuid_is_reported_kg_04() {
        let fs = workspace();
        for (file, name) in [("a", "A"), ("b", "B"), ("c", "C")] {
            fs.write(
                format!("/ws/objects/rules/{file}.yaml"),
                rule("bad-1", name),
            );
        }
        let validation = run(&fs, &Options::default());
        let invalid = with_code(&validation, "invalid_uuid");
        let mut files: Vec<&str> = invalid.iter().filter_map(|d| d.path.as_deref()).collect();
        files.sort_unstable();
        assert_eq!(
            files,
            [
                "objects/rules/a.yaml",
                "objects/rules/b.yaml",
                "objects/rules/c.yaml"
            ]
        );
        assert!(
            invalid
                .iter()
                .all(|d| d.message == "UUID 'bad-1' is not a valid UUIDv4")
        );
        assert!(invalid.iter().all(|d| {
            d.help
                .as_deref()
                .is_some_and(|h| h.starts_with("replace it with a UUID v4"))
        }));
        assert_eq!(with_code(&validation, "duplicate_id").len(), 2);
    }

    #[test]
    fn uuid_format_takes_only_canonical_version_4() {
        let fs = workspace();
        let cases = [
            ("a", "11111111-1111-1111-8111-111111111111", true),
            ("b", "'{11111111-1111-4111-8111-111111111112}'", true),
            ("c", "'11111111111141118111111111111113'", true),
            ("d", "AAAAAAAA-1111-4111-8111-111111111114", false),
        ];
        for (file, uuid, _) in cases {
            fs.write(format!("/ws/objects/rules/{file}.yaml"), rule(uuid, file));
        }
        let validation = run(&fs, &Options::default());
        let mut flagged: Vec<String> = with_code(&validation, "invalid_uuid")
            .iter()
            .map(|d| d.object_uuid.clone())
            .collect();
        flagged.sort();
        let mut expected: Vec<String> = cases
            .iter()
            .filter(|(_, _, invalid)| *invalid)
            .map(|(_, uuid, _)| uuid.trim_matches('\'').to_owned())
            .collect();
        expected.sort();
        assert_eq!(flagged, expected);
    }

    #[test]
    fn a_scope_that_selects_nothing_says_so() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        let selection = Selection {
            uuids: vec![U2.to_owned()],
            ..Selection::default()
        };
        let validation = run(
            &fs,
            &Options {
                selection: Some(&selection),
                ..Options::default()
            },
        );
        let found = with_code(&validation, "scope_no_match");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "No objects matched the validation scope (check --file, --uuid, --type)"
        );
        assert_eq!(validation.report.stats.objects_checked, 0);

        let selection = Selection {
            files: vec!["objects/rules/a.yaml".to_owned(), "nope.yaml".to_owned()],
            ..Selection::default()
        };
        let validation = run(
            &fs,
            &Options {
                selection: Some(&selection),
                ..Options::default()
            },
        );
        let found = with_code(&validation, "scope_no_match");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "--file 'nope.yaml' matched no object, so it was not validated"
        );
        assert_eq!(validation.report.stats.objects_checked, 1);
        assert_eq!(status(&validation, Check::Schema), "failed");
    }

    #[test]
    fn nested_files_are_warnings_that_strict_counts() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        fs.write("/ws/objects/rules/team/b.yaml", rule(U2, "B"));
        let validation = run(
            &fs,
            &Options {
                check: Some(Check::IdUniqueness),
                ..Options::default()
            },
        );
        let nested = with_code(&validation, "nested_object_file");
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].severity, Severity::Warning);
        assert!(nested[0].message.starts_with(
            "objects/rules/team/b.yaml is in a subfolder of objects/rules and is not an object instance"
        ));
        assert!(!validation.failed);
        assert!(validation.warned);
        let strict = run(
            &fs,
            &Options {
                check: Some(Check::IdUniqueness),
                strict: true,
                ..Options::default()
            },
        );
        assert!(strict.failed);
        assert_eq!(strict.exit_code(), 1);
        // A run narrowed by --uuid alone does not warn about other files.
        let selection = Selection {
            uuids: vec![U1.to_owned()],
            ..Selection::default()
        };
        let narrow = run(
            &fs,
            &Options {
                selection: Some(&selection),
                ..Options::default()
            },
        );
        assert!(with_code(&narrow, "nested_object_file").is_empty());
    }

    #[test]
    fn a_disabled_platforms_block_warns_without_failing_strict() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!(
                "{}configurations:\n  splunk:\n    status: X\n",
                rule(U1, "A")
            ),
        );
        let validation = run(
            &fs,
            &Options {
                strict: true,
                ..Options::default()
            },
        );
        let warnings = with_code(&validation, "platform_not_enabled");
        assert_eq!(warnings.len(), 1);
        let warning = warnings[0];
        assert_eq!(warning.field_path, ["configurations", "splunk"]);
        assert_eq!(
            warning.help.as_deref(),
            Some("enable splunk with 'opentide setup platforms --splunk'")
        );
        assert_eq!(
            (warning.line, warning.column, warning.end_column),
            (Some(6), Some(3), Some(9))
        );
        assert_eq!(warning.yaml_line, Some(6));
        assert!(
            !validation.warned,
            "platform_not_enabled is exempt from --strict"
        );
    }

    #[test]
    fn a_misspelled_enabled_key_is_named() {
        let fs = workspace();
        fs.write(
            "/ws/.opentide/configurations/platforms/splunk.toml",
            "[platform]\nenabeld = true\n",
        );
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!(
                "{}configurations:\n  splunk:\n    status: X\n",
                rule(U1, "A")
            ),
        );
        let validation = run(&fs, &Options::default());
        let warning = with_code(&validation, "platform_not_enabled")[0].clone();
        assert_eq!(
            warning.message,
            "this block will not deploy: .opentide/configurations/platforms/splunk.toml sets \
             'enabeld' in [platform], not 'enabled', so splunk is disabled; rename the key to \
             'enabled'"
        );
        assert_eq!(warning.help.as_deref(), Some("rename the key to 'enabled'"));
    }

    #[test]
    fn vendor_ids_on_a_rule_and_broken_shards_are_errors() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!(
                "{}configurations:\n  sentinel_one:\n    rule_id: 12\n",
                rule(U1, "A")
            ),
        );
        fs.write(
            format!("/ws/.opentide/states/deployment/{U2}.json"),
            "{\"schema\": \"deployment.state::1.0\"}",
        );
        let validation = run(&fs, &Options::default());
        let external = with_code(&validation, "external_id_in_rule");
        assert_eq!(external.len(), 1);
        assert_eq!(
            external[0].field_path,
            ["configurations", "sentinel_one", "rule_id"]
        );
        assert!(
            external[0]
                .help
                .as_deref()
                .is_some_and(|h| h.starts_with("Run 'opentide deploy migrate-state'"))
        );
        // The legacy key is not also a schema error.
        assert!(
            with_code(&validation, "schema_validation").iter().all(|d| d
                .field_path
                .last()
                .map(String::as_str)
                != Some("rule_id"))
        );
        let shards = with_code(&validation, "deployment_state_shape");
        assert_eq!(shards.len(), 1);
        assert_eq!(
            shards[0].path.as_deref(),
            Some(format!(".opentide/states/deployment/{U2}.json").as_str())
        );
        assert!(shards[0].message.ends_with("has no string object_uuid"));
    }

    #[test]
    fn configuration_findings_belong_to_the_configuration_check() {
        let fs = workspace();
        fs.write(
            "/ws/.opentide/configurations/deployment.toml",
            "colour = 1\n",
        );
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        let validation = run(
            &fs,
            &Options {
                check: Some(Check::Configuration),
                ..Options::default()
            },
        );
        let unknown = with_code(&validation, "unknown_key");
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].object_type, "configuration");
        assert_eq!(unknown[0].message, "deployment.toml.colour: unknown key");
        assert_eq!(validation.checks, [(Check::Configuration, "failed")]);
        assert_eq!(
            validation.summary.files, 0,
            "a configuration finding has no path"
        );
    }

    #[test]
    fn sharing_toml_is_checked_only_when_asked() {
        let fs = workspace();
        fs.write("/ws/.opentide/configurations/sharing.toml", "[[misp]\n");
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        let asked = run(
            &fs,
            &Options {
                check: Some(Check::SharingConfig),
                ..Options::default()
            },
        );
        let parse = with_code(&asked, "config_parse");
        assert_eq!(parse.len(), 1, "{:?}", asked.report);
        assert!(
            parse[0]
                .message
                .starts_with("Could not read sharing.toml: ")
        );
        assert_eq!(parse[0].object_type, "");
        assert_eq!(asked.checks, [(Check::SharingConfig, "failed")]);
        let default = run(&fs, &Options::default());
        assert!(with_code(&default, "config_parse").is_empty());
    }

    #[test]
    fn an_unknown_reference_names_the_listing_and_a_dangling_detection_model_too() {
        let fs = workspace();
        fs.write(
            "/ws/objects/objectives/o.yaml",
            format!("name: O\nmetadata:\n  uuid: {U1}\n  schema: objective::1.0\nobjective:\n  threats:\n    - {U2}\n"),
        );
        let validation = run(&fs, &Options::default());
        let refs = with_code(&validation, "invalid_ref");
        assert_eq!(refs.len(), 1, "{refs:?}");
        assert_eq!(refs[0].message, format!("Unknown threat reference '{U2}'"));
        assert_eq!(
            refs[0].help.as_deref(),
            Some("opentide info threats lists the ones that exist")
        );
        assert_eq!(refs[0].label.as_deref(), Some("no object has this id"));
        assert_eq!((refs[0].line, refs[0].column), (Some(7), Some(7)));
        assert!(
            with_code(&validation, "vocab_unknown").is_empty(),
            "one finding per cause"
        );
    }

    #[test]
    fn a_vocabulary_typo_has_a_safe_fix_only_when_it_is_the_same_word() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!("name: A\nmetadata:\n  uuid: {U1}\n  schema: rule::1.1\n  tlp: AMBER\n"),
        );
        fs.write(
            "/ws/objects/rules/b.yaml",
            format!("name: B\nmetadata:\n  uuid: {U2}\n  schema: rule::1.1\n  tlp: ambr\n"),
        );
        let validation = run(&fs, &Options::default());
        let typos = with_code(&validation, "vocab_unknown");
        assert_eq!(typos.len(), 2);
        let fix = |file: &str| {
            typos
                .iter()
                .find(|d| d.path.as_deref() == Some(file))
                .and_then(|d| d.fix.clone())
                .unwrap()
        };
        assert!(fix("objects/rules/a.yaml").safe);
        assert_eq!(fix("objects/rules/a.yaml").edits[0].replacement, "amber");
        assert!(!fix("objects/rules/b.yaml").safe);
        assert_eq!(validation.summary.fixable, 1);
        assert_eq!(typos[0].context["vocab"].as_str(), Some("tlp::1.0"));
    }

    #[test]
    fn errors_are_sorted_and_the_summary_counts_files() {
        let fs = workspace();
        fs.write("/ws/objects/rules/b.yaml", rule("bad-b", "B"));
        fs.write("/ws/objects/rules/a.yaml", rule("bad-a", "A"));
        fs.write("/ws/objects/rules/team/c.yaml", rule(U1, "C"));
        let validation = run(
            &fs,
            &Options {
                check: Some(Check::UuidFormat),
                ..Options::default()
            },
        );
        let paths: Vec<&str> = validation
            .report
            .issues
            .iter()
            .filter_map(|d| d.path.as_deref())
            .collect();
        assert_eq!(paths, ["objects/rules/a.yaml", "objects/rules/b.yaml"]);
        assert_eq!(validation.summary.errors, 2);
        assert_eq!(validation.summary.files, 2);
        assert_eq!(validation.summary.warning_files, 1);
        assert_eq!(validation.summary.objects, 2);
        assert_eq!(validation.checks, [(Check::UuidFormat, "failed")]);
    }

    #[test]
    fn a_file_that_is_not_yaml_is_placed_and_helped() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", "name: [A\n");
        fs.write("/ws/objects/rules/b.yaml", "- a list\n");
        let validation = run(&fs, &Options::default());
        let parse = with_code(&validation, "yaml_parse");
        assert_eq!(parse.len(), 2);
        let list = parse
            .iter()
            .find(|d| d.path.as_deref() == Some("objects/rules/b.yaml"))
            .unwrap();
        assert_eq!(
            (list.line, list.column, list.end_column),
            (Some(1), Some(1), Some(9))
        );
        assert_eq!(list.help, None, "the frame's own help note says it");
        let broken = parse
            .iter()
            .find(|d| d.path.as_deref() == Some("objects/rules/a.yaml"))
            .unwrap();
        assert!(broken.line.is_some());
        assert!(
            broken
                .help
                .as_deref()
                .is_some_and(|h| h.starts_with("look at the indentation"))
        );
    }
}

/// Every finding recorded by the oracle's `validate --json` reads into the
/// one `Diagnostic` and is written back byte for byte, keys in order.
mod diagnostic_json {
    use std::path::Path;

    use opentide_workspace::Diagnostic;

    #[derive(serde::Deserialize)]
    struct Recorded {
        report: Report,
    }

    #[derive(serde::Deserialize)]
    struct Report {
        issues: Vec<Diagnostic>,
        warnings: Vec<Diagnostic>,
    }

    #[test]
    fn every_recorded_finding_round_trips() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/cases/validate/json");
        let mut findings = 0;
        for fixture in std::fs::read_dir(&root).unwrap() {
            for case in std::fs::read_dir(fixture.unwrap().path()).unwrap() {
                let stdout = std::fs::read_to_string(case.unwrap().path().join("stdout")).unwrap();
                // Read from the text, so `context` keeps the order it was written in.
                let Ok(document) = serde_json::from_str::<Recorded>(&stdout) else {
                    continue;
                };
                for diagnostic in document
                    .report
                    .issues
                    .iter()
                    .chain(&document.report.warnings)
                {
                    let written = serde_json::to_string(diagnostic).unwrap();
                    assert!(
                        stdout.contains(&written),
                        "not written as recorded: {written}"
                    );
                    findings += 1;
                }
            }
        }
        assert!(findings > 500, "only {findings} findings read");
    }
}
