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
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use opentide_workspace::validate::objects::merge_reference_findings;
    use opentide_workspace::validate::{
        Check, Options, QueriesMode, QueryCheck, QueryFindings, QueryObject, Selection, Validation,
    };
    use opentide_workspace::{Diagnostic, FileSystem, MemoryFs, RootOptions, Severity, Workspace};

    const ROOT: &str = "/ws";
    const U1: &str = "11111111-1111-4111-8111-111111111111";
    const U2: &str = "22222222-2222-4222-8222-222222222222";
    const U3: &str = "33333333-3333-4333-8333-333333333333";

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
        // `original.file_path` is the native path string (`\ws\objects\...`
        // on Windows), so it is compared as a path; the rest of the context,
        // key order included, is compared as the serialised text.
        let context = serde_json::to_string(&duplicate.context).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&context).unwrap();
        let original_path = parsed["original"]["file_path"].as_str().unwrap();
        assert_eq!(
            Path::new(original_path),
            Path::new("/ws/objects/rules/a.yaml")
        );
        let encoded_path = serde_json::to_string(original_path).unwrap();
        assert_eq!(
            context.replacen(&encoded_path, r#""<a.yaml>""#, 1),
            format!(
                r#"{{"value":"{U1}","original":{{"name":"A","file_name":"a.yaml","file_path":"<a.yaml>","field_path":["metadata","uuid"]}}}}"#
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
    fn google_secops_advisories_warn_and_shared_rule_names_fail() {
        let fs = workspace();
        let block = |name: &str| {
            format!(
                "configurations:\n  google_secops:\n    enabled: true\n    name: {name}\n    \
                 status: X\n    events: $e.metadata.event_type = \"X\"\n    condition: \
                 $e\n"
            )
        };
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!("{}{}", rule(U1, "A"), block("shared_name")),
        );
        fs.write(
            "/ws/objects/rules/b.yaml",
            format!("{}{}", rule(U2, "B"), block("SHARED_name")),
        );
        let validation = run(&fs, &Options::default());
        let advised = with_code(&validation, "google_secops_risk_score_missing");
        assert_eq!(advised.len(), 2);
        assert_eq!(advised[0].severity, Severity::Warning);
        assert_eq!(advised[0].field_path, ["configurations", "google_secops"]);
        let duplicates = with_code(&validation, "google_secops_name_duplicate");
        assert_eq!(duplicates.len(), 2);
        assert_eq!(duplicates[0].severity, Severity::Error);
        assert!(
            duplicates
                .iter()
                .any(|d| d.object_uuid == U1 && d.message.contains(U2)),
            "{duplicates:?}"
        );
        assert!(duplicates.iter().all(|d| d.yaml_line.is_some()));
    }

    #[test]
    fn bitdefender_yara_signatures_and_advisories() {
        let fs = workspace();
        let block = |signature: &str| {
            format!(
                "response:\n  alert_severity: Critical\nconfigurations:\n  bitdefender:\n    \
                 enabled: true\n    schema: platform::bitdefender::1.0\n    status: STAGING\n    \
                 yara:\n      signature: {signature}\n"
            )
        };
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!("{}{}", rule(U1, "A"), block("\"  \"")),
        );
        fs.write(
            "/ws/objects/rules/b.yaml",
            format!(
                "{}description: &sig |\n  rule A {{ condition: true }}\n{}",
                rule(U2, "B"),
                block("*sig")
            ),
        );
        let validation = run(&fs, &Options::default());
        let empty = with_code(&validation, "yara_empty_signature");
        assert_eq!(empty.len(), 1, "{empty:?}");
        assert_eq!(empty[0].object_uuid, U1);
        assert_eq!(
            empty[0].field_path,
            ["configurations", "bitdefender", "yara", "signature"]
        );
        let aliased = with_code(&validation, "yara_signature_alias");
        assert_eq!(aliased.len(), 1, "{aliased:?}");
        assert_eq!(aliased[0].object_uuid, U2);
        assert_eq!(aliased[0].severity, Severity::Error);
        assert_eq!(
            aliased[0].message,
            "configurations.bitdefender.yara.signature is a YAML alias; write the YARA \
             signature out in the block"
        );
        // On the anchor's line, as the oracle's reader places an alias.
        let anchor = rule(U2, "B").lines().count();
        assert_eq!(aliased[0].yaml_line, Some(anchor));
        let collapsed = with_code(&validation, "bitdefender_severity_collapsed");
        assert_eq!(collapsed.len(), 2, "{collapsed:?}");
        assert!(collapsed.iter().all(|d| d.severity == Severity::Warning));
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

    /// #913 (0.26.0): a legacy `rule_id::<tenant>` key whose id is text, on
    /// blocks whose models refuse unknown keys (Sysdig) and accept them as
    /// legacy keys (SentinelOne), is `external_id_in_rule`, and nothing reads
    /// the tenant in its name as a vocabulary or schema version: the oracle
    /// (0.23.0) crashed with `invalid literal for int() with base 10`.
    #[test]
    fn a_legacy_tenant_key_with_a_text_id_is_external_id_in_rule() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!(
                "{}configurations:\n  sysdig:\n    status: X\n    condition: proc.name = bash\n    \
                 rule_id::prod: '12'\n",
                rule(U1, "A")
            ),
        );
        fs.write(
            "/ws/objects/rules/b.yaml",
            format!(
                "{}configurations:\n  sentinel_one:\n    status: X\n    rule_id::soc: 9f2c\n",
                rule(U2, "B")
            ),
        );
        let validation = run(&fs, &Options::default());
        let mut paths: Vec<Vec<String>> = with_code(&validation, "external_id_in_rule")
            .iter()
            .map(|finding| finding.field_path.clone())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                ["configurations", "sentinel_one", "rule_id::soc"],
                ["configurations", "sysdig", "rule_id::prod"],
            ]
        );
        // Not also a schema error, nor a vocabulary one.
        for code in ["schema_validation", "vocab_unknown", "internal"] {
            assert!(
                with_code(&validation, code).iter().all(|finding| !finding
                    .field_path
                    .iter()
                    .any(|key| key.starts_with("rule_id"))),
                "{code}"
            );
        }
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

    fn narrowed(fs: &Arc<MemoryFs>, check: Option<Check>, selection: &Selection) -> Validation {
        run(
            fs,
            &Options {
                check,
                selection: Some(selection),
                ..Options::default()
            },
        )
    }

    fn uuids(values: &[&str]) -> Selection {
        Selection {
            uuids: values.iter().map(|v| (*v).to_owned()).collect(),
            ..Selection::default()
        }
    }

    fn files(values: &[&str]) -> Selection {
        Selection {
            files: values.iter().map(|v| (*v).to_owned()).collect(),
            ..Selection::default()
        }
    }

    fn types(values: &[&str]) -> Selection {
        Selection {
            types: values.iter().map(|v| (*v).to_owned()).collect(),
            ..Selection::default()
        }
    }

    fn paths_of<'v>(validation: &'v Validation, code: &str) -> Vec<&'v str> {
        let mut paths: Vec<&str> = with_code(validation, code)
            .iter()
            .filter_map(|d| d.path.as_deref())
            .collect();
        paths.sort_unstable();
        paths
    }

    /// A filesystem that counts the paths it resolves.
    struct CountingFs {
        inner: Arc<MemoryFs>,
        resolved: std::sync::atomic::AtomicUsize,
    }

    impl FileSystem for CountingFs {
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            self.inner.read(path)
        }

        fn kind(&self, path: &Path) -> std::io::Result<opentide_workspace::fs::EntryKind> {
            self.inner.kind(path)
        }

        fn read_dir(&self, path: &Path) -> std::io::Result<Vec<opentide_workspace::fs::DirEntry>> {
            self.inner.read_dir(path)
        }

        fn resolve(&self, path: &Path) -> PathBuf {
            self.resolved
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.resolve(path)
        }
    }

    /// `--file` on one object of a large workspace (the language server
    /// checks the open documents this way) resolves the target and the
    /// object folders, not every object's path: resolving each component of
    /// each path cost more than checking the object (#821).
    #[test]
    fn a_file_selection_resolves_folders_not_every_object() {
        let memory = workspace();
        for i in 0..200 {
            let uuid = format!("{i:08x}-1111-4111-8111-111111111111");
            memory.write(format!("/ws/objects/rules/r{i:03}.yaml"), rule(&uuid, "R"));
        }
        let fs = Arc::new(CountingFs {
            inner: Arc::clone(&memory),
            resolved: std::sync::atomic::AtomicUsize::new(0),
        });
        let workspace = Workspace::open(
            Arc::clone(&fs) as Arc<dyn FileSystem>,
            opentide_workspace::Options {
                roots: RootOptions {
                    repo: Some(PathBuf::from(ROOT)),
                    cwd: PathBuf::from(ROOT),
                    ..RootOptions::default()
                },
            },
        )
        .unwrap();
        fs.resolved.store(0, std::sync::atomic::Ordering::SeqCst);
        let validation = workspace.validate(&Options {
            selection: Some(&files(&["objects/rules/r007.yaml"])),
            ..Options::default()
        });
        assert_eq!(validation.summary.objects, 1);
        assert!(with_code(&validation, "scope_no_match").is_empty());
        let resolved = fs.resolved.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            resolved < 20,
            "{resolved} paths resolved to select one file of 200"
        );
    }

    /// An object file that is a symbolic link is selected by its own path
    /// and by its target's, as `fs.resolve` resolves them.
    #[cfg(unix)]
    #[test]
    fn a_file_selection_selects_a_linked_object_by_link_or_target() {
        let dir =
            std::env::temp_dir().join(format!("opentide-ws-scope-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("objects/rules")).unwrap();
        std::fs::create_dir_all(dir.join("shared")).unwrap();
        std::fs::write(dir.join("shared/x.yaml"), rule(U1, "Linked")).unwrap();
        std::fs::write(dir.join("objects/rules/plain.yaml"), rule(U2, "Plain")).unwrap();
        std::os::unix::fs::symlink(
            dir.join("shared/x.yaml"),
            dir.join("objects/rules/link.yaml"),
        )
        .unwrap();
        let workspace = Workspace::open_os(Some(dir.clone())).unwrap();
        let selected = |target: &str| {
            let validation = workspace.validate(&Options {
                check: Some(Check::UuidFormat),
                selection: Some(&files(&[target])),
                ..Options::default()
            });
            (
                validation.summary.objects,
                with_code(&validation, "scope_no_match").len(),
            )
        };
        let target = dir.join("shared/x.yaml").display().to_string();
        let link = dir.join("objects/rules/link.yaml").display().to_string();
        assert_eq!(selected(&target), (1, 0));
        assert_eq!(selected(&link), (1, 0));
        assert_eq!(selected("objects/rules/plain.yaml"), (1, 0));
        assert_eq!(selected("objects/rules/none.yaml"), (0, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_narrowed_run_reports_the_duplicates_it_selects() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        fs.write("/ws/objects/rules/b.yaml", rule(U1, "B"));
        fs.write("/ws/objects/rules/c.yaml", rule(U2, "C"));
        fs.write("/ws/objects/rules/d.yaml", rule(U2, "D"));
        fs.write("/ws/objects/rules/e.yaml", rule(U3, "E"));
        let check = Some(Check::IdUniqueness);
        // --uuid: the duplicates of that UUID only.
        let by_uuid = narrowed(&fs, check, &uuids(&[U1]));
        assert_eq!(paths_of(&by_uuid, "duplicate_id"), ["objects/rules/b.yaml"]);
        // --file: the later file, or the first one it repeats.
        let later = narrowed(&fs, check, &files(&["objects/rules/d.yaml"]));
        assert_eq!(paths_of(&later, "duplicate_id"), ["objects/rules/d.yaml"]);
        let first = narrowed(&fs, check, &files(&["objects/rules/a.yaml"]));
        assert_eq!(paths_of(&first, "duplicate_id"), ["objects/rules/b.yaml"]);
        // A file that repeats nothing selects no duplicate.
        let other = narrowed(&fs, check, &files(&["objects/rules/e.yaml"]));
        assert!(with_code(&other, "duplicate_id").is_empty());
        let other = narrowed(&fs, check, &uuids(&[U3]));
        assert!(with_code(&other, "duplicate_id").is_empty());
        // --type alone names no target: every duplicate.
        let by_type = narrowed(&fs, check, &types(&["rule"]));
        assert_eq!(
            paths_of(&by_type, "duplicate_id"),
            ["objects/rules/b.yaml", "objects/rules/d.yaml"]
        );
    }

    #[test]
    fn a_narrowed_run_reports_the_invalid_uuids_of_the_files_it_selects_kg_04() {
        let fs = workspace();
        for (file, name) in [("a", "A"), ("b", "B"), ("c", "C")] {
            fs.write(
                format!("/ws/objects/rules/{file}.yaml"),
                rule("bad-1", name),
            );
        }
        fs.write("/ws/objects/threats/t.yaml", rule("bad-1", "T"));
        let check = Some(Check::UuidFormat);
        for file in ["a", "b", "c"] {
            let path = format!("objects/rules/{file}.yaml");
            let one = narrowed(&fs, check, &files(&[path.as_str()]));
            assert_eq!(
                paths_of(&one, "invalid_uuid"),
                [path.as_str()],
                "--file {path}"
            );
        }
        let threats = narrowed(&fs, check, &types(&["threat"]));
        assert!(
            paths_of(&threats, "invalid_uuid")
                .iter()
                .all(|path| !path.starts_with("objects/rules/")),
            "--type threat: {:?}",
            paths_of(&threats, "invalid_uuid")
        );
        let rules = narrowed(&fs, check, &types(&["rule"]));
        assert_eq!(
            paths_of(&rules, "invalid_uuid"),
            [
                "objects/rules/a.yaml",
                "objects/rules/b.yaml",
                "objects/rules/c.yaml"
            ]
        );
    }

    #[test]
    fn a_parse_error_outside_the_selected_types_is_not_reported() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", "name: [A\n");
        fs.write(
            "/ws/objects/threats/t.yaml",
            format!("name: T\nmetadata:\n  uuid: {U1}\n  schema: threat::1.0\n"),
        );
        let threats = narrowed(&fs, None, &types(&["threat"]));
        assert!(
            with_code(&threats, "yaml_parse").is_empty(),
            "{:?}",
            threats.report
        );
        let rules = narrowed(&fs, None, &types(&["rule"]));
        assert_eq!(paths_of(&rules, "yaml_parse"), ["objects/rules/a.yaml"]);
    }

    #[test]
    fn a_scope_that_selects_nothing_fails_the_object_check_that_ran() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        let validation = narrowed(&fs, Some(Check::UuidFormat), &uuids(&[U2]));
        assert_eq!(with_code(&validation, "scope_no_match").len(), 1);
        assert_eq!(validation.report.issues.len(), 1, "{:?}", validation.report);
        assert_eq!(validation.checks, [(Check::UuidFormat, "failed")]);
        // The object itself passes the check.
        let selected = narrowed(&fs, Some(Check::UuidFormat), &uuids(&[U1]));
        assert_eq!(selected.checks, [(Check::UuidFormat, "passed")]);
    }

    #[test]
    fn a_narrowed_run_reports_the_configuration_only_when_it_is_the_check_asked() {
        let fs = workspace();
        fs.write(
            "/ws/.opentide/configurations/deployment.toml",
            "colour = 1\n",
        );
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        let selection = uuids(&[U1]);
        let asked = narrowed(&fs, Some(Check::Configuration), &selection);
        assert_eq!(with_code(&asked, "unknown_key").len(), 1);
        assert_eq!(asked.checks, [(Check::Configuration, "failed")]);
        let default = narrowed(&fs, None, &selection);
        assert!(
            all(&default)
                .iter()
                .all(|d| d.object_type != "configuration"),
            "{:?}",
            default.report
        );
        assert!(default.checks.contains(&(Check::Configuration, "passed")));
    }

    #[test]
    fn errors_of_one_file_follow_its_lines() {
        let fs = workspace();
        // `tlp` sorts before `uuid` by field, but is written after it.
        fs.write(
            "/ws/objects/rules/a.yaml",
            "name: A\nmetadata:\n  uuid: bad-a\n  schema: rule::1.1\n  tlp: ambr\n",
        );
        let validation = run(&fs, &Options::default());
        let codes: Vec<&str> = validation
            .report
            .issues
            .iter()
            .map(|d| d.code.as_str())
            .collect();
        let position = |code: &str| codes.iter().position(|c| *c == code).unwrap();
        assert!(
            position("invalid_uuid") < position("vocab_unknown"),
            "{codes:?}"
        );
        let lines: Vec<i64> = validation
            .report
            .issues
            .iter()
            .map(|d| d.yaml_line.map_or(-1, |l| i64::try_from(l).unwrap()))
            .collect();
        assert!(lines.windows(2).all(|w| w[0] <= w[1]), "{lines:?}");
    }

    fn finding(code: &str, value: &str, suggestion: Option<&str>) -> Diagnostic {
        Diagnostic::error(code, format!("{code} {value}"))
            .object(U1, "objective")
            .at(["objective", "threats", "0"])
            .with("value", value)
            .suggest(suggestion.map(str::to_owned))
    }

    #[test]
    fn a_reference_absorbs_the_vocabulary_finding_on_its_value_and_its_suggestion() {
        let merged = merge_reference_findings(vec![
            finding("vocab_unknown", U2, Some(U3)),
            finding("invalid_ref", U2, None),
            finding("vocab_unknown", "other", Some("x")),
        ]);
        let shown: Vec<(&str, Option<&str>, Option<&str>)> = merged
            .iter()
            .map(|d| (d.code.as_str(), d.value(), d.suggestion.as_deref()))
            .collect();
        assert_eq!(
            shown,
            [
                ("invalid_ref", Some(U2), Some(U3)),
                ("vocab_unknown", Some("other"), Some("x"))
            ]
        );
        // A reference's own suggestion stays.
        let merged = merge_reference_findings(vec![
            finding("invalid_ref", U2, Some(U1)),
            finding("vocab_unknown", U2, Some(U3)),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].suggestion.as_deref(), Some(U1));
        // Without a reference finding, nothing changes.
        let alone = vec![finding("vocab_unknown", U2, Some(U3))];
        assert_eq!(merge_reference_findings(alone.clone()), alone);
    }

    #[test]
    fn a_vocabulary_list_of_the_wrong_shape_is_reported_once() {
        let fs = workspace();
        let packed = "Elevation of privilege; Repudiation";
        fs.write(
            "/ws/objects/threats/t.yaml",
            format!(
                "name: T\nmetadata:\n  uuid: {U1}\n  schema: threat::1.0\nthreat:\n  leverage: [Repudiation, '{packed}']\n"
            ),
        );
        let validation = run(&fs, &Options::default());
        let on_value: Vec<&Diagnostic> = all(&validation)
            .into_iter()
            .filter(|d| d.field_path == ["threat", "leverage", "1"])
            .collect();
        assert_eq!(on_value.len(), 1, "{on_value:?}");
        assert_eq!(on_value[0].code, "schema_validation");
        assert!(
            on_value[0]
                .message
                .contains("packs several vocabulary names"),
            "{}",
            on_value[0].message
        );
        assert!(
            with_code(&validation, "vocab_unknown").is_empty(),
            "{:?}",
            with_code(&validation, "vocab_unknown")
        );
    }

    #[test]
    fn a_broken_shard_is_reported_once_and_only_for_the_rule_selected() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        fs.write("/ws/objects/rules/b.yaml", rule(U2, "B"));
        fs.write(
            format!("/ws/.opentide/states/deployment/{U1}.json"),
            "{\"schema\": \"deployment.state::1.0\"}",
        );
        let full = run(&fs, &Options::default());
        assert_eq!(with_code(&full, "deployment_state_shape").len(), 1);
        let own = narrowed(&fs, None, &uuids(&[U1]));
        assert_eq!(with_code(&own, "deployment_state_shape").len(), 1);
        let other = narrowed(&fs, None, &uuids(&[U2]));
        assert!(with_code(&other, "deployment_state_shape").is_empty());
    }

    /// A query analysis that reports one finding per object at
    /// `configurations.splunk.query`, and records how it was called.
    struct StubQueries {
        calls: Mutex<Vec<(Vec<String>, bool)>>,
    }

    impl QueryCheck for StubQueries {
        fn check(
            &self,
            _ws: &Workspace,
            objects: &[QueryObject<'_>],
            as_warnings: bool,
        ) -> QueryFindings {
            self.calls.lock().unwrap().push((
                objects.iter().map(|o| o.uuid.to_owned()).collect(),
                as_warnings,
            ));
            let mut found = QueryFindings {
                queries: objects.len(),
                ..QueryFindings::default()
            };
            for object in objects {
                let make = |field: &[&str]| {
                    let severity = if as_warnings {
                        Diagnostic::warning("kql_syntax", "bad query")
                    } else {
                        Diagnostic::error("kql_syntax", "bad query")
                    };
                    severity
                        .object(object.uuid, object.family)
                        .file(object.path)
                        .at(field.iter().copied())
                        .with("source", "engine")
                };
                let finding = make(&["configurations", "splunk", "query"]);
                if as_warnings {
                    found.warnings.push(finding);
                } else {
                    found.errors.push(finding);
                }
            }
            found
        }
    }

    fn stub() -> StubQueries {
        StubQueries {
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with_queries(fs: &Arc<MemoryFs>, queries: QueriesMode, check: &StubQueries) -> Validation {
        run(
            fs,
            &Options {
                queries,
                query_check: Some(check),
                ..Options::default()
            },
        )
    }

    fn engine_paths(items: &[Diagnostic]) -> Vec<&Path> {
        items
            .iter()
            .filter(|d| d.code == "kql_syntax")
            .filter_map(|d| d.file_path.as_deref())
            .collect()
    }

    fn engine_findings(validation: &Validation) -> (Vec<&Path>, Vec<&Path>) {
        (
            engine_paths(&validation.report.issues),
            engine_paths(&validation.report.warnings),
        )
    }

    #[test]
    fn the_query_check_reports_the_engine_findings_once_and_as_asked() {
        let fs = workspace();
        // a.yaml's query is the schema's to reject (a number); b.yaml's is the engine's.
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!(
                "{}configurations:\n  splunk:\n    query: 5\n",
                rule(U1, "A")
            ),
        );
        fs.write("/ws/objects/rules/b.yaml", rule(U2, "B"));
        let a = Path::new("/ws/objects/rules/a.yaml");
        let b = Path::new("/ws/objects/rules/b.yaml");

        let check = stub();
        let errors = with_queries(&fs, QueriesMode::Error, &check);
        let mut called = check.calls.lock().unwrap().clone();
        called[0].0.sort();
        assert_eq!(called, [(vec![U1.to_owned(), U2.to_owned()], false)]);
        assert!(
            errors
                .report
                .issues
                .iter()
                .any(|d| d.file_path.as_deref() == Some(a)
                    && d.field_path == ["configurations", "splunk", "query"]
                    && d.code != "kql_syntax"),
            "the schema rejects a.yaml's query: {:?}",
            errors.report.issues
        );
        assert_eq!(engine_findings(&errors), (vec![b], vec![]));
        assert_eq!(errors.report.stats.queries_checked, Some(2));
        assert_eq!(errors.summary.queries, Some(2));
        assert!(errors.checks.contains(&(Check::Queries, "failed")));
        assert!(errors.failed);

        let check = stub();
        let warned = with_queries(&fs, QueriesMode::Warn, &check);
        assert!(check.calls.lock().unwrap()[0].1, "asked for warnings");
        assert_eq!(engine_findings(&warned), (vec![], vec![b]));
        assert!(warned.checks.contains(&(Check::Queries, "passed")));
        assert!(warned.warned);

        let check = stub();
        let off = with_queries(&fs, QueriesMode::Off, &check);
        assert!(check.calls.lock().unwrap().is_empty());
        assert!(off.checks.iter().all(|(c, _)| *c != Check::Queries));
        assert_eq!(off.report.stats.queries_checked, None);
    }
    mod cve {
        use super::*;
        use opentide_workspace::validate::{CveCheck, CveLookup, cve_identifiers};

        /// Answers from a table, as the CLI's lookup would.
        struct Table(Mutex<Vec<String>>);

        impl CveCheck for Table {
            fn canonical(&self, text: &str) -> String {
                text.trim().to_uppercase()
            }

            fn lookup(&self, threat: &str, id: &str) -> CveLookup {
                self.0.lock().unwrap().push(format!("{threat} {id}"));
                match id {
                    "CVE-2024-1" => CveLookup::Found,
                    "CVE-2024-2" => CveLookup::NotFound,
                    _ => CveLookup::Unavailable("down".to_owned()),
                }
            }
        }

        fn threat(uuid: &str, cve: &str) -> String {
            format!(
                "name: T\nmetadata:\n  uuid: {uuid}\n  schema: threat::1.0\nthreat:\n  cve: {cve}\n"
            )
        }

        #[test]
        fn unknown_references_are_errors_and_unreachable_ones_warnings() {
            let fs = workspace();
            fs.write(
                "/ws/objects/threats/a.yaml",
                threat(U1, "[cve-2024-1, CVE-2024-2, x, ' cve-2024-2']"),
            );
            fs.write("/ws/objects/threats/b.yaml", threat(U2, "null"));
            let table = Table(Mutex::new(Vec::new()));
            let validation = run(
                &fs,
                &Options {
                    check: Some(Check::Cve),
                    cve_check: Some(&table),
                    ..Options::default()
                },
            );
            assert_eq!(
                *table.0.lock().unwrap(),
                [
                    format!("{U1} CVE-2024-1"),
                    format!("{U1} CVE-2024-2"),
                    format!("{U1} X")
                ]
            );
            let invalid = with_code(&validation, "invalid_cve");
            assert_eq!(invalid.len(), 1);
            assert_eq!(invalid[0].message, "Invalid CVE references: CVE-2024-2");
            assert_eq!(invalid[0].field_path, ["threat", "cve"]);
            let unchecked = with_code(&validation, "cve_lookup_unavailable");
            assert_eq!(
                unchecked[0].message,
                "Could not check CVE references on Vulnerability-Lookup: X (down)"
            );
            assert_eq!(unchecked[0].severity, Severity::Warning);
            assert_eq!(status(&validation, Check::Cve), "failed");
            // Without a lookup the check reports nothing.
            let quiet = run(
                &fs,
                &Options {
                    check: Some(Check::Cve),
                    ..Options::default()
                },
            );
            assert!(with_code(&quiet, "invalid_cve").is_empty());
        }

        #[test]
        fn identifiers_read_as_python_reads_the_field() {
            let canonical = |text: &str| text.trim().to_owned();
            let doc = opentide_schema::node::load(
                "a: CVE-1\nb: [1, true, null, CVE-1, CVE-1]\nc: 5\nd: ' '\n",
            )
            .unwrap();
            let root = doc.root().unwrap();
            let get = |key: &str| root.get(key).map(AsRef::as_ref);
            assert_eq!(cve_identifiers(get("a"), &canonical), ["CVE-1"]);
            assert_eq!(
                cve_identifiers(get("b"), &canonical),
                ["1", "True", "None", "CVE-1"]
            );
            assert_eq!(cve_identifiers(get("c"), &canonical), ["5"]);
            assert!(cve_identifiers(get("d"), &canonical).is_empty());
            assert!(cve_identifiers(None, &canonical).is_empty());
        }
    }

    /// A plugin's block check (UC-4.5): it claims `acme`, flags `severity`.
    struct AcmeBlocks;

    impl opentide_workspace::validate::PlatformConfigurations for AcmeBlocks {
        fn platforms(&self) -> Vec<String> {
            vec!["acme".to_owned(), "sentinel".to_owned()]
        }

        fn check(
            &self,
            platform: &str,
            block: &serde_json::Value,
        ) -> Vec<opentide_workspace::validate::PlatformFinding> {
            assert_eq!(platform, "acme");
            let mut found = Vec::new();
            if !block["severity"].is_i64() {
                found.push(opentide_workspace::validate::PlatformFinding {
                    field_path: vec!["severity".to_owned()],
                    message: "Input should be a valid integer".to_owned(),
                    warning: false,
                });
            }
            if block.get("note").is_some() {
                found.push(opentide_workspace::validate::PlatformFinding {
                    field_path: vec!["note".to_owned()],
                    message: "note is deprecated".to_owned(),
                    warning: true,
                });
            }
            found
        }
    }

    #[test]
    fn a_plugin_block_is_checked_by_the_plugin_not_refused_as_an_extra_key() {
        let fs = workspace();
        let text = format!(
            "{}configurations:\n  acme:\n    severity: high\n    note: x\n",
            rule(U1, "A")
        );
        fs.write("/ws/objects/rules/a.yaml", text);
        let place =
            |path: &[&str]| -> Vec<String> { path.iter().map(|part| (*part).to_owned()).collect() };
        let without = run(&fs, &Options::default());
        assert!(
            without
                .report
                .issues
                .iter()
                .any(|d| d.field_path == place(&["configurations", "acme"])),
            "an unknown platform's block is an extra key without a plugin"
        );
        let with = run(
            &fs,
            &Options {
                platform_configurations: Some(&AcmeBlocks),
                ..Options::default()
            },
        );
        assert!(
            !with
                .report
                .issues
                .iter()
                .any(|d| d.field_path == place(&["configurations", "acme"]))
        );
        let severity = with
            .report
            .issues
            .iter()
            .find(|d| d.field_path == place(&["configurations", "acme", "severity"]))
            .unwrap();
        assert_eq!(severity.code, "schema_validation");
        assert_eq!(severity.message, "acme: Input should be a valid integer");
        assert_eq!(severity.object_uuid, U1);
        assert_eq!(severity.line, Some(7));
        let note = with
            .report
            .warnings
            .iter()
            .find(|d| d.field_path == place(&["configurations", "acme", "note"]))
            .unwrap();
        assert_eq!(note.message, "acme: note is deprecated");
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
