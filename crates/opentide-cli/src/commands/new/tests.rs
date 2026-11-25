use super::*;

#[test]
fn a_uuid_is_the_canonical_hex_form() {
    assert!(is_uuid("00000000-0000-4000-8000-000000000000"));
    assert!(is_uuid("ABCDEF00-0000-4000-8000-000000000000"));
    assert!(!is_uuid("00000000-0000-4000-8000-00000000000"));
    assert!(!is_uuid("0000000g-0000-4000-8000-000000000000"));
    assert!(!is_uuid("not-a-uuid"));
}

#[test]
fn a_taken_stem_gets_the_uuid_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let uuid = "1234abcd-0000-4000-8000-000000000000";
    let first = target_path(dir.path(), "Credential Dumping", uuid, None, "slug");
    assert_eq!(first, dir.path().join("credential-dumping.yaml"));
    std::fs::write(&first, "").unwrap();
    let second = target_path(dir.path(), "Credential Dumping", uuid, None, "slug");
    assert_eq!(second, dir.path().join("credential-dumping-1234abcd.yaml"));
    // `name` keeps the name, and a stem taken in another case is taken.
    std::fs::write(dir.path().join("my rule.yml"), "").unwrap();
    let named = target_path(dir.path(), "My Rule", uuid, None, "name");
    assert_eq!(named, dir.path().join("My Rule-1234abcd.yaml"));
}

/// `new rule --name CON` cannot write `con.yaml`: Windows takes it for the
/// console. Any style, any case, with or without an extension.
#[test]
fn a_windows_device_name_gets_an_underscore() {
    let dir = tempfile::tempdir().unwrap();
    let uuid = "1234abcd-0000-4000-8000-000000000000";
    for (name, slug, named) in [
        ("CON", "_con", "_CON"),
        ("PRN", "_prn", "_PRN"),
        ("AUX", "_aux", "_AUX"),
        ("nul", "_nul", "_nul"),
        ("Com1", "_com1", "_Com1"),
        ("LPT1", "_lpt1", "_LPT1"),
        ("con.txt", "con-txt", "_con.txt"),
    ] {
        assert_eq!(
            target_path(dir.path(), name, uuid, None, "slug"),
            dir.path().join(format!("{slug}.yaml")),
            "{name}"
        );
        assert_eq!(
            target_path(dir.path(), name, uuid, None, "name"),
            dir.path().join(format!("{named}.yaml")),
            "{name}"
        );
    }
}

#[test]
fn a_path_names_the_file_or_its_folder() {
    let dir = tempfile::tempdir().unwrap();
    let uuid = "1234abcd-0000-4000-8000-000000000000";
    let file = dir.path().join("x.yml");
    assert_eq!(
        target_path(dir.path(), "N", uuid, Some(&file), "slug"),
        file
    );
    let bare = dir.path().join("rule");
    assert_eq!(
        target_path(dir.path(), "N", uuid, Some(&bare), "slug"),
        dir.path().join("rule.yaml")
    );
    let folder = dir.path().join("sub");
    std::fs::create_dir(&folder).unwrap();
    assert_eq!(
        target_path(dir.path(), "N", uuid, Some(&folder), "slug"),
        folder.join("n.yaml")
    );
}

fn configuration(text: &str) -> std::sync::Arc<Node> {
    let root = opentide_schema::configuration::toml::parse(text).unwrap();
    std::sync::Arc::new(root)
}

#[test]
fn a_signal_is_found_by_any_spelling_and_kept_as_the_catalogue_writes_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("o.yaml"),
        "metadata:\n  uuid: 0AAA\nobjective:\n  signals:\n    - {name: S, uuid: 0BBB}\n",
    )
    .unwrap();
    assert_eq!(
        signal_spellings(dir.path()),
        HashMap::from([("0bbb".to_owned(), "0BBB".to_owned())])
    );
    assert_eq!(
        catalogue_spellings(dir.path()),
        HashMap::from([("0aaa".to_owned(), "0AAA".to_owned())])
    );
}

const CONFIGURED_UUID: &str = "11111111-2222-4333-8444-555555555555";

/// `organisation.toml` as the resolved configuration holds it.
fn organisation_file(body: &str) -> std::sync::Arc<Node> {
    configuration(&format!("[organisation]\n{body}\n"))
}

#[test]
fn the_uuids_of_a_catalogue_are_read_from_its_object_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.yaml"), "metadata:\n  uuid: X\n").unwrap();
    std::fs::write(dir.path().join("e.yaml"), "metadata: [1]\n").unwrap();
    assert_eq!(catalogue_uuids(dir.path()), HashSet::from(["x".to_owned()]));
}

/// `setup --org` keeps `{uuid, name}` in `organisation.toml`; `new` reads it
/// (#1670, smoke B17).
#[test]
fn the_configured_organisation_is_read_trimmed_and_checked() {
    let valid = organisation_file(&format!(
        "uuid = \" {CONFIGURED_UUID} \"\nname = \" Example Corp \""
    ));
    assert_eq!(
        configured_organisation(&valid),
        Configured::Usable(CONFIGURED_UUID.to_owned(), "Example Corp".to_owned())
    );
    assert_eq!(
        configured_organisation(&configuration("x = 1\n")),
        Configured::Absent
    );
    // A file `new` cannot write: what is wrong with it, in `setup`'s words
    // for the same file, and what fixes it.
    let setup = "run 'opentide setup --org \"<name>\"'";
    let replace = "replace its uuid with your organisation's UUID";
    let ok = format!("uuid = \"{CONFIGURED_UUID}\"");
    let fix = format!("fix it or {setup}");
    for (body, problems, advice) in [
        ("name = \"A\"".to_owned(), "it has no uuid", fix.clone()),
        (ok.clone(), "it has no name", fix.clone()),
        (
            format!("{ok}\nname = \"  \""),
            "its name is empty",
            fix.clone(),
        ),
        (
            format!("{ok}\nname = 7"),
            "its name is not text",
            fix.clone(),
        ),
        (format!("{ok}\nnmae = \"A\""), "it has no name", fix.clone()),
        (
            "uuid = \"u1\"\nname = \"A\"".to_owned(),
            "its uuid is not a UUID",
            replace.to_owned(),
        ),
        (
            "uuid = 7\nname = \"A\"".to_owned(),
            "its uuid is not text",
            replace.to_owned(),
        ),
        (
            "uuid = \"u1\"".to_owned(),
            "its uuid is not a UUID, it has no name",
            format!("{replace}, then {setup}"),
        ),
    ] {
        assert_eq!(
            configured_organisation(&organisation_file(&body)),
            Configured::Unusable {
                problems: problems.to_owned(),
                advice,
            },
            "{body}"
        );
    }
}

/// The organisation comes from `organisation.toml` and nothing else: with no
/// usable file there is none, and the reason says which (#1670, smoke B17).
#[test]
fn the_organisation_is_the_configured_one_and_nothing_else() {
    let configured = organisation_file(&format!(
        "uuid = \"{CONFIGURED_UUID}\"\nname = \"Example Corp\""
    ));
    let choice = organisation_for(&configured);
    assert_eq!(
        choice.organisation,
        Some((CONFIGURED_UUID.to_owned(), "Example Corp".to_owned()))
    );
    assert_eq!(choice.left_out, "");

    let choice = organisation_for(&configuration("x = 1\n"));
    assert_eq!(choice.organisation, None);
    assert_eq!(
        choice.left_out,
        "no organisation is configured; run 'opentide setup --org \"<name>\"'"
    );

    let choice = organisation_for(&organisation_file("name = \"A\""));
    assert_eq!(choice.organisation, None);
    assert_eq!(
        choice.left_out,
        format!(
            "{ORGANISATION_FILE} is not usable: it has no uuid; fix it or run 'opentide setup \
             --org \"<name>\"'"
        )
    );
    assert!(
        !choice.left_out.contains("catalogue"),
        "{}",
        choice.left_out
    );
    // A uuid that is there is kept by `setup --org`, so the advice is to
    // replace it by hand, not to run `setup`.
    for body in ["uuid = \"u1\"\nname = \"A\"", "uuid = 7\nname = \"A\""] {
        let choice = organisation_for(&organisation_file(body));
        assert_eq!(choice.organisation, None);
        assert!(
            choice
                .left_out
                .ends_with("replace its uuid with your organisation's UUID"),
            "{}",
            choice.left_out
        );
        assert!(!choice.left_out.contains("setup"), "{}", choice.left_out);
        assert!(
            !choice.left_out.contains("catalogue"),
            "{}",
            choice.left_out
        );
    }
}

#[test]
fn object_files_are_in_path_order() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
    for name in ["a.yaml", "a/b/c.yml", "a/z.yaml", "a/note.txt", "b.yml"] {
        std::fs::write(dir.path().join(name), "").unwrap();
    }
    let found: Vec<PathBuf> = object_files(dir.path())
        .into_iter()
        .map(|path| path.strip_prefix(dir.path()).unwrap().to_path_buf())
        .collect();
    let expected: Vec<PathBuf> = ["a/b/c.yml", "a/z.yaml", "a.yaml", "b.yml"]
        .iter()
        .map(PathBuf::from)
        .collect();
    assert_eq!(found, expected);
}

/// A link to a folder above it is not entered: each object is read once,
/// where following the link read it again at every level until the system
/// refused the path.
#[cfg(unix)]
#[test]
fn a_link_back_up_the_catalogue_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("rules")).unwrap();
    std::fs::write(
        dir.path().join("rules/r.yaml"),
        "metadata:\n  uuid: x\n  organisation:\n    uuid: u\n    name: N\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(dir.path(), dir.path().join("rules/up")).unwrap();
    assert_eq!(object_files(dir.path()), [dir.path().join("rules/r.yaml")]);
    assert_eq!(catalogue_uuids(dir.path()), HashSet::from(["x".to_owned()]));
}

/// The path `new` prints and writes has no `\\?\` prefix on Windows.
#[cfg(windows)]
#[test]
fn a_resolved_path_has_no_verbatim_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let resolved = dunce_canonical(dir.path());
    assert!(resolved.is_absolute());
    assert!(
        !resolved.to_string_lossy().starts_with(r"\\?\"),
        "{}",
        resolved.display()
    );
}

#[test]
fn a_resolved_path_is_absolute_and_a_missing_one_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let resolved = dunce_canonical(dir.path());
    assert!(resolved.is_absolute());
    assert_eq!(dunce_canonical(&resolved), resolved);
    let missing = dir.path().join("missing");
    assert_eq!(dunce_canonical(&missing), missing);
}

#[test]
fn the_first_inert_status_is_where_a_block_starts() {
    let config = opentide_schema::configuration::toml::parse(
        "[deployment]\nstatuses = [{name = \"LIVE\", strategy = \"RELEASE\"}, {name = \"DRAFT\", strategy = \"inert\"}, {name = \"X\", strategy = \"INERT\"}]\n",
    )
    .unwrap();
    assert_eq!(inert_status(&config), Some("DRAFT".to_owned()));
    let none = opentide_schema::configuration::toml::parse("[deployment]\n").unwrap();
    assert_eq!(inert_status(&none), None);
}

#[test]
fn a_workspace_root_has_its_folder_or_a_catalogue() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!is_workspace_root(dir.path()));
    std::fs::create_dir(dir.path().join("objects")).unwrap();
    assert!(is_workspace_root(dir.path()));
    // Only opentide's markers count: an `__init__.py` changes nothing.
    std::fs::write(dir.path().join("objects/__init__.py"), "").unwrap();
    assert!(is_workspace_root(dir.path()));
    std::fs::create_dir(dir.path().join(".opentide")).unwrap();
    assert!(is_workspace_root(dir.path()));
}

// -- the questions at a terminal (UC-6.0d) -----------------------------------

use crate::commands::setup::wizard::tests::{Reply, Script};
use std::cell::RefCell;

/// A workspace that enables Sentinel and Splunk, in a temporary folder.
fn prompted_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    for platform in ["sentinel", "splunk"] {
        std::fs::write(
            platforms.join(format!("{platform}.toml")),
            "[platform]\nenabled = true\n",
        )
        .unwrap();
    }
    std::fs::create_dir_all(dir.path().join("objects")).unwrap();
    dir
}

/// `new <family>` in `dir`, its questions answered by `answers`, at a
/// terminal when `can_prompt`: the report and the questions asked.
fn prompted(
    dir: &Path,
    family: &str,
    platforms: &[&str],
    answers: Vec<Reply>,
    can_prompt: bool,
) -> (Report, Vec<String>) {
    let script = RefCell::new(Script::new(answers));
    let env = Env::from_pairs([("TZ", "UTC")]);
    let interrupt = crate::app::Interrupt::default();
    let report = run(
        &NewArgs {
            family: family.into(),
            name: None,
            path: None,
            platforms: platforms.iter().map(|p| (*p).to_owned()).collect(),
            objective: None,
            threats: Vec::new(),
        },
        &Context {
            repo: Some(&dir.to_string_lossy()),
            env: &env,
            cwd: dir,
            version: "9.9.9",
            can_prompt,
            prompter: Some(&script),
            interrupt: Some(&interrupt),
        },
    );
    let asked = script.into_inner().asked;
    (report, asked)
}

fn written(report: &Report, dir: &Path) -> String {
    let data = Json::object(report.outcome.data.clone());
    let Some(Json::Str(path)) = data.get("path") else {
        panic!("no path: {:?}", report.outcome);
    };
    std::fs::read_to_string(dir.join(path)).unwrap()
}

/// At a terminal a missing name is asked for, as `_ask_name` asks.
#[test]
fn a_missing_name_is_asked_for_at_a_terminal() {
    let dir = prompted_workspace();
    let (report, asked) = prompted(
        dir.path(),
        "threat",
        &[],
        vec![Reply::Text(Some("  Served Threat  "))],
        true,
    );
    assert_eq!(asked, ["text Threat name [] Some(\"a name\")"]);
    assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome);
    assert!(written(&report, dir.path()).contains("name: Served Threat"));
}

/// A rule without `--platform` asks which enabled platforms get a block;
/// the blocks are the ones picked, and none when none is.
#[test]
fn a_rule_asks_for_its_platform_blocks() {
    let dir = prompted_workspace();
    let (report, asked) = prompted(
        dir.path(),
        "rule",
        &[],
        vec![Reply::Text(Some("Watch")), Reply::Checkbox(Some(vec![1]))],
        true,
    );
    assert_eq!(asked[0], "text Rule name [] Some(\"a name\")");
    assert_eq!(
        asked[1],
        "checkbox Platform blocks [\"Microsoft Sentinel\", \"Splunk Enterprise Security\"] [] required=false"
    );
    assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome);
    let text = written(&report, dir.path());
    assert!(text.contains("  splunk:"), "{text}");
    assert!(!text.contains("  sentinel:"), "{text}");
    // `--platform` given: nothing asked.
    let (_, asked) = prompted(
        dir.path(),
        "rule",
        &["sentinel"],
        vec![Reply::Text(Some("Other"))],
        true,
    );
    assert_eq!(asked, ["text Rule name [] Some(\"a name\")"]);
}

/// The name question refuses an empty answer (`required`); one that gets
/// through anyway is an invalid name, not a missing one (#1670); Ctrl-C
/// stops the run; and nobody is asked anything away from a terminal.
#[test]
fn an_unanswered_question_stops_the_run() {
    let dir = prompted_workspace();
    let (report, _) = prompted(
        dir.path(),
        "objective",
        &[],
        vec![Reply::Text(Some("  "))],
        true,
    );
    let failure = report.outcome.failure.unwrap();
    assert_eq!(failure.code, code::USAGE_INVALID_VALUE);
    assert_eq!(failure.message, "The name cannot be empty");
    assert_eq!(failure.argument.as_deref(), Some("--name"));
    let (report, _) = prompted(dir.path(), "threat", &[], vec![Reply::CtrlC], true);
    assert_eq!(report.outcome.exit_code, 130);
    let (report, _) = prompted(
        dir.path(),
        "rule",
        &[],
        vec![Reply::Text(Some("Watch")), Reply::CtrlC],
        true,
    );
    assert_eq!(report.outcome.exit_code, 130);
    assert!(
        !dir.path().join("objects/rules").exists()
            || std::fs::read_dir(dir.path().join("objects/rules"))
                .unwrap()
                .next()
                .is_none(),
        "nothing is written"
    );
    let (report, asked) = prompted(dir.path(), "threat", &[], Vec::new(), false);
    assert!(asked.is_empty());
    assert_eq!(report.outcome.failure.unwrap().code, USAGE_NEEDS_INPUT);
}

/// A rule with a block for every platform loads as YAML: the pre-RC smoke run found `--platform google_secops` writing a
/// file `validate` could not parse (#1617).
#[test]
fn a_rule_with_every_platform_block_is_valid() {
    let dir = prompted_workspace();
    let every: Vec<&str> = opentide_schema::platforms::PLATFORMS
        .iter()
        .map(|platform| platform.id)
        .collect();
    let (report, _) = prompted(
        dir.path(),
        "rule",
        &every,
        vec![Reply::Text(Some("Every Platform"))],
        true,
    );
    assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome);
    let text = written(&report, dir.path());
    for platform in &every {
        assert!(
            text.contains(&format!("\n  {platform}:\n")),
            "{platform}: {text}"
        );
    }
    let document = opentide_schema::node::load(&text);
    assert!(document.is_ok(), "{text}");
}
