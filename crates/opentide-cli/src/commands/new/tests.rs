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

#[test]
fn the_most_common_organisation_wins_and_ties_go_to_the_first_in_path_order() {
    let dir = tempfile::tempdir().unwrap();
    let org = |uuid: &str, name: &str| {
        format!("metadata:\n  uuid: x\n  organisation:\n    uuid: {uuid}\n    name: {name}\n")
    };
    std::fs::create_dir(dir.path().join("b")).unwrap();
    std::fs::write(dir.path().join("a.yaml"), org("u2", "Two")).unwrap();
    std::fs::write(dir.path().join("b/c.yaml"), org("u1", "One")).unwrap();
    assert_eq!(
        catalogue_organisation(dir.path()),
        Some(("u2".to_owned(), "Two".to_owned()))
    );
    std::fs::write(dir.path().join("b/d.yml"), org("u1", " One ")).unwrap();
    assert_eq!(
        catalogue_organisation(dir.path()),
        Some(("u1".to_owned(), "One".to_owned()))
    );
    std::fs::write(dir.path().join("e.yaml"), "metadata: [1]\n").unwrap();
    assert_eq!(catalogue_uuids(dir.path()), HashSet::from(["x".to_owned()]));
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
    std::fs::write(dir.path().join("objects/__init__.py"), "").unwrap();
    assert!(!is_workspace_root(dir.path()));
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
    let data = Json::Object(report.outcome.data.clone());
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
    assert_eq!(asked, ["text Threat name [] None"]);
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
    assert_eq!(asked[0], "text Rule name [] None");
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
    assert_eq!(asked, ["text Rule name [] None"]);
}

/// An empty answer needs input; Ctrl-C stops the run; and nobody is asked
/// anything away from a terminal.
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
    assert_eq!(failure.code, USAGE_NEEDS_INPUT);
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
