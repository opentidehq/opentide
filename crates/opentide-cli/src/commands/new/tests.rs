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
