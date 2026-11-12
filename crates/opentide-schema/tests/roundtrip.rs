//! YAML → struct → YAML, and what each field convention does on the way in
//! (ADR 0001, "Optional versus defaulted", "Closure").

use garde::Validate;
use opentide_schema::Pins;
use opentide_schema::configuration::merge::to_json;
use opentide_schema::node;
use opentide_schema::sample::{Sample, SampleExample, SampleV1_0, SampleV1_1};

const FIXTURE: &str = include_str!("fixtures/sample-1.1.yaml");

/// `yaml` read with the workspace's YAML reader, then into `T` by its serde
/// derive.
fn read<T: serde::de::DeserializeOwned>(yaml: &str) -> Result<T, String> {
    let document = node::load(yaml).map_err(|error| error.to_string())?;
    let root = document.root().ok_or("no document")?;
    serde_json::from_value(to_json(root)).map_err(|error| error.to_string())
}

fn write<T: serde::Serialize>(value: &T) -> Result<String, node::DumpError> {
    node::to_yaml(value)
}

fn minimal() -> String {
    "name: n\nuuid: u\nschema: sample::1.1\ndescription: d\nseverity: Low\n".to_owned()
}

#[test]
fn round_trips_byte_for_byte() {
    assert!(
        !FIXTURE.contains('\r'),
        "the fixture was checked out with CRLF: tests/fixtures/.gitattributes pins LF"
    );
    let sample: Sample = read(FIXTURE).unwrap();
    assert_eq!(sample.examples.as_ref().unwrap().len(), 2);
    assert_eq!(sample.examples.as_ref().unwrap()[1].language, None);
    let written = write(&sample).unwrap();
    assert_eq!(written, FIXTURE);
    let again: Sample = read(&written).unwrap();
    assert_eq!(again, sample);
}

#[test]
fn field_order_is_declaration_order() {
    let sample: Sample = read(FIXTURE).unwrap();
    let written = write(&sample).unwrap();
    let keys: Vec<&str> = written
        .lines()
        .filter(|line| !line.starts_with([' ', '-']))
        .filter_map(|line| line.split_once(':').map(|(key, _)| key))
        .collect();
    assert_eq!(
        keys,
        [
            "name",
            "uuid",
            "schema",
            "description",
            "severity",
            "effort",
            "enabled",
            "examples",
            "tags"
        ]
    );
}

#[test]
fn optional_missing_and_null_read_as_none_and_are_not_written() {
    let missing: Sample = read(&minimal()).unwrap();
    let null: Sample = read(&(minimal() + "effort: null\nexamples: null\n")).unwrap();
    assert_eq!(missing, null);
    assert_eq!(missing.effort, None);
    assert_eq!(missing.examples, None);
    let written = write(&missing).unwrap();
    assert!(!written.contains("effort"), "{written}");
    assert!(!written.contains("examples"), "{written}");
}

#[test]
fn defaulted_missing_reads_as_the_default_which_is_written() {
    let sample: Sample = read(&minimal()).unwrap();
    assert!(sample.enabled);
    assert!(sample.tags.is_empty());
    let written = write(&sample).unwrap();
    assert!(written.contains("enabled: true\n"), "{written}");
    assert!(written.contains("tags: []\n"), "{written}");
}

#[test]
fn required_missing_is_an_error() {
    let yaml = minimal().replace("severity: Low\n", "");
    let error = read::<Sample>(&yaml).unwrap_err();
    assert!(error.contains("missing field `severity`"), "{error}");
}

#[test]
fn unknown_keys_are_rejected_at_every_level() {
    let error = read::<Sample>(&(minimal() + "colour: blue\n")).unwrap_err();
    assert!(error.contains("unknown field `colour`"), "{error}");
    let nested = minimal() + "examples:\n- description: d\n  link: l\n  colour: blue\n";
    let error = read::<Sample>(&nested).unwrap_err();
    assert!(error.contains("unknown field `colour`"), "{error}");
    // `tags` is a 1.1 field: revision 1.0 does not know it.
    let error = read::<SampleV1_0>(&(minimal() + "tags: []\n")).unwrap_err();
    assert!(error.contains("unknown field `tags`"), "{error}");
}

#[test]
fn the_alias_is_read_and_the_serialised_name_written() {
    let yaml = minimal().replace("schema:", "schema_id:");
    let sample: Sample = read(&yaml).unwrap();
    assert_eq!(sample.schema_id, "sample::1.1");
    let written = write(&sample).unwrap();
    assert!(written.contains("\nschema: sample::1.1\n"), "{written}");
    assert!(!written.contains("schema_id"), "{written}");
}

#[test]
fn identifiers_are_kept_as_written() {
    // Not a UUID: the schema keeps it, the workspace's invalid_uuid check
    // reports it, as Pydantic and validate do at the oracle.
    let sample: Sample = read(&minimal().replace("uuid: u", "uuid: 'not-a-uuid'")).unwrap();
    assert_eq!(sample.uuid, "not-a-uuid");
}

#[test]
fn validates_with_the_pins_context() {
    let pins = Pins::new([("alert_severity", "1.0")]);
    let sample: Sample = read(FIXTURE).unwrap();
    sample.validate_with(&pins).unwrap();

    let report = sample.validate_with(&Pins::default()).unwrap_err();
    let paths: Vec<String> = report.iter().map(|(path, _)| path.to_string()).collect();
    assert_eq!(paths, ["severity"]);

    let out_of_range: Sample = read(&(minimal() + "effort: 11\n")).unwrap();
    let report = out_of_range.validate_with(&pins).unwrap_err();
    let paths: Vec<String> = report.iter().map(|(path, _)| path.to_string()).collect();
    assert_eq!(paths, ["effort"]);
}

#[test]
fn migrates_forward_in_memory() {
    let old: SampleV1_0 = read(&minimal().replace("sample::1.1", "sample::1.0")).unwrap();
    let new = SampleV1_1::from(old.clone());
    assert_eq!(new.schema_id, "sample::1.1");
    assert_eq!(new.name, old.name);
    assert!(new.tags.is_empty());
}

#[test]
fn sub_structs_are_shared_by_revisions() {
    let example = SampleExample {
        description: "d".into(),
        link: "l".into(),
        language: None,
    };
    let old = SampleV1_0 {
        name: "n".into(),
        uuid: "u".into(),
        schema_id: "sample::1.0".into(),
        description: "d".into(),
        severity: "Low".into(),
        effort: None,
        enabled: true,
        examples: Some(vec![example.clone()]),
    };
    assert_eq!(SampleV1_1::from(old).examples, Some(vec![example]));
}

#[test]
fn dive_validates_the_sub_structs_with_their_paths() {
    let pins = Pins::new([("alert_severity", "1.0")]);
    let yaml =
        minimal() + "examples:\n- description: ok\n  link: l\n- description: ''\n  link: l\n";
    let sample: Sample = read(&yaml).unwrap();
    let report = sample.validate_with(&pins).unwrap_err();
    let paths: Vec<String> = report.iter().map(|(path, _)| path.to_string()).collect();
    assert_eq!(paths, ["examples[1].description"]);
}

#[test]
fn an_overridden_field_keeps_its_position_in_every_revision() {
    fn keys(yaml: &str) -> Vec<String> {
        yaml.lines()
            .filter(|line| !line.starts_with([' ', '-']))
            .filter_map(|line| line.split_once(':').map(|(key, _)| key.to_owned()))
            .collect()
    }
    let new: Sample = read(FIXTURE).unwrap();
    let old = SampleV1_0 {
        name: new.name.clone(),
        uuid: new.uuid.clone(),
        schema_id: "sample::1.0".into(),
        description: new.description.clone(),
        severity: new.severity.clone(),
        effort: new.effort,
        enabled: new.enabled,
        examples: new.examples.clone(),
    };
    let old_keys = keys(&write(&old).unwrap());
    let new_keys = keys(&write(&new).unwrap());
    assert_eq!(old_keys[4..6], ["severity", "effort"]);
    // 1.1 has the same keys in the same order, then its new field.
    assert_eq!(new_keys[..old_keys.len()], old_keys[..]);
    assert_eq!(new_keys[old_keys.len()..], ["tags"]);

    let required = |schema: serde_json::Value| {
        schema["properties"]["effort"]
            .get("tide.template.required")
            .cloned()
    };
    assert_eq!(
        required(schemars::schema_for!(Sample).to_value()),
        Some(serde_json::Value::Bool(true))
    );
    assert_eq!(required(schemars::schema_for!(SampleV1_0).to_value()), None);
}
