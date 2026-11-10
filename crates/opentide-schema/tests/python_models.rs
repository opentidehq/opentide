//! The Tide models as Python sees them (UC-1.9, #815; ADR 0011): the
//! `models` module the binding exports as `opentide._native.models`, run in
//! an embedded CPython (see `tests/python.rs` for the interpreter it links).
//! The comparison with the Pydantic models, on every corpus, is the Python
//! suite's (`tests/test_models/test_native_models.py`).
#![cfg(feature = "python")]

use std::ffi::CString;

use opentide_schema::objects::metadata::ObjectMetadata;
use opentide_schema::objects::objective::ObjectiveV1_0;
use opentide_schema::objects::platform::sentinel::SentinelConfig;
use opentide_schema::objects::rule::{RuleV1_0, RuleV1_1};
use opentide_schema::objects::threat::ThreatVectorV1_0;
use opentide_schema::python::{models, register};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

const fn assert_frozen<T: pyo3::PyClass<Frozen = pyo3::pyclass::boolean_struct::True>>() {}

const _: () = {
    assert_frozen::<RuleV1_0>();
    assert_frozen::<RuleV1_1>();
    assert_frozen::<ObjectiveV1_0>();
    assert_frozen::<ThreatVectorV1_0>();
    assert_frozen::<ObjectMetadata>();
    assert_frozen::<SentinelConfig>();
};

fn run(code: &str) {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let module = pyo3::wrap_pymodule!(models)(py).into_bound(py);
        // The packages above it, so that pickling can import the module.
        let modules = py.import("sys")?.getattr("modules")?;
        for parent in ["opentide", "opentide._native"] {
            modules.set_item(parent, PyModule::new(py, parent)?)?;
        }
        register(&module)?;
        let globals = PyDict::new(py);
        globals.set_item("m", &module)?;
        let code = CString::new(code)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        py.run(&code, Some(&globals), None)
    })
    .unwrap_or_else(|error| panic!("{error}"));
}

const RULE: &str = r#"
import datetime
RULE = {
    "name": "Rule",
    "metadata": {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "rule::1.1",
        "version": 1,
        "created": datetime.date(2026, 1, 1),
        "modified": "2026-01-02",
        "tlp": "clear",
        "reviewed": datetime.datetime(2026, 1, 3, 10, 0, tzinfo=datetime.timezone.utc),
    },
    "description": "d",
    "platforms": {"b": {"z": 1, "a": [1.5, None, True]}, "a": {}},
    "configurations": {"sentinel": {"status": "STAGING", "query": "T | take 1",
        "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
        "alert": {"severity": "High"}}},
}
"#;

#[test]
fn the_classes_have_their_pydantic_names_and_identifiers() {
    run(r#"
assert m.__name__ == "opentide._native.models", m.__name__
for name, identifier in (
    ("DetectionRule", "rule::1.0"),
    ("DetectionRule_v1_1", "rule::1.1"),
    ("DetectionObjective", "objective::1.0"),
    ("ThreatVector", "threat::1.0"),
    ("SentinelConfig", "platform::sentinel::1.0"),
    ("SysdigConfig", "platform::sysdig::1.0"),
):
    cls = getattr(m, name)
    assert cls.__name__ == name and cls.__module__ == "opentide._native.models"
    assert cls.__schema_identifier__ == identifier and cls.schema_identifier() == identifier
assert not hasattr(m.ObjectMetadata, "__schema_identifier__")
assert m.ObjectMetadata.__tide_fields__[1] == ("schema_id", "schema")
assert issubclass(m.ValidationError, ValueError)
"#);
}

#[test]
fn a_rule_validates_reads_dumps_and_is_frozen() {
    run(&format!(
        "{RULE}{}",
        r#"
rule = m.DetectionRule_v1_1.model_validate(RULE)
assert type(rule) is m.DetectionRule_v1_1
# Dates as the loader writes them; a UTC offset as Z.
assert rule.metadata.created == "2026-01-01"
assert rule.metadata.reviewed == "2026-01-03T10:00:00Z", rule.metadata.reviewed
# The serialised name reads the attribute.
assert rule.metadata.schema == rule.metadata.schema_id == "rule::1.1"
try:
    rule.metadata.nothing
except AttributeError as error:
    assert "nothing" in str(error)
else:
    raise AssertionError("an unknown attribute was read")
# Free-form mappings keep the document's order, as a dict does.
assert list(rule.platforms) == ["b", "a"] and list(rule.platforms["b"]) == ["z", "a"]
assert rule.platforms["b"]["a"] == [1.5, None, True]
sentinel = rule.configurations.sentinel
assert type(sentinel) is m.SentinelConfig and sentinel.scheduling.frequency == "PT1H"
assert rule.platform_statuses == {"sentinel": "STAGING"}
assert rule.alert_severity == "Informational" and rule.displayed_severity is None
assert rule.platform_configs() == rule.configurations
bare = m.DetectionRule_v1_1.model_validate(dict(RULE, configurations=None, severity="High"))
assert bare.platform_statuses == {} and bare.displayed_severity == "High"
try:
    bare.platform_configs()
except ValueError as error:
    assert str(error) == "Rule 00000000-0000-4000-8000-000000000001 (Rule) has no configurations block"
else:
    raise AssertionError("a rule without configurations gave some")

dumped = rule.model_dump()
assert dumped["metadata"]["schema_id"] == "rule::1.1" and "schema" not in dumped["metadata"]
assert dumped["severity"] is None and dumped["configurations"]["sentinel"]["platform_schema"] is None
by_alias = rule.model_dump(by_alias=True, exclude_none=True)
assert by_alias["metadata"]["schema"] == "rule::1.1" and "severity" not in by_alias
assert "schema" not in by_alias["configurations"]["sentinel"]
assert m.DetectionRule_v1_1.model_validate(by_alias) == rule
assert m.DetectionRule_v1_1.model_validate_json(rule.model_dump_json(by_alias=True)) == rule
assert m.DetectionRule_v1_1.model_validate(rule) is not rule
assert sentinel.schema is None and sentinel.platform_schema is None
assert m.SentinelConfig.model_validate(dict(RULE["configurations"]["sentinel"], schema="platform::sentinel::1.0")).schema == "platform::sentinel::1.0"

for target, name in ((rule, "name"), (rule.metadata, "uuid"), (sentinel, "query")):
    try:
        setattr(target, name, "changed")
    except AttributeError:
        pass
    else:
        raise AssertionError(f"{type(target).__name__}.{name} is writable")
"#
    ));
}

#[test]
fn equality_hashing_repr_pickling_and_copies_go_by_value() {
    run(&format!(
        "{RULE}{}",
        r#"
import copy, pickle
rule = m.DetectionRule_v1_1.model_validate(RULE)
twin = m.DetectionRule_v1_1.model_validate(RULE)
assert twin is not rule and twin == rule and hash(twin) == hash(rule) and len({rule, twin}) == 1
reordered = dict(RULE, platforms={"a": {}, "b": {"a": [1.5, None, True], "z": 1}})
other = m.DetectionRule_v1_1.model_validate(reordered)
assert other == rule and hash(other) == hash(rule)
renamed = rule.model_copy(update={"name": "Other"})
assert renamed.name == "Other" and renamed != rule and rule.name == "Rule"
assert rule.model_copy() == rule and copy.deepcopy(rule) == rule
assert pickle.loads(pickle.dumps(rule)) == rule
assert repr(rule).startswith("DetectionRule_v1_1(name='Rule', metadata=RuleMetadata(uuid='00000000-0000-4000-8000-000000000001', schema_id='rule::1.1', version=1,"), repr(rule)
try:
    rule.model_copy(update={"name": 3})
except m.ValidationError as error:
    assert error.errors() == [{"type": "string_type", "loc": ("name",), "msg": "Input should be a valid string"}]
else:
    raise AssertionError("an invalid copy was made")
schema = m.DetectionRule_v1_1.model_json_schema()
assert "metadata" in schema["properties"] and "name" in schema["required"]
"#
    ));
}

#[test]
fn validation_reports_every_error_as_pydantic_does() {
    run(r#"
try:
    m.DetectionRule.model_validate({"name": 1, "metadata": {"schema": "rule::1.0"}, "extra": 2})
except m.ValidationError as error:
    errors = error.errors()
    assert error.title == "DetectionRule" and error.error_count() == len(errors)
    kinds = [(e["type"], e["loc"]) for e in errors]
    assert ("string_type", ("name",)) in kinds, kinds
    assert ("missing", ("metadata", "uuid")) in kinds, kinds
    assert ("missing", ("description",)) in kinds, kinds
    assert ("extra_forbidden", ("extra",)) in kinds, kinds
    # A fresh list each time: changing one changes nothing.
    errors.clear()
    assert error.errors()
    assert str(error).startswith(f"{error.error_count()} validation errors for DetectionRule\n")
else:
    raise AssertionError("an invalid rule was accepted")
"#);
}

/// The `ValidationError` `model_validate` raised, or a failure.
const FAILS: &str = r#"
def fails(cls, value):
    try:
        cls.model_validate(value)
    except m.ValidationError as error:
        return error
    raise AssertionError(f"{value!r} was accepted")

def errors_at(error, loc):
    return [(e["type"], e["msg"]) for e in error.errors() if e["loc"] == loc]
"#;

#[test]
fn a_value_no_document_holds_is_a_validation_error_at_its_location() {
    run(&format!(
        "{RULE}{FAILS}{}",
        r#"
INT = ("int_parsing_size", "Input should be an integer from -2**63 to 2**63 - 1")
# An int past 64 bits, in a `str` field: the recorded error replaces the
# conversion's, and every other error is still reported.
error = fails(m.DetectionRule_v1_1, dict(RULE, name=2**70, description=None))
assert errors_at(error, ("name",)) == [INT], error.errors()
assert errors_at(error, ("description",)) == [("string_type", "Input should be a valid string")], error.errors()
# In an optional field, which reads the stand-in `None` without an error.
error = fails(m.DetectionRule_v1_1, dict(RULE, severity=-(2**63) - 1))
assert [(e["type"], e["loc"]) for e in error.errors()] == [("int_parsing_size", ("severity",))]
assert error.error_count() == 1
# The bounds themselves are 64-bit integers.
for edge in (2**63 - 1, -(2**63)):
    rule = m.DetectionRule_v1_1.model_validate(dict(RULE, platforms={"x": {"v": edge}}))
    assert rule.platforms == {"x": {"v": edge}}
# A type no document holds, under a key and in a list.
TYPE = "Input should be None, a bool, int, float, str, date, time, list, tuple, dict or model, not "
error = fails(m.DetectionRule_v1_1, dict(RULE, platforms={"x": {"v": [1, object()]}}, name={1, 2}))
assert errors_at(error, ("platforms", "x", "v", 1)) == [("is_instance_of", TYPE + "object")], error.errors()
assert errors_at(error, ("name",)) == [("is_instance_of", TYPE + "set")], error.errors()
# A key no document holds is refused where the conversion names the entry it
# reads as `None` (`null`); the mapping's other errors are still reported.
metadata = {key: value for key, value in RULE["metadata"].items() if key != "uuid"}
error = fails(m.DetectionRule_v1_1, dict(RULE, metadata={**metadata, object(): 1}))
assert [(e["type"], e["loc"]) for e in error.errors()] == [
    ("missing", ("metadata", "uuid")),
    ("is_instance_of", ("metadata", "null")),
], error.errors()
error = fails(m.DetectionRule, object())
assert [(e["type"], e["loc"], e["msg"]) for e in error.errors()] == [("is_instance_of", (), TYPE + "object")]
assert str(error) == "1 validation error for DetectionRule\n<root>\n  " + TYPE + "object [type=is_instance_of]"
# A str with a lone surrogate is not text.
error = fails(m.DetectionRule_v1_1, dict(RULE, name="\ud800"))
assert errors_at(error, ("name",)) == [("string_unicode", "Input should be a valid string, unable to parse raw data as a unicode string")]
# A value nested past the limit (a list that holds itself too).
nested = []
deep = nested
for _ in range(600):
    deep.append([])
    deep = deep[0]
error = fails(m.DetectionRule_v1_1, dict(RULE, platforms={"x": {"v": nested}}))
assert [e["type"] for e in error.errors()] == ["recursion_loop"], error.errors()
assert error.errors()[0]["loc"][:4] == ("platforms", "x", "v", 0)
assert "nest at most" in str(error)
cycle = []
cycle.append(cycle)
error = fails(m.DetectionRule_v1_1, dict(RULE, platforms={"x": {"v": cycle}}))
assert [e["type"] for e in error.errors()] == ["recursion_loop"], error.errors()
"#
    ));
}

#[test]
fn errors_carry_the_input_and_the_context_they_record() {
    run(&format!(
        "{RULE}{FAILS}{}",
        r#"
REVIEWED = "metadata.reviewed must be an ISO 8601 date (YYYY-MM-DD) or datetime"
metadata = dict(RULE["metadata"], reviewed="yesterday")
error = fails(m.DetectionRule_v1_1, dict(RULE, metadata=metadata))
assert error.errors() == [{
    "type": "value_error",
    "loc": ("metadata", "reviewed"),
    "msg": "Value error, " + REVIEWED,
    "input": "yesterday",
    "ctx": {"error": REVIEWED},
}], error.errors()
# Not a string: no input; a model's type error names its class.
error = fails(m.DetectionRule_v1_1, dict(RULE, metadata=3))
[model] = error.errors()
assert model == {
    "type": "model_type",
    "loc": ("metadata",),
    "msg": "Input should be a valid dictionary or instance of RuleMetadata",
    "ctx": {"class_name": "RuleMetadata"},
}, model
"#
    ));
}

#[test]
fn the_message_counts_the_errors_and_names_each_location() {
    run(&format!(
        "{RULE}{FAILS}{}",
        r#"
error = fails(m.DetectionRule_v1_1, dict(RULE, name=3))
assert error.error_count() == 1
assert str(error) == "1 validation error for DetectionRule_v1_1\nname\n  Input should be a valid string [type=string_type]", str(error)
error = fails(m.DetectionRule_v1_1, dict(RULE, name=3, configurations={"sentinel": {"status": 1}}))
lines = str(error).splitlines()
assert lines[0] == f"{error.error_count()} validation errors for DetectionRule_v1_1", lines
assert "configurations.sentinel.status" in lines, lines
error = fails(m.DetectionRule, 42)
assert str(error).splitlines()[:2] == ["1 validation error for DetectionRule", "<root>"], str(error)
"#
    ));
}

#[test]
fn dumps_take_pydantic_modes_and_keep_non_ascii_text() {
    run(&format!(
        "{RULE}{}",
        r#"
import json
rule = m.DetectionRule_v1_1.model_validate(dict(RULE, name="Règle ☃"))
assert rule.model_dump(mode="json", by_alias=True) == rule.model_dump(by_alias=True)
assert rule.model_dump(mode="python") == rule.model_dump()
assert rule.configurations.sentinel.model_dump(mode="json", by_alias=True)["status"] == "STAGING"
try:
    rule.model_dump(mode="yaml")
except ValueError as error:
    assert str(error) == "mode must be 'python' or 'json', not \"yaml\"", error
else:
    raise AssertionError("an unknown mode was accepted")
text = rule.model_dump_json()
assert '"name": "Règle ☃"' in text and "\\u" not in text, text
assert json.loads(text)["name"] == "Règle ☃"
assert rule.model_dump_json(indent=2).startswith('{\n  "name": "Règle ☃",'), rule.model_dump_json(indent=2)

for cls in (m.ThreatVector, m.DetectionRule_v1_1, m.SentinelConfig):
    assert cls.model_json_schema(by_alias=True) == cls.model_json_schema()
    assert cls.model_json_schema(mode="serialization") == cls.model_json_schema()
assert "schema" in m.ObjectMetadata.model_json_schema()["properties"]
for options, message in (
    ({"by_alias": False}, "model_json_schema names the fields by their serialised names only (by_alias=True)"),
    ({"mode": "python"}, "mode must be 'validation' or 'serialization', not \"python\""),
):
    try:
        m.ThreatVector.model_json_schema(**options)
    except ValueError as error:
        assert str(error) == message, error
    else:
        raise AssertionError(f"{options} was accepted")
"#
    ));
}

#[test]
fn a_copy_updates_attributes_only() {
    run(&format!(
        "{RULE}{}",
        r#"
rule = m.DetectionRule_v1_1.model_validate(RULE)
metadata = rule.metadata
assert metadata.model_copy(update={"schema_id": "rule::1.1"}) == metadata
# `schema` is the serialised name, which the conversion would read: an
# update names attributes, and the copy refuses it before validating.
for target, key in ((metadata, "schema"), (rule.configurations.sentinel, "schema"), (rule, "nothing")):
    try:
        target.model_copy(update={key: "rule::1.0"})
    except m.ValidationError as error:
        raise AssertionError(f"{key} reached validation: {error}")
    except ValueError as error:
        assert str(error) == f'{type(target).__name__} has no field "{key}"', error
    else:
        raise AssertionError(f"{key} was copied")
"#
    ));
}
