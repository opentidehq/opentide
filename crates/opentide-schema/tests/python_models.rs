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
try:
    rule.model_copy(update={"nothing": 1})
except ValueError as error:
    assert "nothing" in str(error)
else:
    raise AssertionError("an unknown field was copied")
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
for bad in (object(), {"name": {1, 2}}, {"name": 2**70}):
    try:
        m.DetectionRule.model_validate(bad)
    except (TypeError, OverflowError, m.ValidationError):
        pass
    else:
        raise AssertionError(f"{bad!r} was accepted")
nested = []
deep = nested
for _ in range(600):
    deep.append([])
    deep = deep[0]
try:
    m.DetectionRule.model_validate({"platforms": nested})
except ValueError as error:
    assert "deeper" in str(error), error
else:
    raise AssertionError("a value nested past the limit was read")
"#);
}
