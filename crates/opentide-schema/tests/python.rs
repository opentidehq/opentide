//! The sample as Python sees it: a frozen class with attribute access, imported
//! from a module (ADR 0001, "The derive stack"). The test embeds CPython: it
//! needs a shared libpython of 3.10 or later (`PYO3_PYTHON` names the
//! interpreter whose library is linked; CI uses 3.10, the abi3 floor).
#![cfg(feature = "python")]

use std::ffi::CString;

use opentide_schema::sample::{Sample, SampleExample, SampleV1_0};
use pyo3::prelude::*;
use pyo3::types::PyDict;

const FIXTURE: &str = include_str!("fixtures/sample-1.1.yaml");

/// `yaml` read with the workspace's YAML reader, then into a sample by its
/// serde derive.
fn read(yaml: &str) -> Result<Sample, String> {
    let document = opentide_schema::node::load(yaml).map_err(|error| error.to_string())?;
    let root = document.root().ok_or("no document")?;
    let json = opentide_schema::configuration::merge::to_json(root);
    serde_json::from_value(json).map_err(|error| error.to_string())
}

/// Compiles only for a `frozen` class. `get_all` without `set_all` already
/// makes the attributes read-only in Python, so assertions in Python cannot
/// tell a frozen class from another; this can.
const fn assert_frozen<T: pyo3::PyClass<Frozen = pyo3::pyclass::boolean_struct::True>>() {}

const _: () = {
    assert_frozen::<SampleV1_0>();
    assert_frozen::<Sample>();
    assert_frozen::<SampleExample>();
};

fn run(code: &str, sample: Sample) {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let module = PyModule::new(py, "opentide_schema")?;
        module.add_class::<Sample>()?;
        module.add_class::<SampleV1_0>()?;
        module.add_class::<SampleExample>()?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("opentide_schema", &module)?;
        let globals = PyDict::new(py);
        // `twin` is a second object equal to `sample`, not the same one.
        globals.set_item("twin", Py::new(py, sample.clone())?)?;
        globals.set_item("sample", Py::new(py, sample)?)?;
        let code = CString::new(code)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        py.run(&code, Some(&globals), None)
    })
    .unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn imports_as_a_frozen_class_with_attribute_access() {
    let sample = read(FIXTURE).unwrap();
    run(
        r#"
import dataclasses
from opentide_schema import SampleExample, SampleV1_0, SampleV1_1

assert type(sample) is SampleV1_1, type(sample)
assert SampleV1_1.__module__ == "opentide_schema"
assert sample.name == "Suspicious service creation"
assert sample.schema_id == "sample::1.1"
assert sample.effort == 3 and isinstance(sample.effort, int)
assert sample.enabled is False
assert sample.tags == ["persistence", "windows"]
assert sample.description.endswith("block scalar.\n")

example = sample.examples[1]
assert type(example) is SampleExample
assert example.link == "https://example.org/plain"
assert example.language is None
assert sample.examples[0] == sample.examples[0]
# Hashable by value, as a frozen Pydantic model is.
assert twin is not sample and twin == sample
assert hash(twin) == hash(sample) and len({sample, twin}) == 1
assert len({sample.examples[0], sample.examples[1]}) == 2

for target, name in ((sample, "name"), (sample, "tags"), (example, "language")):
    try:
        setattr(target, name, "changed")
    except AttributeError:
        pass
    else:
        raise AssertionError(f"{type(target).__name__}.{name} is writable")
try:
    sample.colour = "blue"
except AttributeError:
    pass
else:
    raise AssertionError("a frozen class took a new attribute")
assert sample.name == "Suspicious service creation"
"#,
        sample,
    );
}

#[test]
fn optional_fields_read_as_none() {
    let yaml = "name: n\nuuid: u\nschema: sample::1.1\ndescription: d\nseverity: Low\n";
    run(
        "assert sample.effort is None and sample.examples is None and sample.enabled is True",
        read(yaml).unwrap(),
    );
}
