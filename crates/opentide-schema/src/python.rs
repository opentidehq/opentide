//! The Python classes (UC-1.9, #815; ADR 0011): every object model and
//! platform block as a frozen `#[pyclass]` under its Pydantic name, with the
//! Pydantic methods SDK users call (`model_dump`, `model_dump_json`,
//! `model_validate`, `model_validate_json`, `model_copy`,
//! `model_json_schema`), value equality and hashing, a Pydantic-style
//! `__repr__`, pickling, and the serialised names as read-only aliases
//! (`metadata.schema`).
//!
//! Validation is the structural conversion ([`crate::from_node`]): a Python
//! value becomes a [`Node`] tree and the model is built from it, so
//! `model_validate` reports every error with Pydantic's type, location and
//! message, raised as [`ValidationError`] (a `ValueError`, as Pydantic's is).
//!
//! The binding (`analysis/`, `opentide._native`) exports [`models`] as its
//! submodule `opentide._native.models`; the stubs are generated from it
//! (`cargo xtask stubs`).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::exceptions::{PyAttributeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyModule, PyString, PyTuple, PyType};
use serde::Serialize;

use crate::error::{PathSegment, SchemaError};
use crate::from_node::{Context, FromNode, Model};
use crate::node::{Entry, MAX_DEPTH, Mark, Node, Value};
use crate::objects::any::Any;

/// The module the classes say they belong to (`__module__`), which pickling
/// imports them from.
pub const MODULE: &str = "opentide._native.models";

pyo3::create_exception!(
    opentide._native.models,
    ValidationError,
    PyValueError,
    "A model's input does not fit it. `errors()` lists every error as Pydantic's \
     `ValidationError.errors()` does (`type`, `loc`, `msg`, and `input` and `ctx` when the error \
     has them), `error_count()` counts them and `title` names the class."
);

fn error_dict<'py>(py: Python<'py>, error: &SchemaError) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("type", error.kind.pydantic_type().unwrap_or("value_error"))?;
    let mut location = Vec::with_capacity(error.path.len());
    for segment in &error.path {
        location.push(match segment {
            PathSegment::Key(key) => key.into_pyobject(py)?.into_any(),
            PathSegment::Index(index) => index.into_pyobject(py)?.into_any(),
        });
    }
    dict.set_item("loc", PyTuple::new(py, location)?)?;
    dict.set_item("msg", &error.message)?;
    if let Some(input) = &error.input {
        dict.set_item("input", input)?;
    }
    if !error.context.is_empty() {
        let context = PyDict::new(py);
        for (key, value) in &error.context {
            context.set_item(key, value)?;
        }
        dict.set_item("ctx", context)?;
    }
    Ok(dict)
}

/// Pydantic's message: the count and the class, then each error's location
/// and message with its type.
fn message(title: &str, errors: &[SchemaError]) -> String {
    let count = errors.len();
    let mut text = format!(
        "{count} validation error{} for {title}",
        if count == 1 { "" } else { "s" }
    );
    for error in errors {
        let location = if error.path.is_empty() {
            "<root>".to_owned()
        } else {
            error.field_path().join(".")
        };
        let kind = error.kind.pydantic_type().unwrap_or("value_error");
        text.push_str(&format!("\n{location}\n  {} [type={kind}]", error.message));
    }
    text
}

/// The [`ValidationError`] for `errors`, with `errors()`, `error_count()`
/// and `title` (abi3 cannot subclass an exception with a Rust class, so they
/// are attributes of the instance).
fn raise(py: Python<'_>, title: &str, errors: &[SchemaError]) -> PyErr {
    let build = || -> PyResult<PyErr> {
        let list = PyList::empty(py);
        for error in errors {
            list.append(error_dict(py, error)?)?;
        }
        let error = ValidationError::new_err(message(title, errors));
        let value = error.value(py);
        let functools = py.import("functools")?;
        let deepcopy = py.import("copy")?.getattr("deepcopy")?;
        value.setattr(
            "errors",
            functools.call_method1("partial", (deepcopy, &list))?,
        )?;
        let count = errors.len();
        value.setattr(
            "error_count",
            functools.call_method1("partial", (py.import("builtins")?.getattr("len")?, &list))?,
        )?;
        let _ = count;
        value.setattr("title", title)?;
        Ok(error)
    };
    build().unwrap_or_else(|error| error)
}

// ---------------------------------------------------------------------------
// Values: serde data and nodes to Python, Python to nodes.
// ---------------------------------------------------------------------------

/// A JSON value as the Python value `json.loads` would give.
fn json_to_py<'py>(py: Python<'py>, value: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        serde_json::Value::Null => py.None().into_bound(py),
        serde_json::Value::Bool(flag) => PyBool::new(py, *flag).to_owned().into_any(),
        serde_json::Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                integer.into_pyobject(py)?.into_any()
            } else if let Some(integer) = number.as_u64() {
                integer.into_pyobject(py)?.into_any()
            } else {
                number
                    .as_f64()
                    .unwrap_or(f64::NAN)
                    .into_pyobject(py)?
                    .into_any()
            }
        }
        serde_json::Value::String(text) => PyString::new(py, text).into_any(),
        serde_json::Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(json_to_py(py, item)?)?;
            }
            list.into_any()
        }
        serde_json::Value::Object(entries) => {
            let dict = PyDict::new(py);
            for (key, item) in entries {
                dict.set_item(key, json_to_py(py, item)?)?;
            }
            dict.into_any()
        }
    })
}

/// A serde value as a Python value, through its JSON form.
fn serde_to_py<'py, T: Serialize + ?Sized>(
    py: Python<'py>,
    value: &T,
) -> PyResult<Bound<'py, PyAny>> {
    let json =
        serde_json::to_value(value).map_err(|error| PyValueError::new_err(error.to_string()))?;
    json_to_py(py, &json)
}

/// A node as the Python value the YAML loader gives: `None`, `bool`, `int`,
/// `float`, `str`, `list` or `dict` (in the document's order).
fn node_to_py<'py>(py: Python<'py>, node: &Node) -> PyResult<Bound<'py, PyAny>> {
    Ok(match &node.value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(flag) => PyBool::new(py, *flag).to_owned().into_any(),
        Value::Int(integer) => integer.into_pyobject(py)?.into_any(),
        Value::Float(float) => PyFloat::new(py, *float).into_any(),
        Value::Str(text) | Value::Datetime(text) => PyString::new(py, text).into_any(),
        Value::Seq(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(node_to_py(py, item)?)?;
            }
            list.into_any()
        }
        Value::Map(entries) => {
            let dict = PyDict::new(py);
            for entry in entries {
                dict.set_item(node_to_py(py, &entry.key)?, node_to_py(py, &entry.value)?)?;
            }
            dict.into_any()
        }
    })
}

fn at(value: Value) -> Arc<Node> {
    Arc::new(Node {
        value,
        start: Mark::default(),
        end: Mark::default(),
    })
}

/// A Python value as a node: `None`, `bool`, `int` (64 bits), `float`,
/// `str`, a sequence (`list`, `tuple`), a mapping (`dict`), or a model (its
/// `model_dump(by_alias=True, exclude_none=True)`: a Pydantic model too).
/// Anything else is a `TypeError`.
fn py_to_node(value: &Bound<'_, PyAny>, depth: usize) -> PyResult<Arc<Node>> {
    // The recursion keeps its frame small (the conversions of a leaf are
    // functions of their own), so the deepest value it reads fits a thread's
    // stack in a debug build too.
    if depth > MAX_DEPTH {
        return Err(too_deep());
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut entries = Vec::with_capacity(dict.len());
        for (key, item) in dict.iter() {
            entries.push(Entry {
                key: py_to_node(&key, depth + 1)?,
                value: py_to_node(&item, depth + 1)?,
            });
        }
        return Ok(at(Value::Map(entries)));
    }
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        let mut items = Vec::new();
        for item in value.try_iter()? {
            items.push(py_to_node(&item?, depth + 1)?);
        }
        return Ok(at(Value::Seq(items)));
    }
    match leaf(value)? {
        Leaf::Value(value) => Ok(at(value)),
        Leaf::Model(dumped) => py_to_node(&dumped, depth + 1),
    }
}

#[inline(never)]
fn too_deep() -> PyErr {
    PyValueError::new_err(format!("the value nests deeper than {MAX_DEPTH} levels"))
}

/// What a value that is not a collection reads as.
enum Leaf<'py> {
    /// A scalar.
    Value(Value),
    /// A model's `model_dump(by_alias=True, exclude_none=True)`.
    Model(Bound<'py, PyAny>),
}

#[inline(never)]
fn leaf<'py>(value: &Bound<'py, PyAny>) -> PyResult<Leaf<'py>> {
    if value.is_none() {
        return Ok(Leaf::Value(Value::Null));
    }
    if let Ok(flag) = value.cast::<PyBool>() {
        return Ok(Leaf::Value(Value::Bool(flag.is_true())));
    }
    if value.is_instance_of::<PyInt>() {
        let integer: i64 = value.extract()?;
        return Ok(Leaf::Value(Value::Int(integer)));
    }
    if let Ok(float) = value.cast::<PyFloat>() {
        return Ok(Leaf::Value(Value::Float(float.value())));
    }
    if let Ok(text) = value.cast::<PyString>() {
        return Ok(Leaf::Value(Value::Str(text.to_str()?.to_owned())));
    }
    if let Some(text) = temporal(value)? {
        return Ok(Leaf::Value(Value::Str(text)));
    }
    if value.hasattr("model_dump")? {
        let options = PyDict::new(value.py());
        options.set_item("by_alias", true)?;
        options.set_item("exclude_none", true)?;
        return Ok(Leaf::Model(value.call_method(
            "model_dump",
            (),
            Some(&options),
        )?));
    }
    Err(PyTypeError::new_err(format!(
        "cannot read a value of type {} into a Tide model",
        value.get_type().name()?
    )))
}

/// A `datetime`, `date` or `time` as the loader writes it
/// (`core.io.stringify_yaml_temporals`): ISO 8601, a UTC offset as `Z`.
fn temporal(value: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
    let datetime = value.py().import("datetime")?;
    let is = |name: &str| -> PyResult<bool> { value.is_instance(&datetime.getattr(name)?) };
    if !(is("date")? || is("time")?) {
        return Ok(None);
    }
    let text: String = value.call_method0("isoformat")?.extract()?;
    if is("datetime")?
        && let Some(utc) = text.strip_suffix("+00:00")
    {
        return Ok(Some(format!("{utc}Z")));
    }
    Ok(Some(text))
}

impl<'py> IntoPyObject<'py> for &Any {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    #[cfg(feature = "stubs")]
    const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = pyo3::type_hint_identifier!("typing", "Any");

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        node_to_py(py, self.node())
    }
}

/// `IntoPyObject` for a field type that is not a class (a literal enum, a
/// union), through its serde form: the value Pydantic's model holds, a `str`,
/// `int`, `bool` or `list` of them.
macro_rules! py_value {
    ($($ty:ty => $hint:expr),+ $(,)?) => {$(
        impl<'py> ::pyo3::IntoPyObject<'py> for &$ty {
            type Target = ::pyo3::PyAny;
            type Output = ::pyo3::Bound<'py, ::pyo3::PyAny>;
            type Error = ::pyo3::PyErr;

            #[cfg(feature = "stubs")]
            const OUTPUT_TYPE: ::pyo3::inspect::PyStaticExpr = $hint;

            fn into_pyobject(self, py: ::pyo3::Python<'py>) -> ::pyo3::PyResult<Self::Output> {
                $crate::python::serde_value(py, self)
            }
        }
    )+};
}

pub(crate) use py_value;

/// [`py_value`]'s conversion.
#[doc(hidden)]
pub fn serde_value<'py, T: Serialize>(py: Python<'py>, value: &T) -> PyResult<Bound<'py, PyAny>> {
    serde_to_py(py, value)
}

// ---------------------------------------------------------------------------
// What every class's methods call.
// ---------------------------------------------------------------------------

/// `model_dump`: every field by attribute name (by serialised name with
/// `by_alias`), nested models dumped, `None` kept unless `exclude_none`.
#[doc(hidden)]
pub fn dump<'py, T: Model>(
    this: &Bound<'py, PyAny>,
    by_alias: bool,
    exclude_none: bool,
) -> PyResult<Bound<'py, PyDict>> {
    let py = this.py();
    let dict = PyDict::new(py);
    for (attribute, serialised) in T::FIELDS {
        let value = this.getattr(*attribute)?;
        if exclude_none && value.is_none() {
            continue;
        }
        let key = if by_alias { serialised } else { attribute };
        dict.set_item(*key, dump_value(&value, by_alias, exclude_none)?)?;
    }
    Ok(dict)
}

fn dump_value<'py>(
    value: &Bound<'py, PyAny>,
    by_alias: bool,
    exclude_none: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let py = value.py();
    if value.get_type().module()?.to_str()? == MODULE && value.hasattr("model_dump")? {
        let options = PyDict::new(py);
        options.set_item("by_alias", by_alias)?;
        options.set_item("exclude_none", exclude_none)?;
        return value.call_method("model_dump", (), Some(&options));
    }
    if let Ok(list) = value.cast::<PyList>() {
        let out = PyList::empty(py);
        for item in list.iter() {
            out.append(dump_value(&item, by_alias, exclude_none)?)?;
        }
        return Ok(out.into_any());
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let out = PyDict::new(py);
        for (key, item) in dict.iter() {
            out.set_item(key, dump_value(&item, by_alias, exclude_none)?)?;
        }
        return Ok(out.into_any());
    }
    Ok(value.clone())
}

/// `ClassName(field=value, ...)`, each value's `repr`, as Pydantic writes it.
#[doc(hidden)]
pub fn repr<T: Model>(this: &Bound<'_, PyAny>) -> PyResult<String> {
    let mut parts = Vec::with_capacity(T::FIELDS.len());
    for (attribute, _) in T::FIELDS {
        let value = this.getattr(*attribute)?;
        parts.push(format!("{attribute}={}", value.repr()?.to_str()?));
    }
    Ok(format!("{}({})", T::CLASS, parts.join(", ")))
}

/// A hash of the value, consistent with `==`: equal models serialise alike.
#[doc(hidden)]
pub fn hash_of<T: Serialize>(value: &T) -> PyResult<u64> {
    // Through `serde_json::Value`, whose maps sort their keys: two mappings
    // equal in another order (`==` ignores it, as for a `dict`) hash alike.
    let text = serde_json::to_value(value)
        .map_err(|error| PyValueError::new_err(error.to_string()))?
        .to_string();
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    Ok(hasher.finish())
}

/// `model_validate`: an instance of the class as is; anything else read
/// through the structural conversion, every error raised at once.
#[doc(hidden)]
pub fn validate<T>(class: &Bound<'_, PyType>, value: &Bound<'_, PyAny>) -> PyResult<T>
where
    T: FromNode
        + Model
        + Clone
        + Sync
        + pyo3::PyClass<Frozen = pyo3::pyclass::boolean_struct::True>,
{
    if let Ok(same) = value.cast::<T>() {
        return Ok(same.get().clone());
    }
    let node = py_to_node(value, 0)?;
    let mut cx = Context::new();
    let model = T::from_node(&node, &mut cx);
    let errors = cx.into_errors();
    match model {
        Some(model) if errors.is_empty() => Ok(model),
        _ => Err(raise(class.py(), T::CLASS, &errors)),
    }
}

/// `model_copy`: the dump, `update` applied over it, validated again. A
/// copy that does not fit the model raises rather than holding an invalid
/// value (Pydantic does not validate `update`).
#[doc(hidden)]
pub fn copy<T>(this: &Bound<'_, T>, update: Option<&Bound<'_, PyDict>>) -> PyResult<T>
where
    T: FromNode
        + Model
        + Clone
        + Sync
        + pyo3::PyClass<Frozen = pyo3::pyclass::boolean_struct::True>,
{
    let Some(update) = update.filter(|update| !update.is_empty()) else {
        return Ok(this.get().clone());
    };
    let dumped = dump::<T>(this.as_any(), false, true)?;
    for (key, value) in update.iter() {
        let key: String = key.extract()?;
        // An update names attributes; the conversion reads the serialised
        // names, and takes an alias's attribute name too.
        if !T::FIELDS.iter().any(|(attribute, _)| *attribute == key) {
            return Err(PyValueError::new_err(format!(
                "{} has no field {key:?}",
                T::CLASS
            )));
        }
        dumped.set_item(key, value)?;
    }
    validate::<T>(&this.as_any().get_type(), dumped.as_any())
}

/// The model's JSON Schema (schemars, draft 2020-12).
#[doc(hidden)]
pub fn json_schema<T: schemars::JsonSchema>(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let schema = schemars::schema_for!(T);
    Ok(json_to_py(py, schema.as_value())?.cast_into::<PyDict>()?)
}

/// A serialised name that is not the attribute's (`schema` for
/// `schema_id`), read as that attribute.
#[doc(hidden)]
pub fn alias<T: Model>(this: &Bound<'_, PyAny>, name: &str) -> PyResult<Py<PyAny>> {
    match T::FIELDS
        .iter()
        .find(|(attribute, serialised)| *serialised == name && attribute != serialised)
    {
        Some((attribute, _)) => Ok(this.getattr(*attribute)?.unbind()),
        None => Err(PyAttributeError::new_err(format!(
            "'{}' object has no attribute '{name}'",
            T::CLASS
        ))),
    }
}

/// The methods of every model class. `Type = identifier` also gives the
/// class `__schema_identifier__` and `schema_identifier()`.
macro_rules! py_models {
    ($($ty:ident $([$identifier:expr])? $(with $rule:ident)?),+ $(,)?) => {$(
        #[::pyo3::pymethods]
        impl $ty {
            $(
                #[classattr]
                #[pyo3(name = "__schema_identifier__")]
                fn py_schema_identifier_attribute() -> &'static str {
                    $identifier
                }

                /// The canonical schema identifier (`rule::1.0`).
                #[classmethod]
                fn schema_identifier(_class: &::pyo3::Bound<'_, ::pyo3::types::PyType>) -> &'static str {
                    $identifier
                }
            )?

            /// Each field's attribute and serialised name, in order.
            #[classattr]
            fn __tide_fields__() -> &'static [(&'static str, &'static str)] {
                <Self as $crate::from_node::Model>::FIELDS
            }

            fn __repr__(slf: &::pyo3::Bound<'_, Self>) -> ::pyo3::PyResult<String> {
                $crate::python::repr::<Self>(slf.as_any())
            }

            fn __hash__(&self) -> ::pyo3::PyResult<u64> {
                $crate::python::hash_of(self)
            }

            fn __getattr__(slf: &::pyo3::Bound<'_, Self>, name: &str) -> ::pyo3::PyResult<::pyo3::Py<::pyo3::PyAny>> {
                $crate::python::alias::<Self>(slf.as_any(), name)
            }

            fn __reduce__<'py>(
                slf: &::pyo3::Bound<'py, Self>,
            ) -> ::pyo3::PyResult<(::pyo3::Bound<'py, ::pyo3::PyAny>, (::pyo3::Bound<'py, ::pyo3::types::PyDict>,))> {
                let validate = slf.get_type().getattr("model_validate")?;
                let state = $crate::python::dump::<Self>(slf.as_any(), true, true)?;
                Ok((validate, (state,)))
            }

            /// The fields as a dict: attribute names (`by_alias`: the
            /// serialised ones), nested models as dicts.
            #[pyo3(signature = (*, by_alias = false, exclude_none = false))]
            fn model_dump<'py>(
                slf: &::pyo3::Bound<'py, Self>,
                by_alias: bool,
                exclude_none: bool,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::types::PyDict>> {
                $crate::python::dump::<Self>(slf.as_any(), by_alias, exclude_none)
            }

            /// `model_dump` as JSON text.
            #[pyo3(signature = (*, by_alias = false, exclude_none = false, indent = None))]
            fn model_dump_json(
                slf: &::pyo3::Bound<'_, Self>,
                by_alias: bool,
                exclude_none: bool,
                indent: Option<usize>,
            ) -> ::pyo3::PyResult<String> {
                let py = slf.py();
                let dumped = $crate::python::dump::<Self>(slf.as_any(), by_alias, exclude_none)?;
                let options = ::pyo3::types::PyDict::new(py);
                options.set_item("indent", indent)?;
                options.set_item("ensure_ascii", false)?;
                py.import("json")?.call_method("dumps", (dumped,), Some(&options))?.extract()
            }

            /// Builds the model from a dict (or a model), checked; raises
            /// `ValidationError` with every error.
            #[classmethod]
            fn model_validate(
                class: &::pyo3::Bound<'_, ::pyo3::types::PyType>,
                obj: &::pyo3::Bound<'_, ::pyo3::PyAny>,
            ) -> ::pyo3::PyResult<Self> {
                $crate::python::validate::<Self>(class, obj)
            }

            /// `model_validate` of a JSON document.
            #[classmethod]
            fn model_validate_json(
                class: &::pyo3::Bound<'_, ::pyo3::types::PyType>,
                json_data: &str,
            ) -> ::pyo3::PyResult<Self> {
                let value = class.py().import("json")?.call_method1("loads", (json_data,))?;
                $crate::python::validate::<Self>(class, &value)
            }

            /// A copy, with `update`'s fields replaced; the result is
            /// validated. Models are frozen, so `deep` changes nothing.
            #[pyo3(signature = (update = None, *, deep = false))]
            fn model_copy(
                slf: &::pyo3::Bound<'_, Self>,
                update: Option<&::pyo3::Bound<'_, ::pyo3::types::PyDict>>,
                deep: bool,
            ) -> ::pyo3::PyResult<Self> {
                let _ = deep;
                $crate::python::copy::<Self>(slf, update)
            }

            /// The model's JSON Schema.
            #[classmethod]
            fn model_json_schema<'py>(
                class: &::pyo3::Bound<'py, ::pyo3::types::PyType>,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::types::PyDict>> {
                $crate::python::json_schema::<Self>(class.py())
            }

            $(
                /// Each set block's `status`, keyed by platform, in the
                /// container's order: what deploy and promotion use.
                #[getter(platform_statuses)]
                fn py_platform_statuses(&self) -> ::indexmap::IndexMap<&'static str, String> {
                    let _ = stringify!($rule);
                    self.configurations
                        .as_ref()
                        .map(|configurations| {
                            configurations
                                .platform_statuses()
                                .into_iter()
                                .map(|(platform, status)| (platform, status.to_owned()))
                                .collect()
                        })
                        .unwrap_or_default()
                }

                /// The severity a page shows: `response.alert_severity`,
                /// else the authored `severity`.
                #[getter(displayed_severity)]
                fn py_displayed_severity(&self) -> Option<&str> {
                    self.displayed_severity()
                }

                /// `response.alert_severity`, or its default without a
                /// response.
                #[getter(alert_severity)]
                fn py_alert_severity(&self) -> &str {
                    self.alert_severity()
                }

                /// `configurations`, or a `ValueError` naming the rule when
                /// it has none.
                fn platform_configs(&self) -> ::pyo3::PyResult<RuleConfigurations> {
                    self.configurations.clone().ok_or_else(|| {
                        ::pyo3::exceptions::PyValueError::new_err(format!(
                            "Rule {} ({}) has no configurations block",
                            self.metadata.uuid, self.name
                        ))
                    })
                }
            )?
        }
    )+};
}

use crate::objects::metadata::{
    ObjectMetadata, ObjectReferences, Organisation, RuleMetadata, Version,
};
use crate::objects::objective::{
    DetectionExample, DetectionSignal, ExternalDetector, ObjectiveBody, ObjectiveComposition,
    ObjectiveV1_0, SignalData,
};
use crate::objects::platform::PlatformBlock;
use crate::objects::platform::carbon_black::CarbonBlackConfig;
use crate::objects::platform::crowdstrike::{
    CrowdstrikeConfig, CrowdstrikeDetails, CrowdstrikeSchedule,
};
use crate::objects::platform::defender::{
    DefenderAlert, DefenderAllowBlockAction, DefenderAllowBlockGroupScoping, DefenderConfig,
    DefenderDeviceActions, DefenderExclusion, DefenderFileActions, DefenderGroupScoping,
    DefenderImpactedEntities, DefenderResponseActions, DefenderUserActions,
};
use crate::objects::platform::elastic::{
    ElasticActions, ElasticCardinality, ElasticConfig, ElasticEql, ElasticExceptionList,
    ElasticExceptions, ElasticFilter, ElasticGuide, ElasticIntegration, ElasticMachineLearning,
    ElasticNewTerms, ElasticOverrides, ElasticRequiredField, ElasticRisk, ElasticRiskScoreMapping,
    ElasticScheduling, ElasticSeverity, ElasticSeverityMapping, ElasticSuppression,
    ElasticThreatEntry, ElasticThreatGroup, ElasticThreatMatch, ElasticThreshold, ElasticTimeline,
};
use crate::objects::platform::elastic::{IntegrationChoice, JobId, RiskChoice, SeverityChoice};
use crate::objects::platform::harfanglab::SelectionValue;
use crate::objects::platform::harfanglab::{
    HarfangLabConfig, HarfangLabSigma, HarfangLabSigmaLogSource, HarfangLabSigmaSelection,
    HarfangLabYara, HarfangLabYaraMeta,
};
use crate::objects::platform::sentinel::{
    SentinelAlert, SentinelAlertGrouping, SentinelConfig, SentinelCustomDetails,
    SentinelDynamicProperties, SentinelEntityMapping, SentinelExclusion, SentinelGrouping,
    SentinelMappingEntry, SentinelScheduling, SentinelTemplate, SentinelTrigger,
};
use crate::objects::platform::sentinel::{SentinelTechnique, Suppression};
use crate::objects::platform::sentinel_one::TreatAsThreat;
use crate::objects::platform::sentinel_one::{
    SentinelOneCondition, SentinelOneConfig, SentinelOneCorrelation, SentinelOneDetails,
    SentinelOneResponse, SentinelOneSingleEvent, SentinelOneSubQuery,
};
use crate::objects::platform::splunk::{
    SplunkActions, SplunkConfig, SplunkEmail, SplunkEmailInclude, SplunkNotable,
    SplunkNotableDrilldown, SplunkNotableEvent, SplunkRisk, SplunkRiskObject, SplunkSchedule,
    SplunkScheduling, SplunkThreatObject, SplunkThrottling, SplunkTimerange, SplunkTrigger,
};
use crate::objects::platform::sysdig::{ListItem, OneOrMany};
use crate::objects::platform::sysdig::{SysdigConfig, SysdigException, SysdigList, SysdigMacro};
use crate::objects::response::{ResponseProcedure, ResponseSearch, RuleResponse};
use crate::objects::rule::{RuleConfigurations, RuleV1_0, RuleV1_1};
use crate::objects::threat::Killchain;
use crate::objects::threat::{ThreatActor, ThreatBody, ThreatVectorV1_0};

// `type_hint_union!` names itself unqualified when it recurses.
#[cfg(feature = "stubs")]
use pyo3::type_hint_union;

/// `str`, `int`, `bool`, `float` and `list[str]`, for the hints below.
#[cfg(feature = "stubs")]
mod hint {
    use pyo3::inspect::PyStaticExpr;
    use pyo3::{type_hint_identifier, type_hint_subscript};

    pub const STR: PyStaticExpr = type_hint_identifier!("builtins", "str");
    pub const INT: PyStaticExpr = type_hint_identifier!("builtins", "int");
    pub const BOOL: PyStaticExpr = type_hint_identifier!("builtins", "bool");
    pub const FLOAT: PyStaticExpr = type_hint_identifier!("builtins", "float");
    pub const STRS: PyStaticExpr =
        type_hint_subscript!(type_hint_identifier!("builtins", "list"), STR);
}

py_value! {
    Version => type_hint_union!(hint::STR, hint::INT),
    Killchain => type_hint_union!(hint::STR, hint::STRS),
    OneOrMany => type_hint_union!(hint::STR, hint::STRS),
    JobId => type_hint_union!(hint::STR, hint::STRS),
    ListItem => type_hint_union!(hint::STR, hint::INT, hint::FLOAT),
    SelectionValue => type_hint_union!(hint::STR, hint::STRS, hint::BOOL, hint::INT, hint::FLOAT),
    Suppression => type_hint_union!(hint::STR, hint::BOOL),
    SentinelTechnique => hint::STR,
    TreatAsThreat => type_hint_union!(hint::BOOL, hint::STR),
}

/// A union with a model member: the member's class instance, as Pydantic
/// holds it, or the plain value.
macro_rules! py_union {
    ($($ty:ty { $plain:ident, $model:ident } => $hint:expr),+ $(,)?) => {$(
        impl<'py> IntoPyObject<'py> for &$ty {
            type Target = PyAny;
            type Output = Bound<'py, PyAny>;
            type Error = PyErr;

            #[cfg(feature = "stubs")]
            const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = $hint;

            fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
                type Union = $ty;
                match self {
                    Union::$plain(value) => Ok(value.into_pyobject(py)?.into_any()),
                    Union::$model(model) => Ok(Bound::new(py, model.clone())?.into_any()),
                }
            }
        }
    )+};
}

py_union! {
    SeverityChoice { Level, Mapped } => type_hint_union!(hint::STR, <ElasticSeverity as pyo3::PyTypeInfo>::TYPE_HINT),
    RiskChoice { Score, Mapped } => type_hint_union!(hint::INT, <ElasticRisk as pyo3::PyTypeInfo>::TYPE_HINT),
    IntegrationChoice { Package, Detailed } => type_hint_union!(hint::STR, <ElasticIntegration as pyo3::PyTypeInfo>::TYPE_HINT),
}

py_models! {
    Organisation,
    ObjectMetadata,
    RuleMetadata,
    ObjectReferences,
    SignalData,
    ExternalDetector,
    DetectionExample,
    DetectionSignal,
    ObjectiveComposition,
    ObjectiveBody,
    ObjectiveV1_0 [ObjectiveV1_0::SCHEMA_IDENTIFIER],
    ResponseSearch,
    ResponseProcedure,
    RuleResponse,
    RuleConfigurations,
    RuleV1_0 [RuleV1_0::SCHEMA_IDENTIFIER] with rule,
    RuleV1_1 [RuleV1_1::SCHEMA_IDENTIFIER] with rule,
    ThreatActor,
    ThreatBody,
    ThreatVectorV1_0 [ThreatVectorV1_0::SCHEMA_IDENTIFIER],
    CarbonBlackConfig [<CarbonBlackConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    CrowdstrikeDetails,
    CrowdstrikeSchedule,
    CrowdstrikeConfig [<CrowdstrikeConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    DefenderAlert,
    DefenderImpactedEntities,
    DefenderGroupScoping,
    DefenderAllowBlockGroupScoping,
    DefenderAllowBlockAction,
    DefenderFileActions,
    DefenderDeviceActions,
    DefenderUserActions,
    DefenderResponseActions,
    DefenderExclusion,
    DefenderConfig [<DefenderConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    ElasticConfig [<ElasticConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    ElasticSuppression,
    ElasticCardinality,
    ElasticThreshold,
    ElasticRequiredField,
    ElasticIntegration,
    ElasticSeverityMapping,
    ElasticRiskScoreMapping,
    ElasticThreatEntry,
    ElasticThreatGroup,
    ElasticScheduling,
    ElasticSeverity,
    ElasticRisk,
    ElasticOverrides,
    ElasticGuide,
    ElasticExceptionList,
    ElasticExceptions,
    ElasticTimeline,
    ElasticActions,
    ElasticFilter,
    ElasticEql,
    ElasticNewTerms,
    ElasticThreatMatch,
    ElasticMachineLearning,
    HarfangLabSigmaLogSource,
    HarfangLabSigmaSelection,
    HarfangLabSigma,
    HarfangLabYaraMeta,
    HarfangLabYara,
    HarfangLabConfig [<HarfangLabConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    SentinelTemplate,
    SentinelTrigger,
    SentinelScheduling,
    SentinelCustomDetails,
    SentinelDynamicProperties,
    SentinelAlert,
    SentinelAlertGrouping,
    SentinelGrouping,
    SentinelMappingEntry,
    SentinelEntityMapping,
    SentinelExclusion,
    SentinelConfig [<SentinelConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    SentinelOneDetails,
    SentinelOneSingleEvent,
    SentinelOneSubQuery,
    SentinelOneCorrelation,
    SentinelOneCondition,
    SentinelOneResponse,
    SentinelOneConfig [<SentinelOneConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    SplunkRiskObject,
    SplunkThreatObject,
    SplunkConfig [<SplunkConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
    SplunkSchedule,
    SplunkTimerange,
    SplunkScheduling,
    SplunkThrottling,
    SplunkTrigger,
    SplunkNotableEvent,
    SplunkNotableDrilldown,
    SplunkNotable,
    SplunkRisk,
    SplunkEmailInclude,
    SplunkEmail,
    SplunkActions,
    SysdigException,
    SysdigMacro,
    SysdigList,
    SysdigConfig [<SysdigConfig as PlatformBlock>::SCHEMA_IDENTIFIER],
}

/// Names the exported `models` submodule [`MODULE`] and puts it in
/// `sys.modules`, so `import opentide._native.models` and pickling find it.
/// The binding calls it from its module's initialisation.
pub fn register(models: &Bound<'_, PyModule>) -> PyResult<()> {
    models.setattr("__name__", MODULE)?;
    models
        .py()
        .import("sys")?
        .getattr("modules")?
        .set_item(MODULE, models)
}

/// `opentide._native.models`: every class, under its Pydantic name, and
/// [`ValidationError`]. The binding exports it as a submodule.
#[pymodule(submodule)]
pub mod models {
    #[pymodule_export]
    use super::{
        CarbonBlackConfig, CrowdstrikeConfig, CrowdstrikeDetails, CrowdstrikeSchedule,
        DefenderAlert, DefenderAllowBlockAction, DefenderAllowBlockGroupScoping, DefenderConfig,
        DefenderDeviceActions, DefenderExclusion, DefenderFileActions, DefenderGroupScoping,
        DefenderImpactedEntities, DefenderResponseActions, DefenderUserActions, DetectionExample,
        DetectionSignal, ElasticActions, ElasticCardinality, ElasticConfig, ElasticEql,
        ElasticExceptionList, ElasticExceptions, ElasticFilter, ElasticGuide, ElasticIntegration,
        ElasticMachineLearning, ElasticNewTerms, ElasticOverrides, ElasticRequiredField,
        ElasticRisk, ElasticRiskScoreMapping, ElasticScheduling, ElasticSeverity,
        ElasticSeverityMapping, ElasticSuppression, ElasticThreatEntry, ElasticThreatGroup,
        ElasticThreatMatch, ElasticThreshold, ElasticTimeline, ExternalDetector, HarfangLabConfig,
        HarfangLabSigma, HarfangLabSigmaLogSource, HarfangLabSigmaSelection, HarfangLabYara,
        HarfangLabYaraMeta, ObjectMetadata, ObjectReferences, ObjectiveBody, ObjectiveComposition,
        ObjectiveV1_0, Organisation, ResponseProcedure, ResponseSearch, RuleConfigurations,
        RuleMetadata, RuleResponse, RuleV1_0, RuleV1_1, SentinelAlert, SentinelAlertGrouping,
        SentinelConfig, SentinelCustomDetails, SentinelDynamicProperties, SentinelEntityMapping,
        SentinelExclusion, SentinelGrouping, SentinelMappingEntry, SentinelOneCondition,
        SentinelOneConfig, SentinelOneCorrelation, SentinelOneDetails, SentinelOneResponse,
        SentinelOneSingleEvent, SentinelOneSubQuery, SentinelScheduling, SentinelTemplate,
        SentinelTrigger, SignalData, SplunkActions, SplunkConfig, SplunkEmail, SplunkEmailInclude,
        SplunkNotable, SplunkNotableDrilldown, SplunkNotableEvent, SplunkRisk, SplunkRiskObject,
        SplunkSchedule, SplunkScheduling, SplunkThreatObject, SplunkThrottling, SplunkTimerange,
        SplunkTrigger, SysdigConfig, SysdigException, SysdigList, SysdigMacro, ThreatActor,
        ThreatBody, ThreatVectorV1_0, ValidationError,
    };
}
