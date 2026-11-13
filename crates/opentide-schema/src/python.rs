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
//! The binding (`bindings/python/`, `opentide._native`) exports [`models`] as its
//! submodule `opentide._native.models`; the stubs are generated from it
//! (`cargo xtask stubs`).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyModule, PyString, PyTuple, PyType};
use serde::Serialize;

use crate::error::{ErrorKind, PathSegment, SchemaError};
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
        value.setattr(
            "error_count",
            functools.call_method1("partial", (py.import("builtins")?.getattr("len")?, &list))?,
        )?;
        value.setattr("title", title)?;
        Ok(error)
    };
    build().unwrap_or_else(|error| error)
}

/// [`ValidationError`]'s class, as `opentide._native.models` exports it.
///
/// PyO3's introspection cannot describe a `create_exception!` type (and
/// abi3 below Python 3.12 cannot subclass an exception with a `#[pyclass]`),
/// so the module exports the class through this value, whose type hint
/// (`type[ValueError]`) declares it in the generated stub: the stub stays
/// complete, without a module `__getattr__` that would type every unknown
/// name. `errors()`, `error_count()` and `title` are attributes of each
/// instance (see [`raise`]).
#[doc(hidden)]
pub struct ValidationErrorClass;

impl<'py> IntoPyObject<'py> for ValidationErrorClass {
    type Target = PyType;
    type Output = Bound<'py, PyType>;
    type Error = std::convert::Infallible;

    #[cfg(feature = "stubs")]
    const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = pyo3::type_hint_subscript!(
        pyo3::type_hint_identifier!("builtins", "type"),
        pyo3::type_hint_identifier!("builtins", "ValueError")
    );

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(py.get_type::<ValidationError>())
    }
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

/// Reads a Python value as a node tree, and records each value it cannot
/// read as a [`SchemaError`] at its location: an `int` outside 64 bits, a
/// `str` that is not UTF-8, a type a Tide document cannot hold, a value nested
/// deeper than [`MAX_DEPTH`]. Such a value reads as `null`, so the conversion
/// still reports every other error; [`validate`] then replaces what it says
/// at that location with the recorded error. Pydantic raises its
/// `ValidationError` for these values too, never an `OverflowError` or a
/// `TypeError`.
#[derive(Default)]
struct Reader {
    path: Vec<PathSegment>,
    unreadable: Vec<SchemaError>,
}

impl Reader {
    /// A Python value as a node: `None`, `bool`, `int` (64 bits), `float`,
    /// `str`, a `date`, `datetime` or `time`, a sequence (`list`, `tuple`), a
    /// mapping (`dict`), or a model (its `model_dump(by_alias=True,
    /// exclude_none=True)`: a Pydantic model too).
    fn read(&mut self, value: &Bound<'_, PyAny>, depth: usize) -> PyResult<Arc<Node>> {
        // The recursion keeps its frame small (the conversions of a leaf are
        // functions of their own), so the deepest value it reads fits a
        // thread's stack in a debug build too.
        if depth > MAX_DEPTH {
            self.refuse(too_deep());
            return Ok(at(Value::Null));
        }
        if let Ok(dict) = value.cast::<PyDict>() {
            let mut entries = Vec::with_capacity(dict.len());
            for (key, item) in dict.iter() {
                let refused = self.unreadable.len();
                let key = self.read(&key, depth + 1)?;
                let segment = PathSegment::Key(segment(&key));
                // A key that cannot be read is refused where the conversion
                // reports the entry it reads as `None`.
                for error in &mut self.unreadable[refused..] {
                    error.path.insert(self.path.len(), segment.clone());
                }
                self.path.push(segment);
                let item = self.read(&item, depth + 1);
                self.path.pop();
                entries.push(Entry { key, value: item? });
            }
            return Ok(at(Value::Map(entries)));
        }
        if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
            let mut items = Vec::new();
            for (index, item) in value.try_iter()?.enumerate() {
                self.path.push(PathSegment::Index(index));
                let item = item.and_then(|item| self.read(&item, depth + 1));
                self.path.pop();
                items.push(item?);
            }
            return Ok(at(Value::Seq(items)));
        }
        match leaf(value)? {
            Leaf::Value(value) => Ok(at(value)),
            Leaf::Model(dumped) => self.read(&dumped, depth + 1),
            Leaf::Unreadable(error) => {
                self.refuse(error);
                Ok(at(Value::Null))
            }
        }
    }

    /// Records `error` at the current location.
    fn refuse(&mut self, (kind, message): (ErrorKind, String)) {
        self.unreadable
            .push(SchemaError::new(kind, self.path.clone(), message));
    }

    /// The conversion's `errors` with the recorded ones: what the conversion
    /// says at a location it read as `null` (which holds nothing, so nothing
    /// under it has an error) gives way to the recorded error there.
    fn merge(self, mut errors: Vec<SchemaError>) -> Vec<SchemaError> {
        if self.unreadable.is_empty() {
            return errors;
        }
        errors.retain(|error| {
            !self
                .unreadable
                .iter()
                .any(|refused| refused.path == error.path)
        });
        errors.extend(self.unreadable);
        errors
    }
}

/// A mapping key as a location segment, as the conversion names it: a
/// string key's text, else the value's text (`null` for `None`).
fn segment(key: &Node) -> String {
    key.value
        .as_str()
        .map_or_else(|| key.value.to_string(), str::to_owned)
}

#[inline(never)]
fn too_deep() -> (ErrorKind, String) {
    (
        ErrorKind::InvalidValue("recursion_loop"),
        format!("Input should nest at most {MAX_DEPTH} levels deep"),
    )
}

/// What a value that is not a collection reads as.
enum Leaf<'py> {
    /// A scalar.
    Value(Value),
    /// A model's `model_dump(by_alias=True, exclude_none=True)`.
    Model(Bound<'py, PyAny>),
    /// A value no Tide document holds: the error's kind and message.
    Unreadable((ErrorKind, String)),
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
        return Ok(match value.extract::<i64>() {
            Ok(integer) => Leaf::Value(Value::Int(integer)),
            Err(_) => Leaf::Unreadable((
                ErrorKind::InvalidValue("int_parsing_size"),
                "Input should be an integer from -2**63 to 2**63 - 1".to_owned(),
            )),
        });
    }
    if let Ok(float) = value.cast::<PyFloat>() {
        return Ok(Leaf::Value(Value::Float(float.value())));
    }
    if let Ok(text) = value.cast::<PyString>() {
        return Ok(match text.to_str() {
            Ok(text) => Leaf::Value(Value::Str(text.to_owned())),
            // Pydantic's type and message for a `str` with lone surrogates.
            Err(_) => Leaf::Unreadable((
                ErrorKind::InvalidType("string_unicode"),
                "Input should be a valid string, unable to parse raw data as a unicode string"
                    .to_owned(),
            )),
        });
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
    Ok(Leaf::Unreadable((
        ErrorKind::InvalidType("is_instance_of"),
        format!(
            "Input should be None, a bool, int, float, str, date, time, list, tuple, dict or \
             model, not {}",
            value.get_type().name()?
        ),
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
    let mut reader = Reader::default();
    let node = reader.read(value, 0)?;
    let mut cx = Context::new();
    let model = T::from_node(&node, &mut cx);
    let errors = reader.merge(cx.into_errors());
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

/// `model_dump`'s and `model_dump_json`'s `mode`: `"python"` or `"json"`.
/// The two give the same values: every field already holds what JSON holds
/// (`DetectionRule.file` is a `str`, a date the text the loader writes).
#[doc(hidden)]
pub fn dump_mode(mode: &str) -> PyResult<()> {
    match mode {
        "python" | "json" => Ok(()),
        other => Err(PyValueError::new_err(format!(
            "mode must be 'python' or 'json', not {other:?}"
        ))),
    }
}

/// `model_json_schema`'s arguments: the schema names the fields by their
/// serialised names (`by_alias=True`, Pydantic's default) and describes what
/// validation reads and serialisation writes alike.
#[doc(hidden)]
pub fn json_schema_options(by_alias: bool, mode: &str) -> PyResult<()> {
    if !by_alias {
        return Err(PyValueError::new_err(
            "model_json_schema names the fields by their serialised names only (by_alias=True)",
        ));
    }
    match mode {
        "validation" | "serialization" => Ok(()),
        other => Err(PyValueError::new_err(format!(
            "mode must be 'validation' or 'serialization', not {other:?}"
        ))),
    }
}

/// Warns that `class.name` is a Pydantic method kept for one minor release
/// (ADR 0011): a `DeprecationWarning` naming what replaces it.
#[doc(hidden)]
pub fn deprecated(py: Python<'_>, class: &str, name: &str, instead: &str) -> PyResult<()> {
    let message = std::ffi::CString::new(format!(
        "{class}.{name} is Pydantic's and is deprecated: the Tide models are Rust classes. \
         {instead} It will be removed in a later minor release."
    ))
    .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let category = py.get_type::<pyo3::exceptions::PyDeprecationWarning>();
    PyErr::warn(py, category.as_any(), &message, 1)
}

/// `Model.model_fields`, kept for one minor release (ADR 0011): reading it
/// warns, and gives each field's attribute name mapped to its serialised
/// name, in order (Pydantic's `FieldInfo` has no Rust equivalent; the
/// field metadata is in `model_json_schema()`).
#[pyclass(frozen, module = "opentide._native.models")]
pub struct DeprecatedModelFields {
    class: &'static str,
    fields: &'static [(&'static str, &'static str)],
}

impl DeprecatedModelFields {
    #[doc(hidden)]
    pub const fn new(class: &'static str, fields: &'static [(&'static str, &'static str)]) -> Self {
        Self { class, fields }
    }
}

#[pymethods]
impl DeprecatedModelFields {
    /// The fields, attribute name to serialised name, with a
    /// `DeprecationWarning`.
    fn __get__<'py>(
        &self,
        py: Python<'py>,
        instance: &Bound<'py, PyAny>,
        owner: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let _ = (instance, owner);
        deprecated(
            py,
            self.class,
            "model_fields",
            "Read `__tide_fields__` (attribute and serialised names) or `model_json_schema()`.",
        )?;
        let fields = PyDict::new(py);
        for (attribute, serialised) in self.fields {
            fields.set_item(*attribute, *serialised)?;
        }
        Ok(fields)
    }
}

/// The methods of every model class. `Type [identifier]` also gives the
/// class `__schema_identifier__` and `schema_identifier()`; `(schema =
/// field: type)` gives it `schema`, the serialised name of `field`, as a
/// read-only attribute (every class whose serialised and attribute names
/// differ has one: `test_native_models.py` checks it).
macro_rules! py_models {
    ($($ty:ident $([$identifier:expr])? $((schema = $field:ident: $field_ty:ty))? $(with $rule:ident)?),+ $(,)?) => {$(
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

            /// Deprecated (Pydantic's): each field's attribute name mapped to
            /// its serialised name, with a `DeprecationWarning`.
            #[classattr]
            fn model_fields() -> $crate::python::DeprecatedModelFields {
                $crate::python::DeprecatedModelFields::new(
                    <Self as $crate::from_node::Model>::CLASS,
                    <Self as $crate::from_node::Model>::FIELDS,
                )
            }

            /// Deprecated (Pydantic's): `model_validate(values)`, with a
            /// `DeprecationWarning`. Unlike Pydantic's, the values are
            /// validated: a Rust model never holds an unchecked value.
            #[classmethod]
            #[pyo3(signature = (_fields_set = None, **values))]
            fn model_construct(
                class: &::pyo3::Bound<'_, ::pyo3::types::PyType>,
                _fields_set: Option<&::pyo3::Bound<'_, ::pyo3::PyAny>>,
                values: Option<&::pyo3::Bound<'_, ::pyo3::types::PyDict>>,
            ) -> ::pyo3::PyResult<Self> {
                let py = class.py();
                $crate::python::deprecated(
                    py,
                    <Self as $crate::from_node::Model>::CLASS,
                    "model_construct",
                    "Call `model_validate(values)`.",
                )?;
                let empty = ::pyo3::types::PyDict::new(py);
                $crate::python::validate::<Self>(class, values.unwrap_or(&empty).as_any())
            }

            /// Deprecated (Pydantic's): does nothing, with a
            /// `DeprecationWarning`; a Rust class is complete when compiled.
            #[classmethod]
            #[pyo3(signature = (**kwargs))]
            fn model_rebuild(
                class: &::pyo3::Bound<'_, ::pyo3::types::PyType>,
                kwargs: Option<&::pyo3::Bound<'_, ::pyo3::types::PyDict>>,
            ) -> ::pyo3::PyResult<Option<bool>> {
                let _ = kwargs;
                $crate::python::deprecated(
                    class.py(),
                    <Self as $crate::from_node::Model>::CLASS,
                    "model_rebuild",
                    "Remove the call: the class is complete.",
                )?;
                Ok(None)
            }

            /// Deprecated (Pydantic's): does nothing, with a
            /// `DeprecationWarning`; a Rust class cannot be subclassed.
            #[pyo3(signature = (context = None))]
            fn model_post_init(
                slf: &::pyo3::Bound<'_, Self>,
                context: Option<&::pyo3::Bound<'_, ::pyo3::PyAny>>,
            ) -> ::pyo3::PyResult<()> {
                let _ = context;
                $crate::python::deprecated(
                    slf.py(),
                    <Self as $crate::from_node::Model>::CLASS,
                    "model_post_init",
                    "Remove the call: there is nothing to initialise.",
                )
            }

            fn __repr__(slf: &::pyo3::Bound<'_, Self>) -> ::pyo3::PyResult<String> {
                $crate::python::repr::<Self>(slf.as_any())
            }

            fn __hash__(&self) -> ::pyo3::PyResult<u64> {
                $crate::python::hash_of(self)
            }

            $(
                /// The serialised name of the schema identifier field,
                /// read-only (`metadata.schema`, `block.schema`).
                #[getter(schema)]
                fn py_schema_alias(&self) -> $field_ty {
                    self.$field.clone()
                }
            )?

            fn __reduce__<'py>(
                slf: &::pyo3::Bound<'py, Self>,
            ) -> ::pyo3::PyResult<(::pyo3::Bound<'py, ::pyo3::PyAny>, (::pyo3::Bound<'py, ::pyo3::types::PyDict>,))> {
                let validate = slf.get_type().getattr("model_validate")?;
                let state = $crate::python::dump::<Self>(slf.as_any(), true, true)?;
                Ok((validate, (state,)))
            }

            /// The fields as a dict: attribute names (`by_alias`: the
            /// serialised ones), nested models as dicts. `mode` is
            /// `"python"` or `"json"`, which give the same values.
            #[pyo3(signature = (*, mode = "python", by_alias = false, exclude_none = false))]
            fn model_dump<'py>(
                slf: &::pyo3::Bound<'py, Self>,
                mode: &str,
                by_alias: bool,
                exclude_none: bool,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::types::PyDict>> {
                $crate::python::dump_mode(mode)?;
                $crate::python::dump::<Self>(slf.as_any(), by_alias, exclude_none)
            }

            /// `model_dump` as JSON text, non-ASCII characters as they are.
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

            /// The model's JSON Schema, the fields under their serialised
            /// names (`by_alias=True` only); `mode` is `"validation"` or
            /// `"serialization"`, which describe the same document.
            #[classmethod]
            #[pyo3(signature = (by_alias = true, mode = "validation"))]
            fn model_json_schema<'py>(
                class: &::pyo3::Bound<'py, ::pyo3::types::PyType>,
                by_alias: bool,
                mode: &str,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::types::PyDict>> {
                $crate::python::json_schema_options(by_alias, mode)?;
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
use crate::objects::platform::bitdefender::{
    BitdefenderActions, BitdefenderConfig, BitdefenderCriterion, BitdefenderDetection,
    BitdefenderProcessScope, BitdefenderTargets, BitdefenderYara, CriterionValue, ProcessAction,
};
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
use crate::objects::platform::google_secops::{
    GoogleSecopsConfig, GoogleSecopsMatch, GoogleSecopsOptions, GoogleSecopsSchedule,
};
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
use crate::objects::platform::splunk::SavedSearchValue;
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
    CriterionValue => type_hint_union!(hint::STR, hint::INT),
    SavedSearchValue => type_hint_union!(hint::STR, hint::INT, hint::FLOAT, hint::BOOL),
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

/// `Literal[True] | BitdefenderProcessScope`: `True`, or the scope's class
/// instance, as Pydantic holds it.
impl<'py> IntoPyObject<'py> for &ProcessAction {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    #[cfg(feature = "stubs")]
    const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = type_hint_union!(
        hint::BOOL,
        <BitdefenderProcessScope as pyo3::PyTypeInfo>::TYPE_HINT
    );

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        match self {
            ProcessAction::On(flag) => Ok(PyBool::new(py, *flag).to_owned().into_any()),
            ProcessAction::Scoped(scope) => Ok(Bound::new(py, scope.clone())?.into_any()),
        }
    }
}

py_models! {
    Organisation,
    ObjectMetadata (schema = schema_id: String),
    RuleMetadata (schema = schema_id: String),
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
    BitdefenderCriterion,
    BitdefenderDetection,
    BitdefenderYara,
    BitdefenderTargets,
    BitdefenderProcessScope,
    BitdefenderActions,
    BitdefenderConfig [<BitdefenderConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
    CarbonBlackConfig [<CarbonBlackConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
    CrowdstrikeDetails,
    CrowdstrikeSchedule,
    CrowdstrikeConfig [<CrowdstrikeConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
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
    DefenderConfig [<DefenderConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
    ElasticConfig [<ElasticConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
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
    HarfangLabConfig [<HarfangLabConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
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
    SentinelConfig [<SentinelConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
    SentinelOneDetails,
    SentinelOneSingleEvent,
    SentinelOneSubQuery,
    SentinelOneCorrelation,
    SentinelOneCondition,
    SentinelOneResponse,
    SentinelOneConfig [<SentinelOneConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
    SplunkRiskObject,
    SplunkThreatObject,
    SplunkConfig [<SplunkConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
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
    SysdigConfig [<SysdigConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
    GoogleSecopsMatch,
    GoogleSecopsOptions,
    GoogleSecopsSchedule,
    GoogleSecopsConfig [<GoogleSecopsConfig as PlatformBlock>::SCHEMA_IDENTIFIER] (schema = platform_schema: Option<String>),
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
    use super::DeprecatedModelFields;

    #[pymodule_export]
    use super::{
        BitdefenderActions, BitdefenderConfig, BitdefenderCriterion, BitdefenderDetection,
        BitdefenderProcessScope, BitdefenderTargets, BitdefenderYara, CarbonBlackConfig,
        CrowdstrikeConfig, CrowdstrikeDetails, CrowdstrikeSchedule, DefenderAlert,
        DefenderAllowBlockAction, DefenderAllowBlockGroupScoping, DefenderConfig,
        DefenderDeviceActions, DefenderExclusion, DefenderFileActions, DefenderGroupScoping,
        DefenderImpactedEntities, DefenderResponseActions, DefenderUserActions, DetectionExample,
        DetectionSignal, ElasticActions, ElasticCardinality, ElasticConfig, ElasticEql,
        ElasticExceptionList, ElasticExceptions, ElasticFilter, ElasticGuide, ElasticIntegration,
        ElasticMachineLearning, ElasticNewTerms, ElasticOverrides, ElasticRequiredField,
        ElasticRisk, ElasticRiskScoreMapping, ElasticScheduling, ElasticSeverity,
        ElasticSeverityMapping, ElasticSuppression, ElasticThreatEntry, ElasticThreatGroup,
        ElasticThreatMatch, ElasticThreshold, ElasticTimeline, ExternalDetector,
        GoogleSecopsConfig, GoogleSecopsMatch, GoogleSecopsOptions, GoogleSecopsSchedule,
        HarfangLabConfig, HarfangLabSigma, HarfangLabSigmaLogSource, HarfangLabSigmaSelection,
        HarfangLabYara, HarfangLabYaraMeta, ObjectMetadata, ObjectReferences, ObjectiveBody,
        ObjectiveComposition, ObjectiveV1_0, Organisation, ResponseProcedure, ResponseSearch,
        RuleConfigurations, RuleMetadata, RuleResponse, RuleV1_0, RuleV1_1, SentinelAlert,
        SentinelAlertGrouping, SentinelConfig, SentinelCustomDetails, SentinelDynamicProperties,
        SentinelEntityMapping, SentinelExclusion, SentinelGrouping, SentinelMappingEntry,
        SentinelOneCondition, SentinelOneConfig, SentinelOneCorrelation, SentinelOneDetails,
        SentinelOneResponse, SentinelOneSingleEvent, SentinelOneSubQuery, SentinelScheduling,
        SentinelTemplate, SentinelTrigger, SignalData, SplunkActions, SplunkConfig, SplunkEmail,
        SplunkEmailInclude, SplunkNotable, SplunkNotableDrilldown, SplunkNotableEvent, SplunkRisk,
        SplunkRiskObject, SplunkSchedule, SplunkScheduling, SplunkThreatObject, SplunkThrottling,
        SplunkTimerange, SplunkTrigger, SysdigConfig, SysdigException, SysdigList, SysdigMacro,
        ThreatActor, ThreatBody, ThreatVectorV1_0,
    };

    /// The error `model_validate` raises: a `ValueError` whose instances
    /// have `errors()` (each error's `type`, `loc`, `msg`, and `input` and
    /// `ctx` when it records them), `error_count()` and `title`.
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const ValidationError: super::ValidationErrorClass = super::ValidationErrorClass;
}
