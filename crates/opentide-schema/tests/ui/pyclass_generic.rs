// `#[pyclass]` accepts no generic parameters (ADR 0001, "Revisions"): a
// revision cannot be `Rule<V>`, so each revision is a concrete struct.
use pyo3::prelude::*;

#[pyclass(frozen, get_all)]
pub struct Rule<V> {
    pub revision: V,
}

fn main() {}
