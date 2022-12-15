//! Defines the Python interface for Findex.

mod py_api;
mod py_structs;

use py_api::InternalFindex;
use py_structs::{IndexedValue, Label, MasterKey};
use pyo3::prelude::*;

#[pymodule]
fn cosmian_findex(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<InternalFindex>()?;
    m.add_class::<Label>()?;
    m.add_class::<MasterKey>()?;
    m.add_class::<IndexedValue>()?;
    Ok(())
}
