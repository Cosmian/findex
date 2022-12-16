use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use pyo3::{prelude::*, pyclass::CompareOp, types::PyBytes};

use crate::{
    core::{
        IndexedValue as IndexedValueRust, KeyingMaterial as KeyingMaterialRust, Keyword,
        Label as LabelRust, Location,
    },
    interfaces::generic_parameters::MASTER_KEY_LENGTH,
};

/// The value indexed by a `Keyword`. It can be either a `Location` or another
/// `Keyword` in case the searched `Keyword` was a tree node.
#[pyclass]
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct IndexedValue(pub(super) IndexedValueRust);

#[pymethods]
impl IndexedValue {
    /// Create `IndexedValue` from a location in bytes.
    ///
    /// Args:
    ///     location_bytes (bytes)
    ///
    /// Returns:
    ///     IndexedValue
    #[staticmethod]
    pub fn from_location(location_bytes: &[u8]) -> Self {
        Self(IndexedValueRust::Location(Location::from(location_bytes)))
    }

    /// Create `IndexedValue` from a keyword in bytes.
    ///
    /// Args:
    /// keyword_bytes (bytes)
    ///
    /// Returns:
    ///     IndexedValue
    #[staticmethod]
    pub fn from_keyword(keyword_bytes: &[u8]) -> Self {
        Self(IndexedValueRust::NextKeyword(Keyword::from(keyword_bytes)))
    }

    /// Checks whether the `IndexedValue` is a location.
    ///
    /// Returns:
    ///     bool
    pub fn is_location(&self) -> bool {
        self.0.is_location()
    }

    /// Checks whether the `IndexedValue` is a keyword.
    ///
    /// Returns:
    ///     bool
    pub fn is_keyword(&self) -> bool {
        self.0.is_keyword()
    }

    /// Returns the underlying location if the `IndexedValue` is one.
    ///
    /// Returns:
    ///     Optional[bytes]
    pub fn get_location(&self, py: Python) -> PyObject {
        self.0
            .get_location()
            .map(|location| PyBytes::new(py, location))
            .into_py(py)
    }

    /// Returns the underlying keyword if the `IndexedValue` is one.
    ///
    /// Returns:
    ///     Optional[bytes]
    pub fn get_keyword(&self, py: Python) -> PyObject {
        self.0
            .get_keyword()
            .map(|keyword| PyBytes::new(py, keyword))
            .into_py(py)
    }

    /// Converts to string.
    /// See <https://pyo3.rs/v0.17.3/class/protocols.html#basic-object-customization>
    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }

    /// Makes the object hashable in Python.
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }

    /// Implements comparison.
    fn __richcmp__(&self, other: Self, op: pyo3::basic::CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.0 == other.0),
            CompareOp::Ne => Ok(self.0 != other.0),
            _ => Err(pyo3::exceptions::PyNotImplementedError::new_err(
                "Comparison operator not available for IndexedValues",
            )),
        }
    }
}

/// Additional data used to encrypt the entry table.
#[pyclass]
pub struct Label(pub(super) LabelRust);

#[pymethods]
impl Label {
    /// Initialize a random label.
    ///
    /// Returns:
    ///     Label
    #[staticmethod]
    pub fn random() -> Self {
        let mut rng = CsRng::from_entropy();
        Self(LabelRust::random(&mut rng))
    }

    /// Load from bytes.
    ///
    /// Args:
    ///     label_bytes (bytes)
    ///
    /// Returns:
    ///     Label
    #[staticmethod]
    pub fn from_bytes(label_bytes: Vec<u8>) -> Self {
        Self(LabelRust::from(label_bytes))
    }

    /// Convert to bytes.
    ///
    /// Returns:
    ///     bytes
    pub fn to_bytes(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.0).into()
    }
}

/// Input key used to derive Findex keys.
#[pyclass]
pub struct MasterKey(pub(super) KeyingMaterialRust<MASTER_KEY_LENGTH>);

#[pymethods]
impl MasterKey {
    /// Initialize a random key.
    ///
    /// Returns:
    ///     MasterKey
    #[staticmethod]
    pub fn random() -> Self {
        let mut rng = CsRng::from_entropy();
        Self(KeyingMaterialRust::new(&mut rng))
    }

    /// Load from bytes.
    ///
    /// Args:
    ///     key_bytes (bytes)
    ///
    /// Returns:
    ///     MasterKey
    #[staticmethod]
    pub fn from_bytes(key_bytes: [u8; MASTER_KEY_LENGTH]) -> Self {
        Self(KeyingMaterialRust::from(key_bytes))
    }

    /// Convert to bytes.
    ///
    /// Returns:
    ///     bytes
    pub fn to_bytes(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.0).into()
    }
}
