use crate::python::{PythonVersion, state::pthreads_impl};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum RuntimeType {
    Unknown,
    Python {
        is_lib: bool,
        version: PythonVersion,
        pthreads_impl: pthreads_impl,
    },
}

impl Default for RuntimeType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl RuntimeType {
    pub fn is_unknown(&self) -> bool {
        &Self::Unknown == self
    }

    pub fn is_python(&self) -> bool {
        matches!(self, Self::Python { .. })
    }

    pub fn as_python(&self) -> PythonVersion {
        match self {
            RuntimeType::Unknown => unimplemented!(),
            RuntimeType::Python { is_lib: _, version, pthreads_impl: _ } => *version,
        }
    }
}
