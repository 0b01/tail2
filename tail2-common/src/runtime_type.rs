#[repr(C)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct PythonVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
} 

#[cfg(feature = "user")]
unsafe impl aya::Pod for PythonVersion {}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum RuntimeType {
    Unknown,
    Python {
        is_lib: bool,
        version: PythonVersion,
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
        match self {
            Self::Python { is_lib: _, version: _ } => true,
            _ => false,
        }
    }
}
