use self::offsets::*;

pub mod offsets;
pub mod state;

#[repr(C)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct PythonVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
} 

impl PythonVersion {
    pub fn offsets(&self) -> PythonOffsets {
        match &self {
            PythonVersion { major: 2, minor: _, patch: _ } => PY27_OFFSETS,
            PythonVersion { major: 3, minor: 6, patch: _ } => PY36_OFFSETS,
            PythonVersion { major: 3, minor: 7, patch: _ } => PY37_OFFSETS,
            PythonVersion { major: 3, minor: 8, patch: _ } => PY38_OFFSETS,
            PythonVersion { major: 3, minor: 9, patch: _ } => PY38_OFFSETS, // 39 is same as 38
            PythonVersion { major: 3, minor: 10, patch: _ } => PY310_OFFSETS,
            _ => PY310_OFFSETS,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PythonVersion {}
