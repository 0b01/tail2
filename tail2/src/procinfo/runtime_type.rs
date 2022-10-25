use std::path::PathBuf;

use anyhow::{Result, Context};

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeType {
    Unknown,
    Python {
        is_lib: bool,
        version: String,
    },
}

impl Default for RuntimeType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl RuntimeType {
    pub fn from(path: &PathBuf) -> Result<Self> {
        let base_name = path.file_name()
            .context("Unable to get entry file name")?
            .to_str().context("unable to convert OsStr to str")?;
        if base_name.starts_with("python") || base_name.starts_with("libpython") {
            let is_lib = base_name.starts_with("libpython");
            if let Some(version) = base_name.split("python").last() {
                return Ok(Self::Python {
                    is_lib,
                    version: version.to_string(),
                });
            }
        }

        Ok(Self::Unknown)
    }

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
