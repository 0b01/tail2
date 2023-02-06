use std::{collections::HashMap, path::Path};
use anyhow::Result;

use serde::{Deserialize, Serialize};

// name = "mydb"
// [tags]
// tag1 = "value1"
// tag2 = "value2"

/// Metadata file for a database with same name
#[derive(Debug, Deserialize, Serialize)]
pub struct Metadata {
    /// Name of the database
    pub name: String,
    /// Tags associated with the database
    pub tags: HashMap<String, String>, 
}

impl Metadata {
    /// given a path, open file
    pub fn open<P: AsRef<Path>>(path: &P) -> Result<Self> {
        let path = path.as_ref();
        let toml = std::fs::read_to_string(path)?;
        let metadata: Self = toml::from_str(&toml)?;
        Ok(metadata)
    }

    /// write toml to disk
    pub(crate) fn save(&self, folder: &Path) -> Result<()> {
        let toml = toml::to_string(self)?;
        let path = folder.join(&self.name).with_extension("toml");
        std::fs::write(path, toml)?;
        Ok(())
    }
}