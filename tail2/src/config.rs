use anyhow::{Context, Result};
use std::{fs::File, io::Read};

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Tail2Config {
    pub server: Server,
}

#[derive(Deserialize, Debug)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub batch_size: usize,
}

impl Tail2Config {
    pub fn new() -> Result<Self> {
        Self::from_path("Tail2.toml")
    }

    pub fn from_path(path: &str) -> Result<Self> {
        let current_dir = std::env::current_dir().context("unable to get current dir")?;
        let mut config_file = File::open(path).with_context(move || format!("Tail2.toml not found in {current_dir:?}"))?;
        let mut contents = String::new();
        config_file
            .read_to_string(&mut contents)
            .context("something went wrong reading Tail2.toml")?;
        let config: Tail2Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
