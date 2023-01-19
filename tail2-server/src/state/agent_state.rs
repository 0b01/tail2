use std::collections::HashMap;

use anyhow::Result;
use serde::{Serialize, Deserialize};
use tail2::{client::ws_client::messages::AgentMessage, probes::Probe};
use tokio::sync::mpsc::UnboundedSender;
use tracing::error;

#[derive(Serialize, Deserialize, Default)]
pub struct ProbeInfo {
    pub is_running: bool,
    // TODO:
}

#[derive(Serialize, Deserialize)]
pub struct Tail2Agent {
    #[serde(with = "vectorize")]
    pub probes: HashMap<Probe, ProbeInfo>,
    #[serde(skip)]
    pub tx: Option<UnboundedSender<AgentMessage>>,
    is_halted: bool,
}

impl Tail2Agent {
    pub fn new(tx: UnboundedSender<AgentMessage>) -> Self {
        Self {
            probes: HashMap::new(),
            tx: Some(tx),
            is_halted: true,
        }
    }

    pub fn process(&mut self, diff: &AgentMessage) -> Result<()> {
        match diff {
            AgentMessage::AddProbe { probe } => {
                self.is_halted = false;
                let info = self.probes.entry(probe.clone()).or_insert(Default::default());
                info.is_running = true;
            }
            AgentMessage::StopProbe { probe } => {
                let info = self.probes.entry(probe.clone()).or_insert(Default::default());
                info.is_running = false;
            }
            AgentMessage::AgentError { message } => {
                error!("error: {}", message);
            }
            AgentMessage::Halt => {
                self.is_halted = true;
                self.probes.values_mut().for_each(|v|
                    v.is_running = false
                );
            }
        };

        Ok(())
    }
}

pub mod vectorize {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::iter::FromIterator;

    pub fn serialize<'a, T, K, V, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: IntoIterator<Item = (&'a K, &'a V)>,
        K: Serialize + 'a,
        V: Serialize + 'a,
    {
        let container: Vec<_> = target.into_iter().collect();
        serde::Serialize::serialize(&container, ser)
    }

    pub fn deserialize<'de, T, K, V, D>(des: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromIterator<(K, V)>,
        K: Deserialize<'de>,
        V: Deserialize<'de>,
    {
        let container: Vec<_> = serde::Deserialize::deserialize(des)?;
        Ok(T::from_iter(container.into_iter()))
    }
}