use std::sync::Arc;

use anyhow::Result;
use fnv::FnvHashMap;
use serde::{Serialize};
use tail2::{client::ws_client::messages::AgentMessage, probes::Probe};
use tail2_db::db;
use tokio::sync::{mpsc::UnboundedSender};
use tokio::sync::Mutex;


use crate::Notifiable;



#[derive(Serialize)]
pub struct ProbeState {
    pub is_running: bool,

    #[serde(skip)]
    pub db: Notifiable<Arc<Mutex<db::Tail2DB>>>,
}

impl ProbeState {
    pub fn new() -> Self {
        let path = std::env::current_dir().unwrap().join("tail2.db");
        let db = Notifiable::new(Arc::new(Mutex::new(db::Tail2DB::new(path))));
        Self {
            db,
            is_running: false,
        }
    }
}

impl Default for ProbeState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
pub struct Tail2Agent {
    #[serde(with = "vectorize")]
    pub probes: FnvHashMap<Probe, ProbeState>,
    #[serde(skip)]
    pub tx: Option<UnboundedSender<AgentMessage>>,
    is_halted: bool,
}

impl Tail2Agent {
    pub fn new(tx: UnboundedSender<AgentMessage>) -> Self {
        Self {
            probes: FnvHashMap::default(),
            tx: Some(tx),
            is_halted: true,
        }
    }

    pub fn process(&mut self, diff: &AgentMessage) -> Result<()> {
        match diff {
            AgentMessage::AddProbe { probe } => {
                self.is_halted = false;
                let info = self.probes.entry(probe.clone()).or_insert(ProbeState::new());
                info.is_running = true;
            }
            AgentMessage::StopProbe { probe } => {
                let info = self.probes.entry(probe.clone()).or_insert(ProbeState::new());
                info.is_running = false;
            }
            AgentMessage::AgentError { message } => {
                tracing::error!("error: {}", message);
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