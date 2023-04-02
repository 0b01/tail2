use std::sync::Arc;

use anyhow::Result;
use fnv::FnvHashMap;
use serde::{Serialize};
use tail2::{client::ws_client::messages::AgentMessage, probes::Probe};
use tail2_db::{manager::Db};
use tail2_db::manager::Manager;
use tail2_db::metadata::Metadata;
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use crate::Notifiable;

#[derive(Serialize)]
pub struct ProbeState {
    pub is_running: bool,

    #[serde(skip)]
    pub db: Notifiable<Db>,
}

impl ProbeState {
    pub fn new(manager: &mut Manager, md: Metadata) -> Self {
        // let path = std::env::current_dir().unwrap().join("tail2.t2db");
        // let db = Notifiable::new(Arc::new(Mutex::new(db::Tail2DB::open(&path))));
        let db = manager.create_db(md).unwrap();
        let db = Notifiable::new_wrapped(db);

        Self {
            db,
            is_running: false,
        }
    }
}

#[derive(Serialize)]
pub struct Tail2Agent {
    /// Probes attached to the agent.
    #[serde(with = "vectorize")]
    pub probes: FnvHashMap<Probe, ProbeState>,

    /// tx handle to send messages to the agent.
    #[serde(skip)]
    pub tx: Option<UnboundedSender<AgentMessage>>,

    /// Whether the agent is halted.
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

    pub async fn process(&mut self, diff: &AgentMessage, manager: Arc<Mutex<Manager>>) -> Result<()> {
        match diff {
            AgentMessage::AddProbe { probe } => {
                self.is_halted = false;
                let manager = &mut *manager.lock().await;
                let info = self.probes
                    .entry(probe.clone())
                    .or_insert(ProbeState::new(manager, Metadata::empty(probe)));
                info.is_running = true;
            }
            AgentMessage::StopProbe { probe } => {
                let manager = &mut *manager.lock().await;
                let info = self.probes
                    .entry(probe.clone())
                    .or_insert(ProbeState::new(manager, Metadata::empty(probe)));
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