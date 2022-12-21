use anyhow::Result;
use tracing::{error, info};
use serde::{Serialize, Deserialize, ser::{SerializeMap, SerializeSeq}};
use tokio::sync::{mpsc::UnboundedSender, Mutex, watch};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use aya::{programs::perf_attach::PerfLink, Bpf};

use crate::{probes::Probe, Tail2, client::run::{run_until_exit, RunUntil}, symbolication::module_cache::ModuleCache};

use super::api_client::ApiStackEndpointClient;

#[derive(Serialize, Deserialize, Default)]
pub struct ProbeInfo {
    pub is_running: bool,
}

#[derive(Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(with = "vectorize")]
    pub probes: HashMap<Probe, ProbeInfo>,
    #[serde(skip)]
    pub tx: Option<UnboundedSender<AgentMessage>>,
    is_halted: bool,
}

impl AgentConfig {
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
            }
        };

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AgentMessage {
    AddProbe {
        probe: Probe,
    },
    StopProbe {
        probe: Probe,
    },
    AgentError {
        message: String,
    },
    Halt,
}

#[derive(Serialize, Deserialize)] 
pub struct NewConnection {
    pub name: String,
}

// TODO: currently dropping PerfLink is broken, alessandrod will change to PerfEventLink
pub struct ProbeLinks {
    links: Vec<PerfLink>,
}

pub struct AgentState {
    probes: HashMap<Probe, ProbeLinks>,
    halt_tx: Option<watch::Sender<()>>,
    is_task_running: bool,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            probes: Default::default(),
            halt_tx: None,
            is_task_running: false,
        }
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentState {
    pub async fn on_new_msg(
        &mut self,
        diff: AgentMessage,
        tx: UnboundedSender<AgentMessage>,
        bpf: Arc<Mutex<Bpf>>,
        cli: Arc<Mutex<ApiStackEndpointClient>>,
        module_cache: Arc<Mutex<ModuleCache>>,
    ) {
        match &diff {
            AgentMessage::AddProbe { probe } => {
                if self.probes.contains_key(&probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe is already running: {:?}", probe)
                    }).unwrap();
                    return;
                }

                let links = probe.attach(&mut *bpf.lock().await).unwrap();
                self.probes.insert(probe.clone(), ProbeLinks { links });
                info!("Probe attached: {:?}", &probe);

                let (halt_tx, halt_rx) = watch::channel(());
                self.halt_tx = Some(halt_tx);
                if !self.is_task_running {
                    tokio::spawn(
                        run_until_exit(
                            bpf,
                            cli,
                            module_cache,
                            RunUntil::ExternalHalt(halt_rx),
                            None)
                    );
                }

                tx.send(diff).unwrap();
            }
            AgentMessage::StopProbe { probe } => {
                if !self.probes.contains_key(&probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe doesn't exist: {:?}", probe)
                    }).unwrap();
                    return;
                }

                let links = self.probes.remove(probe).unwrap();
                drop(links);

                info!("Probe detached: {:?}", &probe);
                tx.send(diff).unwrap();
            },
            AgentMessage::Halt => {
                match &self.halt_tx {
                    Some(halt_tx) => {
                        halt_tx.send(());
                        tx.send(AgentMessage::Halt).unwrap();
                    }
                    None => {
                        tx.send(AgentMessage::AgentError {
                            message: format!("Unable to halt")
                        }).unwrap();
                    }
                }
            }
            AgentMessage::AgentError { message } => unimplemented!(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct HaltAgent {
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct StartAgent {
    pub name: String,
    pub probe: Option<Probe>,
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