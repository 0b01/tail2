use anyhow::Result;
use tracing::{error, info};
use serde::{Serialize, Deserialize, ser::{SerializeMap, SerializeSeq}};
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use aya::programs::perf_attach::PerfLink;

use crate::{probes::Probe, Tail2, client::run::run_until_exit};

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
}

impl AgentConfig {
    pub fn new(tx: UnboundedSender<AgentMessage>) -> Self {
        Self {
            probes: HashMap::new(),
            tx: Some(tx),
        }
    }

    pub fn process(&mut self, diff: &AgentMessage) -> Result<()> {
        match diff {
            AgentMessage::AddProbe { probe } => {
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
    }
}

#[derive(Serialize, Deserialize)] 
pub struct NewConnection {
    pub name: String,
}

#[derive(Default)]
pub struct AgentProbeState {
    attached: HashMap<Probe, Vec<PerfLink>>,
}

impl AgentProbeState {
    pub async fn on_new_msg(&mut self, diff: AgentMessage, tx: UnboundedSender<AgentMessage>, tail2: Arc<Mutex<Tail2>>) {
        match &diff {
            AgentMessage::AddProbe { probe } => {
                if self.attached.contains_key(&probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe is already running: {:?}", probe)
                    }).unwrap();
                    return;
                }

                let mut tail2 = tail2.lock().await;
                let links = probe.attach(&mut tail2).unwrap();
                self.attached.insert(probe.clone(), links);
                info!("Probe attached: {:?}", &probe);
                tx.send(diff).unwrap();
                // tokio::spawn(async move {
                    run_until_exit(&mut tail2, None, None).await.unwrap();
                // });
            }
            AgentMessage::StopProbe { probe } => {
                if !self.attached.contains_key(&probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe doesn't exist: {:?}", probe)
                    }).unwrap();
                    return;
                }

                let mut tail2 = tail2.lock().await;
                let links = self.attached.remove(probe).unwrap();
                probe.detach(&mut tail2, links);

                info!("Probe detached: {:?}", &probe);
                tx.send(diff).unwrap();
            },
            AgentMessage::AgentError { message } => todo!(),
        }
    }
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