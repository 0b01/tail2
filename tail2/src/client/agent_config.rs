use anyhow::Result;
use log::error;
use serde::{Serialize, Deserialize, ser::SerializeMap};
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use aya::programs::perf_attach::PerfLink;

use crate::{probes::Probe, Tail2};

#[derive(Serialize, Deserialize)]
pub struct ProbeInfo {
    pub is_running: bool,
}

#[derive(Deserialize)]
pub struct AgentConfig {
    pub probes: HashMap<Probe, ProbeInfo>,
    #[serde(skip)]
    pub tx: Option<UnboundedSender<AgentMessage>>,
}

impl Serialize for AgentConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer
    {
        let mut map = serializer.serialize_map(Some(self.probes.len()))?;
        for (k, v) in &self.probes {
            map.serialize_entry(&serde_json::to_string(k)?, &v)?;
        }
        map.end()
    }
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
                let info = ProbeInfo { is_running: true };
                self.probes.insert(probe.clone(), info);
            }
            AgentMessage::StopProbe { probe } => {
                self.probes.remove(probe);
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
                    tx.send(AgentMessage::AgentError { message: "Already running".to_owned() });
                    return;
                }

                let mut tail2 = tail2.lock().await;
                let links = probe.attach(&mut tail2).unwrap();
                self.attached.insert(probe.clone(), links);
                // dbg!(&self.attached);
                tx.send(diff);
            }
            AgentMessage::StopProbe { probe } => todo!(),
            AgentMessage::AgentError { message } => todo!(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StartAgent {
    pub name: String,
    pub probe: Option<Probe>,
}