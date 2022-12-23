use tracing::info;
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc::UnboundedSender, Mutex, watch};
use std::{collections::HashMap, sync::Arc};

use aya::{programs::perf_attach::PerfLink, Bpf};

use crate::{probes::Probe, client::run::{run_until_exit, RunUntil}, symbolication::module_cache::ModuleCache};

use self::messages::AgentMessage;

use super::post_stack_client::PostStackClient;

pub mod messages {
    use super::*;

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

    #[derive(Serialize, Deserialize)]
    pub struct HaltAgent {
        pub name: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct StartAgent {
        pub name: String,
        pub probe: String,
    }
}

// TODO: currently dropping PerfLink is broken, alessandrod will change to PerfEventLink
pub struct ProbeLinks {
    pub links: Vec<PerfLink>,
}

pub struct WsAgent {
    probes: HashMap<Probe, ProbeLinks>,
    halt_tx: Option<watch::Sender<()>>,
    is_task_running: bool,
}

impl WsAgent {
    pub fn new() -> Self {
        Self {
            probes: Default::default(),
            halt_tx: None,
            is_task_running: false,
        }
    }
}

impl Default for WsAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl WsAgent {
    pub async fn on_new_msg(
        &mut self,
        diff: AgentMessage,
        tx: UnboundedSender<AgentMessage>,
        bpf: Arc<Mutex<Bpf>>,
        cli: Arc<Mutex<PostStackClient>>,
        module_cache: Arc<Mutex<ModuleCache>>,
    ) {
        match &diff {
            AgentMessage::AddProbe { probe } => {
                if self.probes.contains_key(probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe is already running: {probe:?}")
                    }).unwrap();
                    return;
                }

                let links = probe.attach(&mut *bpf.lock().await).unwrap();
                self.probes.insert(probe.clone(), ProbeLinks { links });
                info!("Probe attached: {:?}", &probe);

                if !self.is_task_running {
                    let (halt_tx, halt_rx) = watch::channel(());
                    self.halt_tx = Some(halt_tx);
                    tokio::spawn(
                        run_until_exit(
                            bpf,
                            cli,
                            module_cache,
                            RunUntil::ExternalHalt(halt_rx),
                            None)
                    );
                    self.is_task_running = true;
                }

                tx.send(diff).unwrap();
            }
            AgentMessage::StopProbe { probe } => {
                if !self.probes.contains_key(probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe doesn't exist: {probe:?}")
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
                        halt_tx.send(()).unwrap();
                        tx.send(AgentMessage::Halt).unwrap();
                        self.probes.clear();
                        self.is_task_running = false;
                    }
                    None => {
                        tx.send(AgentMessage::AgentError {
                            message: "Unable to halt".to_string()
                        }).unwrap();
                    }
                }
            }
            AgentMessage::AgentError { message: _ } => unimplemented!(),
        }
    }
}
