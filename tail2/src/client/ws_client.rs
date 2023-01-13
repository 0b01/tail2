use std::sync::Arc;

use serde::{Serialize, Deserialize};

use aya::programs::{perf_attach::PerfLink, Link};
use tokio::sync::Mutex;

use crate::config::CONFIG;

use super::PostStackClient;

pub mod messages {
    use crate::probes::Probe;

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
pub struct ProbeState {
    pub links: Vec<PerfLink>,
    pub cli: Arc<Mutex<PostStackClient>>,
}

impl ProbeState {
    pub fn new(links: Vec<PerfLink>) -> Self {
        let cli = Arc::new(Mutex::new(PostStackClient::new(
            &format!("http://{}:{}/api/stack", CONFIG.server.host, CONFIG.server.port),
            CONFIG.server.batch_size,
        )));

        Self {
            links,
            cli,
        }
    }
    pub async fn detach(self) {
        for link in self.links {
            link.detach().unwrap();
        }

        self.cli.lock().await.flush().await.unwrap();
    }
}
