use std::sync::Arc;

use serde::{Serialize, Deserialize};

use crate::probes::{Probe, probe::Attachment};

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
        pub hostname: String,
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