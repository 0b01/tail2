use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use aya::programs::perf_attach::PerfLink;

use crate::{probes::Probe, Tail2};

pub struct ProbeInfo {
    pub links: Vec<PerfLink>,
}

pub struct AgentConfig {
    probes: HashMap<Probe, ProbeInfo>,
}

impl AgentConfig {
    pub fn new() -> Self {
        Self {
            probes: HashMap::new(),
        }
    }

    pub fn process(&mut self, diff: AgentConfigDiff, state: &mut Tail2) -> Result<()> {
        match diff {
            AgentConfigDiff::AddProbe { probe } => {
                let info = ProbeInfo { links: probe.attach(state)? };
                self.probes.insert(probe, info);
            }
            AgentConfigDiff::StopProbe { probe } => {
                self.probes.remove(&probe);
            }
        };

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub enum AgentConfigDiff {
    AddProbe {
        probe: Probe,
    },
    StopProbe {
        probe: Probe,
    }
}