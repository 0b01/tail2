pub struct PerfProbe {

}

pub struct UprobeProbe {

}

pub enum Probe {
    Perf(PerfProbe),
    Uprobe(UprobeProbe),
}

pub struct AgentConfig {
    probes: Vec<Probe>,
}

impl AgentConfig {
    pub fn new() -> Self {
        Self {
            probes: vec![],
        }
    }
}

pub enum AgentConfigDiff {
    AddProbe {
        probe: Probe,
    },
    StopProbe {
        probe: Probe,
    }
}