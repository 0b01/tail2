use anyhow::Result;
use aya::{programs::{UProbe, PerfEvent, SamplePolicy, perf_event, PerfEventScope, PerfTypeId, perf_attach::PerfLink}, util::online_cpus};
use serde::{Deserialize, Serialize};
use crate::Tail2;
use tracing::{info, error};

use super::Scope;

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct PerfProbe {
    pub scope: Scope,
    pub period: u64,
}

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct UprobeProbe {
    pub scope: Scope,
    pub uprobe: String,
}

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize, Clone, Debug)]
pub enum Probe {
    Perf(PerfProbe),
    Uprobe(UprobeProbe),
}

impl Probe {
    pub fn attach(&self, state: &mut Tail2) -> Result<Vec<PerfLink>> {
        match self {
            Probe::Perf(probe) => {
                let program: &mut PerfEvent = state
                    .bpf
                    .program_mut("capture_stack")
                    .unwrap()
                    .try_into()
                    .unwrap();
                match program.load() {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e.to_string());
                        panic!();
                    }
                }

                let mut links = vec![];
                for cpu in online_cpus()? {
                    let scope = match probe.scope {
                        Scope::Pid(pid) => PerfEventScope::OneProcessOneCpu { cpu, pid },
                        Scope::SystemWide => PerfEventScope::AllProcessesOneCpu { cpu },
                    };
                    let link_id = program.attach(
                        PerfTypeId::Software,
                        perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
                        scope,
                        SamplePolicy::Period(probe.period),
                    )?;
                    let link = program.take_link(link_id)?;
                    links.push(link.into());
                }
                Ok(links)
            }
            Probe::Uprobe(probe) => {
                let program: &mut UProbe = state
                    .bpf
                    .program_mut("malloc_enter")
                    .unwrap()
                    .try_into()
                    .unwrap();
                match program.load() {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e.to_string());
                        panic!();
                    }
                }

                let mut uprobe = probe.uprobe.split(':');
                let src = uprobe.next().unwrap();
                let func = uprobe.next().unwrap();
                let pid = match probe.scope {
                    Scope::Pid(pid) => Some(pid as i32),
                    Scope::SystemWide => None,
                };
                let uprobe_linkid = program
                    .attach(Some(func), 0, src, pid)
                    .unwrap();
                let link = program.take_link(uprobe_linkid)?.into();
                info!("loaded");
                Ok(vec![link])
            }
        }
    }
}