use anyhow::Result;
use aya::{programs::{UProbe, PerfEvent, SamplePolicy, perf_event, PerfEventScope, PerfTypeId, perf_attach::PerfLink, Program}, util::online_cpus, Bpf};
use serde::{Deserialize, Serialize};

use tracing::{info, error};

use super::Scope;

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum Probe {
    Perf {
        scope: Scope,
        period: u64,
    },
    Uprobe {
        scope: Scope,
        uprobe: String,
    },
}

impl Probe {
    pub fn to_program<'a>(&'a self, bpf: &'a mut Bpf) -> &mut Program {
        match self {
            Probe::Perf{ .. } => bpf.program_mut("capture_stack").unwrap(),
            Probe::Uprobe { .. } => bpf.program_mut("malloc_enter").unwrap(),
        }
    }

    pub fn attach(&self, bpf: &mut Bpf) -> Result<Vec<PerfLink>> {
        let program = self.to_program(bpf);
        match self {
            Probe::Perf{ scope, period } => {
                let program: &mut PerfEvent = program.try_into().unwrap();
                match program.load() {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e.to_string());
                    }
                }

                let mut links = vec![];
                for cpu in online_cpus()? {
                    let scope = match scope {
                        Scope::Pid{pid} => PerfEventScope::OneProcessOneCpu { cpu, pid: *pid },
                        Scope::SystemWide => PerfEventScope::AllProcessesOneCpu { cpu },
                    };
                    let link_id = program.attach(
                        PerfTypeId::Software,
                        perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
                        scope,
                        SamplePolicy::Period(*period),
                    )?;
                    let link = program.take_link(link_id)?;
                    links.push(link);
                }
                Ok(links)
            }
            Probe::Uprobe{scope, uprobe} => {
                let program: &mut UProbe = program.try_into().unwrap();
                match program.load() {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e.to_string());
                    }
                }

                let mut uprobe = uprobe.split(':');
                let src = uprobe.next().unwrap();
                let func = uprobe.next().unwrap();
                let pid = match scope {
                    Scope::Pid{pid} => Some(*pid as i32),
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