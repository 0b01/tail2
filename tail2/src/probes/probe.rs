use std::sync::{atomic::AtomicBool, Arc};

use anyhow::{Result, Context};
use aya::{programs::{UProbe, PerfEvent, SamplePolicy, perf_event, PerfEventScope, PerfTypeId, perf_attach::PerfLink, Program, Link}, util::online_cpus, Bpf};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{tail2::Probes, client::PostStackClient};

use super::Scope;

pub struct ProbePool {
    available: Vec<Arc<AtomicBool>>,
}

impl ProbePool {
    pub(crate) fn new(n: usize) -> ProbePool {
        Self {
            available: vec![true; n].into_iter().map(|i| Arc::new(AtomicBool::new(i))).collect(),
        }
    }

    pub(crate) fn next_avail(&self) -> Option<(usize, Arc<AtomicBool>)> {
        for (i, n) in self.available.iter().enumerate() {
            if n.load(std::sync::atomic::Ordering::SeqCst) {
                n.store(false, std::sync::atomic::Ordering::SeqCst);
                return Some((i, n.clone()));
            }
        }

        None
    }
}

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

pub struct Attachment {
    pub links: Vec<PerfLink>,
    pub idx: usize,
    pub avail: Arc<AtomicBool>,
    pub cli: Arc<Mutex<PostStackClient>>,
}

impl Attachment {
    pub async fn detach(self) {
        self.avail.store(true, std::sync::atomic::Ordering::SeqCst);

        for link in self.links {
            link.detach().unwrap();
        }

        self.cli.lock().await.flush().await.unwrap();
    }
}

impl Probe {
    pub fn to_program<'a>(&'a self, bpf: &'a mut Bpf, probe_pool: &ProbePool) -> Option<(&mut Program, usize, Arc<AtomicBool>)> {
        let (i, avail) = probe_pool.next_avail()?;
        let ret = match self {
            Probe::Perf{ .. } => bpf.program_mut(&format!("capture_stack_{i}")).unwrap(),
            Probe::Uprobe { .. } => bpf.program_mut(&format!("malloc_enter_{i}")).unwrap(),
        };

        Some((ret, i, avail))
    }

    pub async fn attach(&self, bpf: &mut Bpf, probes: &Probes) -> Result<Attachment> {
        let (program, idx, avail) = self.to_program(bpf, &probes.probe_pool).context("No probe function available")?;

        let cli = Arc::new(Mutex::new(PostStackClient::new(Arc::new(self.clone()))));
        probes.clients.lock().await.insert(idx, Arc::clone(&cli));

        match self {
            Probe::Perf{ scope, period } => {
                let program: &mut PerfEvent = program.try_into().unwrap();
                match program.load() {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("{}", e.to_string());
                    }
                }

                let mut links = vec![];
                for cpu in online_cpus()? {
                    let scope = match scope {
                        Scope::Pid{pid: 0} => PerfEventScope::OneProcessOneCpu { cpu, pid: std::process::id() },
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
                Ok(Attachment{links, idx, cli, avail})
            }
            Probe::Uprobe{scope, uprobe} => {
                let program: &mut UProbe = program.try_into().unwrap();
                match program.load() {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("{}", e.to_string());
                    }
                }

                let mut uprobe = uprobe.split(':');
                let src = uprobe.next().unwrap();
                let func = uprobe.next().unwrap();
                let pid = match scope {
                    Scope::Pid{pid: 0} => Some(std::process::id() as i32),
                    Scope::Pid{pid} => Some(*pid as i32),
                    Scope::SystemWide => None,
                };
                let uprobe_linkid = program
                    .attach(Some(func), 0, src, pid)
                    .unwrap();
                let link = program.take_link(uprobe_linkid)?.into();
                Ok(Attachment{links: vec![link], idx, avail, cli})
            }
        }
    }
}