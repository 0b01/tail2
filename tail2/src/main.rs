use std::f32::consts::E;
use std::fmt::Display;
use std::mem::size_of;
use std::os::unix::prelude::MetadataExt;

use aya::maps::perf::{AsyncPerfEventArray};
use aya::maps::{HashMap, MapRefMut};
use aya::maps::stack_trace::StackTrace;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::UProbe;
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use elf::ElfCache;
use framehop::aarch64::{UnwinderAarch64, UnwindRegsAarch64, CacheAarch64};
use log::{warn};
use proc_mem::ProcMemMap;
use tail2_common::{ConfigKey, Stack, MAX_STACK_SIZE};
use tokio::{task, signal};

use crate::unwind::add_module_to_unwinder;

mod proc_mem;
mod elf;
mod unwind;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print symbols
    Symbols {
        /// path to elf file
        #[clap(short, long)]
        elf_file: String,
    },
    /// Listen to a PID
    Listen {
        #[clap(short, long)]
        pid: Option<i32>,
    }

}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    match opt.command {
        Commands::Symbols { elf_file } => {
            let elf_cache = ElfCache::build(&[elf_file]);
            dbg!(elf_cache);
            Ok(())
        },
        Commands::Listen { pid } => {
            run_bpf(pid).await
        },
    }
}

async fn run_bpf(pid: Option<i32>) -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tail2"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tail2"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("malloc"), 0, "libc", pid)?;

    let mut config: HashMap<MapRefMut, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG")?)?;
    send_device_info(&mut config);

    let mut stacks = AsyncPerfEventArray::try_from(bpf.map_mut("STACKS")?)?;



    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, None)?;

        task::spawn(async move {
            let mut unwinder = UnwinderAarch64::new();
            let mut unw_cache = CacheAarch64::<_>::new();

            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size_of::<Stack>()))
                .collect::<Vec<_>>();
    
            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await.unwrap();
                dbg!(&events);
    
                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let st = unsafe { *std::mem::transmute::<_, *const Stack>(buf.as_ptr()) };

                    let cache = SymCache::build(st.pidtgid.pid());
                    for entry in cache.proc_map.entries {
                        if !entry.is_exec { continue; }
                        add_module_to_unwinder(
                            &mut unwinder,
                            entry.object_path.as_bytes(),
                            entry.offset,
                            entry.address_range.0,
                            entry.address_range.1 - entry.address_range.0,
                            None,
                            None,
                        );
                    }

                    fn to_u64_arr(s8: &[u8]) -> &[u64] {
                        use std::slice;
                        unsafe {
                            slice::from_raw_parts(s8.as_ptr() as *const u64, s8.len() / 8)
                        }
                    }

                    let mut read_stack = |addr| to_u64_arr(&st.stuff).get((addr / 8) as usize).cloned().ok_or(());
                    use framehop::Unwinder;
                    let mut iter = unwinder.iter_frames(
                        st.pc,
                        UnwindRegsAarch64::new(st.lr, st.sp, st.fp),
                        &mut unw_cache,
                        &mut read_stack,
                    );

                    while let Ok(f) = iter.next() {
                        dbg!(f);
                    }

                    // dbg!(st);
                    // process buf
                }
            }
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");

    Ok(())
}

pub struct SymCache {
    pub proc_map: ProcMemMap,
    pub elf_cache: ElfCache,
}

impl SymCache {
    pub fn build(pid: u32) -> Self {
        let proc_map = ProcMemMap::from_process_id(pid).unwrap();
        let paths: Vec<String> = proc_map.entries.iter().map(|i| i.object_path.to_owned()).collect();
        let elf_cache = ElfCache::build(&paths);

        Self {
            proc_map,
            elf_cache,
        }
    }
}


#[derive(Hash, Eq, PartialEq, Debug)]
struct MyStackTrace {
    frames: Vec<(String, u64, String)>,
}

impl MyStackTrace {
    fn from(trace: StackTrace, syms: &SymCache) -> Self {
        let frames = trace.frames().iter().map(|f| {
            if let Some(res) = syms.proc_map.lookup(f.ip) {
                let addr = res.address;
                let name = syms.elf_cache.map.get(&res.object_path).and_then(|c| c.find(addr)).unwrap_or("".to_owned());
                (res.object_path, addr, name)
            } else {
                ("".to_owned(), 0, "".to_owned())
            }
        }).collect();

        Self {
            frames,
        }
    }
}

impl Display for MyStackTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (obj, offset, name) in &self.frames {
            let _ = writeln!(f, "<{}> {}+{:#x}", name, obj, offset);
        }

        Ok(())
    }
}

fn send_device_info(config: &mut HashMap<MapRefMut, u32, u64>) {
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigKey::DEV as u32, dev, 0).unwrap();
    config.insert(ConfigKey::INO as u32, ino, 0).unwrap();
}