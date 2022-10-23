use std::mem::size_of;
use std::os::unix::prelude::MetadataExt;

use aya::maps::perf::{AsyncPerfEventArray};
use aya::maps::HashMap;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::info;
use unwinding::MyUnwinderAarch64;
use crate::stacktrace::MyStackTrace;
use crate::symbolication::SymCache;
use crate::symbolication::elf::ElfCache;
use framehop::aarch64::{UnwinderAarch64, CacheAarch64};
use tail2_common::{ConfigKey, Stack};
use tokio::{task, signal};

mod proc_mem;
mod unwinding;
mod stacktrace;
mod symbolication;

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
    )).unwrap();
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tail2"
    )).unwrap();

        // let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
        // program.load().unwrap();
        // program.attach(Some("malloc"), 0, "libc", pid).unwrap();

        let program: &mut PerfEvent = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
        program.load().unwrap();
        // program.attach(Some("malloc"), 0, "libc", pid).unwrap();
        for cpu in online_cpus()? {
            program.attach(
                PerfTypeId::Software,
                aya::programs::perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Period(10000000),
            )?;
        }

    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    // send device info
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigKey::DEV as u32, dev, 0).unwrap();
    config.insert(ConfigKey::INO as u32, ino, 0).unwrap();

    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map("STACKS").unwrap()).unwrap();

    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, None).unwrap();
        
        task::spawn(async move {
            let mut unw = MyUnwinderAarch64::new();

            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size_of::<Stack>()))
                .collect::<Vec<_>>();
    
            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await.unwrap();
    
                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let st = unsafe { *std::mem::transmute::<_, *const Stack>(buf.as_ptr()) };

                    let frames = unw.unwind(st);

                    let stacktrace = MyStackTrace::from_frames(&frames, &SymCache::build(st.pidtgid.pid()));
                    dbg!(stacktrace);
                }
            }
        });
    }
    
    signal::ctrl_c().await.expect("failed to listen for event");

    info!("exiting!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {

        let mut unwinder = UnwinderAarch64::new();
        let mut unw_cache = CacheAarch64::<_>::new();

        add_module_to_unwinder(
            &mut unwinder,
            "/home/g/tail2/testapp/malloc/a.out".as_bytes(),
            0,
            0xaaaac6cd0000,
            0x1000,
            None,
            None,
        );

        add_module_to_unwinder(
            &mut unwinder,
            "/usr/lib/aarch64-linux-gnu/libc.so.6".as_bytes(),
            0,
            0xffff87770000,
            0xffff878f9000 - 0xffff87770000,
            None,
            None,
        );

        let pc = 281473445385793;
        let sp = 281474403929088;
        let fp = 281474403929088;
        let lr = 187650854029324;

        let mut iter = unwinder.iter_frames(
            pc,
            UnwindRegsAarch64::new(lr, sp, fp),
            &mut unw_cache,
            &mut read_stack,
        );

    }
}