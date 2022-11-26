use std::collections::{HashMap, BTreeMap};

use aya::maps::{StackTraceMap, MapData};
use tail2_common::{bpf_sample::BpfSample, NativeStack, python::state::PythonStack, pidtgid::PidTgid};

pub struct ResolvedBpfSample {
    pub pid_tgid: PidTgid,
    pub native_stack: Option<NativeStack>,
    pub python_stack: Option<PythonStack>,
    pub kernel_frames: Option<Vec<Option<String>>>,
}

impl ResolvedBpfSample {
    pub fn resolve(sample: BpfSample, kernel_stacks: &StackTraceMap<MapData>, ksyms: &BTreeMap<u64, String>) -> Self {
        let mut kernel_frames = None;
        let stack_id = sample.kernel_stack_id;
        if stack_id > 0 {
            let mut kernel_stack = kernel_stacks.get(&(stack_id as u32), 0).unwrap();
            let kfs: Vec<_> = kernel_stack.resolve(&ksyms).frames().into_iter().map(|i|i.symbol_name.clone()).collect();
            kernel_frames = Some(kfs);
        }

        Self {
            pid_tgid: sample.pidtgid,
            native_stack: sample.native_stack,
            python_stack: sample.python_stack,
            kernel_frames,
        }
    }
}