use std::collections::BTreeMap;

use aya::maps::{MapData, StackTraceMap};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tail2_common::{
    bpf_sample::BpfSample, pidtgid::PidTgid, python::state::PythonStack, NativeStack,
};

pub static KSYMS: Lazy<BTreeMap<u64, String>> = Lazy::new(|| {
    aya::util::kernel_symbols().unwrap()
});

fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> Result<&str, std::str::Utf8Error> {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len());
    ::std::str::from_utf8(&utf8_src[0..nul_range_end])
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ResolvedPythonFrames {
    pub frames: Vec<String>,
}

impl ResolvedPythonFrames {
    pub fn resolve(python_stack: PythonStack) -> Self {
        let mut frames = vec![];
        for f in &python_stack.frames[..python_stack.frames_len] {
            if let Ok(name) = str_from_u8_nul_utf8(&f.name) {
                frames.push(name.to_owned());
            }
        }

        Self { frames }
    }
}

#[derive(Debug)]
pub struct ResolvedBpfSample {
    pub pid_tgid: PidTgid,
    pub ts_ms: u64,
    pub native_stack: Box<NativeStack>,
    pub python_stack: Option<ResolvedPythonFrames>,
    pub kernel_frames: Option<Vec<Option<String>>>,
}

impl ResolvedBpfSample {
    pub fn resolve(
        sample: BpfSample,
        kernel_stacks: &StackTraceMap<MapData>,
    ) -> Option<Self> {
        let mut kernel_frames = None;
        let stack_id = sample.kernel_stack_id;
        if stack_id > 0 {
            let mut kernel_stack = kernel_stacks.get(&(stack_id as u32), 0).unwrap();
            let kfs: Vec<_> = kernel_stack
                .resolve(&KSYMS)
                .frames()
                .iter()
                .map(|i| i.symbol_name.clone())
                .collect();
            kernel_frames = Some(kfs);
        }

        if sample.native_stack.unwind_success.is_none() {
            return None;
        }

        Some(Self {
            pid_tgid: sample.pidtgid,
            ts_ms: sample.ts_ms,
            native_stack: Box::new(sample.native_stack),
            python_stack: sample.python_stack.map(ResolvedPythonFrames::resolve),
            kernel_frames,
        })
    }
}
