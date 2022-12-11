use std::{sync::{Arc}, path::PathBuf};
use tokio::sync::Mutex;

use log::info;
use rocket::{post, http::Status, Route, tokio, State};
use tail2::{dto::{StackBatchDto, FrameDto, StackDto}, calltree::inner::CallTreeInner, symbolication::{elf::ElfCache, module::Module}};
use crate::{error::Result, state::{CurrentCallTree, ResolvedFrame, CodeType}};

#[post("/stack", data = "<var>")]
async fn stack<'a>(var: StackBatchDto, st: &'a State<CurrentCallTree>) -> Result<Status> {
    // info!("{:#?}", var);
    let changed = Arc::clone(&st.changed);

    let ct_ = Arc::clone(&st.ct);
    let syms = Arc::clone(&st.syms);
    tokio::spawn(async move {
        let mut ct = CallTreeInner::new();
        for stack in var.stacks {
            let stack = build_stack(stack, &syms, &var.modules).await;
            ct.merge(&CallTreeInner::from_stack(&stack));
        }
        // info!("{:#?}", ct.root.debug_pretty_print(&ct.arena));
        (*ct_).lock().await.merge(&ct);
        changed.notify_one();
    });

    Ok(Status::Ok)
}

async fn build_stack(stack: StackDto, syms: &Arc<Mutex<ElfCache>>, modules: &[Arc<Module>]) -> Vec<Option<ResolvedFrame>> {
    let mut ret = vec![];
    let mut python_frames = stack.python_frames.into_iter();

    for f in stack.native_frames {
        match f {
            FrameDto::Native { module_idx, offset } => {
                let module = &modules[module_idx];
                let mut syms = syms.lock().await;
                match syms.entry(&module.path) {
                    Some((module_idx, elf)) => {
                        let name = elf.find(offset);
                        match name.as_ref().map(|i|i.as_str()) {
                            Some("_PyEval_EvalFrameDefault") => {
                                ret.push(python_frames.next().map(|i|
                                    ResolvedFrame {
                                        module_idx: 0,
                                        offset: 0,
                                        code_type: CodeType::Python,
                                        name: i.python_name(),
                                    }
                                ));
                            }
                            _ => {
                                let module_name = PathBuf::from(&module.path);
                                let module_name = module_name.file_name().map(|i|i.to_string_lossy().to_string()).unwrap_or_default();
                                let fn_name = name.unwrap_or_default();
                                ret.push(Some(
                                    ResolvedFrame {
                                        module_idx,
                                        offset,
                                        code_type: CodeType::Native,
                                        name: Some(format!("{}: {}", module_name, fn_name)),
                                    }));
                            }
                        }
                    }
                    None => {
                        ret.push(None);
                    }
                }
            }
            _ => { unreachable!() }
        }
    }

    // ret.append(&mut python_frames.map(|f| Some(ResolvedFrame {
    //     module_idx: 0,
    //     offset: 0,
    //     code_type: CodeType::Python,
    //     name: f.python_name(),
    // })).collect());
    if !ret.is_empty() {
        for kernel_frame in stack.kernel_frames {
            ret.push(Some(
                ResolvedFrame {
                    module_idx: 0,
                    offset: 0,
                    code_type: crate::state::CodeType::Kernel,
                    name: kernel_frame.kernel_name(),
                }));
        }
    }

    ret
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        stack,
    ]
}