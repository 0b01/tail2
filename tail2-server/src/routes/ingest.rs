use std::sync::Arc;

use log::info;
use rocket::{post, http::Status, Route, tokio, State};
use tail2::{dto::{StackBatchDto, FrameDto}, calltree::frames::CallTree, symbolication::elf::ElfCache};
use crate::{error::Result, state::{CurrentCallTree, ResolvedFrame}};

#[post("/stack", data = "<var>")]
fn stack<'a>(var: StackBatchDto, st: &'a State<CurrentCallTree>) -> Result<Status> {
    // info!("{:#?}", var);
    let changed = Arc::clone(&st.changed);

    let ct_ = Arc::clone(&st.ct);
    let syms = Arc::clone(&st.syms);
    tokio::spawn(async move {
        let mut ct = CallTree::new();
        for stack in var.stacks {
            let stack = {
                let mut ret = vec![];
                for f in stack.native_frames {
                    match f {
                        FrameDto::Native { module_idx, offset } => {
                            let module = &var.modules[module_idx];
                            let mut syms = syms.lock().unwrap();
                            if let Some((module_idx, elf)) = syms.entry(&module.path) {
                                let name = elf.find(offset);
                                ret.push(Some(ResolvedFrame { module_idx, offset, name }));
                            } else {
                                ret.push(None);
                            }
                        }
                        // TODO: merge python frames into _PyEval_EvalDefaultFrame
                        FrameDto::Python { name } => {
                            let name = Some(format!("python: {}", name));
                            ret.push(Some(ResolvedFrame { module_idx: 0, offset: 0, name }))
                        }
                    }
                }
                ret
            };
            ct.merge(&CallTree::from_stack(&stack));
        }
        // info!("{:#?}", ct.root.debug_pretty_print(&ct.arena));
        ct_.lock().unwrap().merge(&ct);
        changed.notify_one();
    });

    Ok(Status::Ok)
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        stack,
    ]
}