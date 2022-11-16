use std::sync::Arc;

use log::info;
use rocket::{post, http::Status, Route, tokio, State};
use tail2::{dto::StackBatchDto, calltree::frames::CallTree, symbolication::elf::ElfCache};
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
                for f in &stack.frames {
                    let module = &var.modules[f.module_idx];
                    let mut syms = syms.lock().unwrap();
                    if let Some((module_idx, elf)) = syms.entry(&module.path) {
                        let name = elf.find(f.offset);
                        ret.push(Some(ResolvedFrame { module_idx, offset: f.offset, name }));
                    } else {
                        ret.push(None);
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