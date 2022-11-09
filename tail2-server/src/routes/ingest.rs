use std::sync::Arc;

use log::info;
use rocket::{post, http::Status, Route, tokio, State};
use tail2::{dto::StackBatchDto, calltree::frames::CallTree};
use crate::{error::Result, state::CurrentCallTree};

#[post("/stack", data = "<var>")]
fn stack(var: StackBatchDto, st: &State<CurrentCallTree>) -> Result<Status> {
    info!("{:#?}", var);
    let ct_ = Arc::clone(&st.ct);
    tokio::spawn(async move {
        let mut ct = CallTree::new();
        for stack in var.stacks {
            let stack = {
                let mut ret = vec![];
                for f in &stack.frames {
                    let module = &var.modules[f.module_idx];
                    let name = tail2::symbolication::dump_elf::lookup(&module.path, f.offset).unwrap_or("(not found)".to_string());
                    ret.push(name);
                }
                ret
            };
            ct.merge(&CallTree::from_stack(&stack));
        }
        info!("{:#?}", ct.root.debug_pretty_print(&ct.arena));
        ct_.lock().unwrap().merge(&ct);
    });

    Ok(Status::Ok)
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        stack,
    ]
}