use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

use crate::{error::Result, state::CurrentCallTree};
use log::info;
use rocket::{http::Status, post, tokio, Route, State};
use tail2::{
    calltree::{inner::CallTreeInner, CodeType, ResolvedFrame},
    dto::{FrameDto, StackBatchDto, StackDto, build_stack},
    symbolication::{elf::ElfCache, module::Module},
    Mergeable,
};

#[post("/stack", data = "<var>")]
async fn stack(var: StackBatchDto, st: &State<CurrentCallTree>) -> Result<Status> {
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
        ct_.lock().await.merge(&ct);
        changed.notify_one();
    });

    Ok(Status::Ok)
}

pub fn routes() -> Vec<Route> {
    rocket::routes![stack,]
}
