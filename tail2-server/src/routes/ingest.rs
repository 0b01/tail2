use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;

use crate::{error::Result, state::{CurrentCallTree, Connections}, Notifiable};
use log::info;
use rocket::{response::stream::{Event, EventStream}, get};
use rocket::{http::Status, post, tokio, Route, State};
use tail2::{
    calltree::{inner::CallTreeInner, CodeType, ResolvedFrame},
    dto::{FrameDto, StackBatchDto, StackDto, build_stack},
    symbolication::{elf::ElfCache, module::Module},
    Mergeable, client::agent_config::AgentConfig,
};

#[get("/connect")]
async fn connect(st: &State<Connections>) -> EventStream![] {
    let config = Notifiable::<AgentConfig>::new(AgentConfig::new());
    let changed = Arc::clone(&config.changed);
    st.machines.lock().await.push(config);

    let stream = EventStream!{
        loop {
            changed.notified().await;
            yield Event::data("test");
        }
    };

    stream.heartbeat(Duration::from_secs(30))
}

#[post("/stack", data = "<var>")]
async fn stack(var: StackBatchDto, st: &State<Notifiable<CurrentCallTree>>) -> Result<Status> {
    // info!("{:#?}", var);
    let changed = Arc::clone(&st.changed);

    let ct_ = Arc::clone(&st.inner.ct);
    let syms = Arc::clone(&st.inner.syms);
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
    rocket::routes![
        stack,
        connect,
    ]
}
