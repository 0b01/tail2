use axum::{response::Result, debug_handler};
use std::{path::PathBuf, sync::Arc, time::Duration};
use axum::{Router, routing::post, body::Bytes, extract::State};
use tokio::sync::Mutex;
use crate::state::{CurrentCallTree, AppState};
use log::info;
use tail2::{
    calltree::{inner::CallTreeInner, CodeType, ResolvedFrame},
    dto::{FrameDto, StackBatchDto, StackDto, build_stack},
    symbolication::{elf::ElfCache, module::Module},
    Mergeable, client::agent_config::AgentConfig
};

#[debug_handler]
pub(crate) async fn stack(State(st): State<Arc<AppState>>, var: Bytes) -> Result<()> {
    // info!("{:#?}", var);
    let st = &st.calltree;
    let var: StackBatchDto = bincode::deserialize(&var).unwrap();
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

    Ok(())
}
