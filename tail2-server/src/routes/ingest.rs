use anyhow::Context;
use axum::{response::Result, debug_handler};
use tracing::info;
use std::{sync::Arc};
use axum::{body::Bytes, extract::State};

use crate::{state::{AppState}, error::AppError};

use tail2::{
    calltree::{inner::CallTreeInner},
    dto::{StackBatchDto, build_stack},
    Mergeable
};

pub(crate) async fn stack(State(st): State<Arc<AppState>>, var: Bytes) -> Result<(), AppError> {
    // info!("{:#?}", var);
    let st = &st.calltree;
    let var: StackBatchDto = bincode::deserialize(&var).context("cant deserialize")?;
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
