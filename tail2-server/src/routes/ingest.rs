use anyhow::Context;
use axum::{response::Result};
use tracing::info;
use std::{sync::Arc};
use axum::{body::Bytes, extract::State};

use crate::{state::{ServerState}, error::AppError};

use tail2::{
    calltree::{inner::CallTreeInner},
    dto::{StackBatchDto, build_stack},
    Mergeable, probes::Probe
};

pub(crate) async fn stack(State(state): State<ServerState>, var: Bytes) -> Result<(), AppError> {
    let st = &state.calltree;
    let var: StackBatchDto = bincode::deserialize(&var).context("cant deserialize")?;
    let probe: Probe = serde_json::from_str(&var.probe).unwrap();

    let agents = &mut *state.agents.as_ref().lock().await;
    let probe_info = agents
        .get_mut(&var.hostname).unwrap()
        .probes
        .get_mut(&probe).unwrap();
    let metrics = &mut probe_info.metrics;

    let notify = st.notify();

    let ct_ = Arc::clone(&st.as_ref().ct);
    let syms = Arc::clone(&st.as_ref().syms);
    tokio::spawn(async move {
        let mut ct = CallTreeInner::new();
        for stack in var.stacks {
            info!("k{},u{},p{}",
                stack.kernel_frames.len(),
                stack.native_frames.len(),
                stack.python_frames.len(),
            );
            let stack = build_stack(stack, &syms, &var.modules).await;
            ct.merge(&CallTreeInner::from_stack(&stack));
        }
        // info!("{:#?}", ct.root.debug_pretty_print(&ct.arena));
        ct_.lock().await.merge(&ct);
        notify.notify_one();
    });

    Ok(())
}
