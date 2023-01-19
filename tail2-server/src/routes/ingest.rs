use anyhow::Context;
use axum::{response::Result};
use axum::{body::Bytes, extract::State};

use crate::{state::{ServerState}, error::AppError};

use tail2::{ dto::{StackBatchDto}, probes::Probe};

pub(crate) async fn stack(State(state): State<ServerState>, var: Bytes) -> Result<(), AppError> {
    let calltree = &state.calltree;
    let batch: StackBatchDto = bincode::deserialize(&var).context("cant deserialize")?;
    let probe: Probe = serde_json::from_str(&batch.probe).unwrap();

    let agents = &mut *state.agents.as_ref().lock().await;
    let probe_info = agents
        .get_mut(&batch.hostname).unwrap()
        .probes
        .get_mut(&probe).unwrap();

    let notify = calltree.notify();
    calltree.as_ref().lock().await.add_stacks(batch, notify);
    Ok(())
}
