


use std::time::SystemTime;

use anyhow::Context;
use axum::response::Result;
use axum::{body::Bytes, extract::State};
use tail2::Mergeable;
use tail2::calltree::{UnsymbolizedCallTree};
use tail2_db::db::DbRow;
use tracing::info;


use crate::{state::ServerState, error::AppError};

use tail2::{ dto::StackBatchDto, probes::Probe};

pub(crate) async fn stack(State(state): State<ServerState>, var: Bytes) -> Result<(), AppError> {
    let now = SystemTime::now();
    let batch: StackBatchDto = bincode::deserialize(&var).context("cant deserialize")?;
    let probe: Probe = serde_json::from_str(&batch.probe).unwrap();

    let agents = &mut *state.agents.lock().await;
    let probe_state = agents
        .get(&batch.hostname).unwrap()
        .probes
        .get(&probe).unwrap();
    let db = probe_state.db.clone();
    let notify = probe_state.notify.clone();

    let modules = db.tail2_db.lock().await.modules();
    let mut modules = modules.lock().await;

    let mut ts = 0;
    let mut n = 0;
    let mut ct = UnsymbolizedCallTree::default();
    for stack in batch.stacks {
        ts = ts.max(stack.ts_ms as i64);
        n += 1;
        let unsym = stack.mix(&batch.modules, &mut *modules);
        ct.merge(&UnsymbolizedCallTree::from_frames(&unsym));
    }

    let db_row = DbRow {
        ts_ms: ts,
        ct: Some(ct),
        n
    };

    db.tail2_db.lock().await.insert(vec![db_row]).unwrap();

    notify.notify_one();

    info!("ingested {} stacks in {:?}", n, now.elapsed().unwrap());

    Ok(())
}