use std::sync::Arc;

use anyhow::Context;
use axum::response::Result;
use axum::{body::Bytes, extract::State};
use tail2::Mergeable;
use tail2::calltree::{CallTree, UnsymbolizedCallTree};
use tail2_db::db::DbRow;

use crate::{state::ServerState, error::AppError};

use tail2::{ dto::StackBatchDto, probes::Probe};

pub(crate) async fn stack(State(state): State<ServerState>, var: Bytes) -> Result<(), AppError> {
    let batch: StackBatchDto = bincode::deserialize(&var).context("cant deserialize")?;
    let probe: Probe = serde_json::from_str(&batch.probe).unwrap();

    let agents = &mut *state.agents.as_ref().lock().await;
    let probe_info = agents
        .get_mut(&batch.hostname).unwrap()
        .probes
        .get_mut(&probe).unwrap();

    let db = &probe_info.db;
    let db_lock = db.as_ref().lock().await;
    let mut modules = db_lock.modules();
    drop(db_lock);

    let mut ts = 0;
    let mut n = 0;
    let mut ct = UnsymbolizedCallTree::default();
    for stack in batch.stacks {
        ts = ts.max(stack.ts_ms as i64);
        n += 1;
        let unsym = stack.mix(&batch.modules, &mut modules);
        ct.merge(&UnsymbolizedCallTree::from_frames(&unsym));
    }

    let db_row = DbRow {
        ts_ms: ts,
        ct,
        n
    };
    db.as_ref().lock().await.insert(vec![db_row]);

    db.notify().notify_one();
    Ok(())
}
