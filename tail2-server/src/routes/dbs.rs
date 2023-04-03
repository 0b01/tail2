//! returns a list of all databases

use axum::response::Result;
use axum::extract::State;

use crate::state::ServerState;

pub(crate) async fn dbs(State(st): State<ServerState>) -> Result<String> {
    let manager = st.manager.lock().await;
    let map = serde_json::to_string(&manager.dbs).unwrap();
    Ok(map)
}
