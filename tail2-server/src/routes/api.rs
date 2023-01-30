use axum::{extract::{State, Query}, response::IntoResponse, http::HeaderMap};
use reqwest::header;
use serde::{Serialize, Deserialize};
use tail2::{calltree::serialize::Node, probes::Probe};
use axum::response::sse::{Event, Sse};
use tracing::info;
use std::{convert::Infallible, sync::Arc, time::SystemTime, alloc::System};
use crate::state::ServerState;
use async_stream::{try_stream, AsyncStream};

#[derive(Serialize, Deserialize)]
pub struct CallTreeParams {
    probe: String,
    host_name: String,
}

pub(crate) async fn current<'a>(State(state): State<ServerState>, Query(params): Query<CallTreeParams>) -> String {
    let t = SystemTime::now();

    let agents = state.agents.as_ref().lock().await;
    let probe = serde_json::from_str(&params.probe).unwrap();
    let db = agents
        .get(&params.host_name).unwrap()
        .probes
        .get(&probe).unwrap()
        .db
        .clone();
    drop(agents);

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as i64;
    let calltree = db.as_ref().lock().await.range_query((now - 60 * 1000, now)).unwrap().calltree;

    let symbols = &mut *state.symbols.lock().await;
    let mut modules = db.as_ref().lock().await.modules();
    let calltree = calltree.symbolize(symbols, &mut *modules.lock().await);

    let node = Node::new(calltree.root, &calltree.arena);

    info!("current time: {}", SystemTime::now().duration_since(t).unwrap().as_millis());
    serde_json::to_string(&node).unwrap()
}

pub(crate) async fn events(State(state): State<ServerState>, Query(params): Query<CallTreeParams>) -> impl IntoResponse {
    let agents = state.agents.as_ref().lock().await;
    let probe = serde_json::from_str(&params.probe).unwrap();
    let notify = agents
        .get(&params.host_name).unwrap()
        .probes
        .get(&probe).unwrap()
        .db
        .notify();
    drop(agents);
    notify.notify_one();

    let stream = try_stream! {
        loop {
            yield Event::default().data("_");
            notify.notified().await;
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/event-stream;charset=UTF-8".parse().unwrap());
    headers.insert(header::CONTENT_ENCODING, "UTF-8".parse().unwrap());
    (headers, Sse::<AsyncStream<Result<Event, Infallible>, _>>::new(stream))
}
