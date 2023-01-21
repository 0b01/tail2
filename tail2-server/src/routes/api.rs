use axum::{extract::{State, Query}, response::IntoResponse, http::HeaderMap};
use reqwest::header;
use serde::{Serialize, Deserialize};
use tail2::{calltree::serialize::Node, probes::Probe};
use axum::response::sse::{Event, Sse};
use std::{convert::Infallible, sync::Arc};
use crate::state::ServerState;
use async_stream::{try_stream, AsyncStream};

#[derive(Serialize, Deserialize)]
pub struct CallTreeParams {
    probe: String,
    host_name: String,
}

pub(crate) async fn current<'a>(State(state): State<ServerState>, Query(params): Query<CallTreeParams>) -> String {
    let agents = state.agents.as_ref().lock().await;
    let probe = serde_json::from_str(&params.probe).unwrap();
    let calltree = &agents
        .get(&params.host_name).unwrap()
        .probes
        .get(&probe).unwrap()
        .calltree
        .as_ref()
        .lock().await
        .calltree;
    let node = Node::new(calltree.root, &calltree.arena);

    serde_json::to_string(&node).unwrap()
}

pub(crate) async fn events(State(state): State<ServerState>, Query(params): Query<CallTreeParams>) -> impl IntoResponse {
    let agents = state.agents.as_ref().lock().await;
    let probe = serde_json::from_str(&params.probe).unwrap();
    let notify = agents
        .get(&params.host_name).unwrap()
        .probes
        .get(&probe).unwrap()
        .calltree
        .notify();
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
