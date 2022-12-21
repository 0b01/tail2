use std::{sync::Arc};

use axum::{extract::State, response::IntoResponse, http::HeaderMap};
use reqwest::header;
use tail2::{
    calltree::inner::{serialize::Node},
};
use axum::{
    response::sse::{Event, Sse},
};
use std::{convert::Infallible};




use crate::{state::{AppState}};

pub(crate) async fn current<'a>(State(ct): State<Arc<AppState>>) -> String {
    let ct = ct.calltree.inner.ct.lock().await;
    let node = Node::new(ct.root, &ct.arena);

    serde_json::to_string(&node).unwrap()
}

use async_stream::{try_stream, AsyncStream};

pub(crate) async fn events(State(ct): State<Arc<AppState>>) -> impl IntoResponse {
    let changed = ct.calltree.changed.clone();
    changed.notify_one();
    let stream = try_stream! {
        loop {
            yield Event::default().data("_");
            changed.notified().await;
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/event-stream;charset=UTF-8".parse().unwrap());
    headers.insert(header::CONTENT_ENCODING, "UTF-8".parse().unwrap());
    (headers, Sse::<AsyncStream<Result<Event, Infallible>, _>>::new(stream))
}
