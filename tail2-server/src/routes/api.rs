use std::{rc::Rc, sync::Arc};

use axum::{extract::State, debug_handler, response::IntoResponse, http::HeaderMap};
use reqwest::header;
use tail2::{
    calltree::inner::{serialize::Node, CallTreeFrame},
    dto::FrameDto,
    symbolication::elf::ElfCache,
};
use axum::{
    Router,
    routing::get,
    response::sse::{Event, KeepAlive, Sse},
};
use std::{time::Duration, convert::Infallible};
use tokio_stream::StreamExt as _ ;
use futures::stream::{self, Stream};


use crate::{state::{CurrentCallTree, AppState}, Notifiable};

pub(crate) async fn current<'a>(State(ct): State<Arc<AppState>>) -> String {
    let ct = ct.calltree.inner.ct.lock().await;
    let node = Node::new(ct.root, &ct.arena);

    serde_json::to_string(&node).unwrap()
}

use async_stream::{stream, try_stream, AsyncStream};

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
