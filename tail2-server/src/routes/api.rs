use axum::{extract::{State, Query}, response::IntoResponse, http::HeaderMap};
use reqwest::header;
use serde::{Serialize, Deserialize};
use tail2::{calltree::{serialize::Node, CodeType}};
use axum::response::sse::{Event, Sse};
use tracing::info;
use std::{convert::Infallible, time::SystemTime};
use crate::state::ServerState;
use async_stream::{try_stream, __private::AsyncStream};

#[derive(Serialize, Deserialize)]
pub struct CallTreeParams {
    start: Option<i64>,
    end: Option<i64>,
    probe: Option<String>,
    host_name: Option<String>,
    db: Option<String>,
    filter: Option<String>,
}

// TODO: refactor so we only need db instead of probe + host_name
pub(crate) async fn calltree<'a>(State(state): State<ServerState>, Query(params): Query<CallTreeParams>) -> String {
    let t = SystemTime::now();

    let db = match params.db {
        Some(db) => {
            let manager = state.manager.lock().await;
            manager.dbs.get(&db).unwrap().clone()
        }
        None => {
            let agents = state.agents.lock().await;
            let probe = serde_json::from_str(&params.probe.unwrap()).unwrap();
            let db = agents
                .get(&params.host_name.unwrap()).unwrap()
                .probes
                .get(&probe).unwrap()
                .db
                .clone();
                drop(agents);
            db
        }
    };

    let range = match (params.start, params.end) {
        (Some(start), Some(end)) => (start, end),
        _ => {
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as i64;
            let range = (now - 60 * 1000, now);
            range
        }
    };
    dbg!(range);
    let calltree = db.tail2_db.lock().await.range_query(range).unwrap().calltree.unwrap_or_default();

    let symbols = &mut *state.symbols.lock().await;
    let modules = db.tail2_db.lock().await.modules();
    let mut calltree = calltree.symbolize(symbols, &mut *modules.lock().await);
    if let Some(filter) = &params.filter {
        calltree = calltree.filter(|i|i.code_type == CodeType::Python);
    }

    let node = Node::new(calltree.root, &calltree.arena);

    info!("processed current() in {:?}", t.elapsed().unwrap());
    serde_json::to_string(&node).unwrap()
}

pub(crate) async fn events(State(state): State<ServerState>, Query(params): Query<CallTreeParams>) -> impl IntoResponse {
    let agents = state.agents.lock().await;
    let probe = serde_json::from_str(&params.probe.unwrap()).unwrap();
    let notify = agents
        .get(&params.host_name.unwrap()).unwrap()
        .probes
        .get(&probe).unwrap()
        .notify.clone();
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
