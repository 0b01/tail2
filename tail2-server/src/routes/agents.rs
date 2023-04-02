use async_stream::{try_stream, __private::AsyncStream};
use axum::{response::{Result, IntoResponse, sse::Event, Sse}, extract::{WebSocketUpgrade, ws::{WebSocket, Message}, Query}, http::HeaderMap};
use futures::{StreamExt, SinkExt};

use reqwest::header;
use tokio::{sync::mpsc::{self, UnboundedReceiver}};
use std::{convert::Infallible, sync::Arc};

use axum::{extract::State};
use tail2::{client::ws_client::messages::{AgentMessage, NewConnection, StartAgent, HaltAgent}};


use crate::{state::{ServerState, Tail2Agent}};

pub(crate) async fn agents(State(st): State<ServerState>) -> Result<String> {
    let agents = &*st.agents.lock().await;
    let map = serde_json::to_string(agents).unwrap();
    Ok(map)
}

pub(crate) async fn on_connect(ws: WebSocketUpgrade, State(state): State<ServerState>, new_conn: Query<NewConnection>) -> impl IntoResponse {
    let (tx, rx) = mpsc::unbounded_channel::<AgentMessage>();
    let config = Tail2Agent::new(tx);
    tracing::info!("new agent: {}", new_conn.hostname);
    let mut agents = state.agents.lock().await;
    let name = new_conn.hostname.to_owned();
    let _i = agents.insert(name.clone(), config);
    drop(agents);

    ws.on_upgrade(|socket| connect_ws(socket, state, name, rx))
}

async fn connect_ws(stream: WebSocket, state: ServerState, name: String, mut rx: UnboundedReceiver<AgentMessage>) {
    let (mut sender, mut receiver) = stream.split();
    let name = name;

    // receiver
    tokio::spawn(async move {
        while let Some(Ok(Message::Text(msg))) = receiver.next().await {
            let diff = serde_json::from_str(&msg).unwrap();
            let mut agents = state.agents.lock().await;
            let agt = agents.get_mut(&name).unwrap();
            let manager = Arc::clone(&state.manager);
            agt.process(&diff, manager).await.unwrap();
            state.agents.notify_one();
        }});

    // sender
    tokio::spawn(async move {
        while let Some(diff) = rx.recv().await {
            let msg = serde_json::to_string(&diff).unwrap();
            sender
                .send(Message::Text(msg))
                .await.unwrap();
        }
    });
}

pub(crate) async fn start_probe(State(st): State<ServerState>, start_agent: Query<StartAgent>) -> Result<String> {
    let agents = st.agents.lock().await;
    let agt = agents.get(&start_agent.name).unwrap();
    let tx = agt.tx.as_ref().unwrap().clone();
    let probe = serde_json::from_str(&start_agent.probe).unwrap();

    tx.send(AgentMessage::AddProbe { probe }).unwrap();

    Ok(String::from(""))
}

pub(crate) async fn stop_probe(State(st): State<ServerState>, stop_agent: Query<StartAgent>) -> Result<String> {
    let agents = st.agents.lock().await;
    let agt = agents.get(&stop_agent.name).unwrap();
    let tx = agt.tx.as_ref().unwrap().clone();
    let probe = serde_json::from_str(&stop_agent.probe).unwrap();

    tx.send(AgentMessage::StopProbe { probe }).unwrap();

    Ok(String::from(""))
}

pub(crate) async fn halt(State(st): State<ServerState>, start_agent: Query<HaltAgent>) -> Result<String> {
    let agents = st.agents.lock().await;
    let agt = agents.get(&start_agent.name).unwrap();
    let tx = agt.tx.as_ref().unwrap().clone();

    tx.send(AgentMessage::Halt).unwrap();

    Ok(String::from(""))
}

pub(crate) async fn agent_events(State(st): State<ServerState>) -> impl IntoResponse {
    st.agents.notify_one();
    let nofity = st.agents.notify();
    let stream = try_stream! {
        loop {
            yield Event::default().data("_");
            nofity.notified().await;
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/event-stream;charset=UTF-8".parse().unwrap());
    headers.insert(header::CONTENT_ENCODING, "UTF-8".parse().unwrap());
    (headers, Sse::<AsyncStream<Result<Event, Infallible>, _>>::new(stream))
}
