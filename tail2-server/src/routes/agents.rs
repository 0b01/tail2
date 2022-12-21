use axum::{response::{Result, IntoResponse}, extract::{WebSocketUpgrade, ws::{WebSocket, Message}, Query}};
use futures::{StreamExt, SinkExt};

use tokio::{sync::mpsc::{self, UnboundedReceiver}};
use std::{sync::Arc};

use axum::{extract::State};
use tail2::{client::agent_config::{AgentConfig, AgentMessage, NewConnection, StartAgent}, probes::{PerfProbe, Scope, Probe}};


use crate::{state::AppState};

pub(crate) async fn agents(State(st): State<Arc<AppState>>) -> Result<String> {
    let agents = &*st.agents.lock().await;
    let map = serde_json::to_string(agents).unwrap();
    Ok(map)
}

pub(crate) async fn on_connect(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>, new_conn: Query<NewConnection>) -> impl IntoResponse {
    let (tx, rx) = mpsc::unbounded_channel::<AgentMessage>();
    let config = AgentConfig::new(tx);
    tracing::info!("new agent: {}", new_conn.name);
    let mut agents = state.agents.lock().await;
    let name = new_conn.name.to_owned();
    let _i = agents.insert(name.clone(), config);
    drop(agents);

    ws.on_upgrade(|socket| connect_ws(socket, state, name, rx))
}

async fn connect_ws(stream: WebSocket, state: Arc<AppState>, name: String, mut rx: UnboundedReceiver<AgentMessage>) {
    let (mut sender, mut receiver) = stream.split();
    let name = name.to_owned();

    // receiver
    tokio::spawn(async move {
        while let Some(Ok(Message::Text(msg))) = receiver.next().await {
            let diff = serde_json::from_str(&msg).unwrap();
            let mut agents = state.agents.lock().await;
            let agt = agents.get_mut(&name).unwrap();
            agt.process(&diff).unwrap();
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

pub(crate) async fn start_probe(State(st): State<Arc<AppState>>, start_agent: Query<StartAgent>) -> Result<String> {
    let agents = st.agents.lock().await;
    let agt = agents.get(&start_agent.name).unwrap();
    let tx = agt.tx.as_ref().unwrap().clone();
    let probe = start_agent.probe.clone().unwrap_or_else(||
        Probe::Perf(PerfProbe{
            scope: Scope::Pid(375573),
            period: 400000,
        })
    );

    tx.send(AgentMessage::AddProbe { probe }).unwrap();

    Ok(String::from(""))
}

pub(crate) async fn stop_probe(State(st): State<Arc<AppState>>, start_agent: Query<StartAgent>) -> Result<String> {
    let agents = st.agents.lock().await;
    let agt = agents.get(&start_agent.name).unwrap();
    let tx = agt.tx.as_ref().unwrap().clone();
    let probe = start_agent.probe.clone().unwrap_or_else(||
        Probe::Perf(PerfProbe{
            scope: Scope::Pid(375573),
            period: 400000,
        })
    );

    tx.send(AgentMessage::StopProbe { probe }).unwrap();

    Ok(String::from(""))
}