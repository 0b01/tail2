use axum::{response::{Result, IntoResponse}, extract::{WebSocketUpgrade, ws::{WebSocket, Message}, Query}, Json};
use futures::{StreamExt, SinkExt};
use tokio::time::sleep;
use std::{time::Duration, sync::Arc};

use axum::{Router, extract::State};
use tail2::{tail2::NewConnection, client::agent_config::AgentConfig};
use axum::routing::get;

use crate::{Notifiable, state::AppState};

#[axum::debug_handler]
pub(crate) async fn start(State(st): State<Arc<AppState>>, name: String) -> Result<()> {
    // let agent = st.agents.lock().await.get(name)?.inner;
    // agent.process(diff, state);
    Ok(())
}

#[axum::debug_handler]
pub(crate) async fn agents(State(st): State<Arc<AppState>>) -> Result<String> {
    let map = serde_json::to_string(&*st.agents.lock().await).unwrap();
    Ok(map)
}

pub(crate) async fn connect(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>, new_conn: Query<NewConnection>) -> impl IntoResponse {
    let config = Notifiable::<AgentConfig>::new(AgentConfig::new());
    let changed = Arc::clone(&config.changed);
    tracing::info!("new agent: {}", new_conn.name);
    let mut agents = state.agents.lock().await;
    let i = agents.insert(new_conn.name.to_owned(), config);
    drop(agents);

    ws.on_upgrade(|socket| connect_ws(socket, state))
}

async fn connect_ws(stream: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = stream.split();

    let mut send_task = tokio::spawn(
        receiver.for_each(|msg| async {
            let msg = msg.unwrap();
            dbg!(msg);
        }));

    loop {
        let _ = sender
            .send(Message::Text(String::from("test.")))
            .await;
        sleep(Duration::from_secs(1)).await;
    }
}

/*

async fn websocket(stream: WebSocket, state: Arc<AppState>) {
    // By splitting we can send and receive at the same time.
    let (mut sender, mut receiver) = stream.split();

    // Username gets set in the receive loop, if it's valid.
    let mut username = String::new();
    // Loop until a text message is found.
    while let Some(Ok(message)) = receiver.next().await {
        if let Message::Text(name) = message {
            // If username that is sent by client is not taken, fill username string.
            check_username(&state, &mut username, &name);

            // If not empty we want to quit the loop else we want to quit function.
            if !username.is_empty() {
                break;
            } else {
                // Only send our client that username is taken.
                let _ = sender
                    .send(Message::Text(String::from("Username already taken.")))
                    .await;

                return;
            }
        }
    }

    // Subscribe before sending joined message.
    let mut rx = state.tx.subscribe();

    // Send joined message to all subscribers.
    let msg = format!("{} joined.", username);
    tracing::debug!("{}", msg);
    let _ = state.tx.send(msg);

    // This task will receive broadcast messages and send text message to our client.

    // Clone things we want to pass to the receiving task.
    let tx = state.tx.clone();
    let name = username.clone();

    // This task will receive messages from client and send them to broadcast subscribers.
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            // Add username before message.
            let _ = tx.send(format!("{}: {}", name, text));
        }
    });

    // If any one of the tasks exit, abort the other.
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    // Send user left message.
    let msg = format!("{} left.", username);
    tracing::debug!("{}", msg);
    let _ = state.tx.send(msg);
    // Remove username from map so new clients can take it.
    state.user_set.lock().unwrap().remove(&username);
}

*/