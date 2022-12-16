use axum::response::Result;
use std::{time::Duration, sync::Arc};

use axum::{Router, extract::State};
use tail2::{tail2::NewConnection, client::agent_config::AgentConfig};
use axum::routing::get;

use crate::{Notifiable, state::Connections};

#[axum::debug_handler]
pub(crate) async fn start(State(st): State<Arc<Connections>>, name: String) -> Result<()> {
    // let agent = st.agents.lock().await.get(name)?.inner;
    // agent.process(diff, state);
    Ok(())
}

#[axum::debug_handler]
pub(crate) async fn agents(State(st): State<Arc<Connections>>) -> Result<String> {
    let map = serde_json::to_string(&*st.agents.lock().await).unwrap();
    Ok(map)
}

// #[get("/connect?<new_conn>")]
// async fn connect(st: &State<Connections>, new_conn: Json<NewConnection>) -> EventStream![] {
//     let config = Notifiable::<AgentConfig>::new(AgentConfig::new());
//     let changed = Arc::clone(&config.changed);
//     st.agents.lock().await.insert(new_conn.name.to_owned(), config);

//     let stream = EventStream!{
//         loop {
//             changed.notified().await;
//             yield Event::data("test");
//         }
//     };

//     stream.heartbeat(Duration::from_secs(30))
// }
