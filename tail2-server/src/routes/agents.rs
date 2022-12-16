use std::{time::Duration, sync::Arc};

use crate::error::Result;
use rocket::{response::stream::{Event}, get, serde::json::Json, State, http::Status};
use rocket::{Route, response::stream::EventStream};
use tail2::{tail2::NewConnection, client::agent_config::AgentConfig};

use crate::{Notifiable, state::Connections};

#[get("/start")]
async fn start(st: &State<Connections>) -> Result<Status> {
    Ok(Status::Ok)
}

#[get("/agents")]
async fn agents(st: &State<Connections>) -> Result<Json<Vec<String>>> {
    let agents = st.agents.lock().await.keys().cloned().collect();
    Ok(Json(agents))
}

#[get("/connect?<new_conn>")]
async fn connect(st: &State<Connections>, new_conn: Json<NewConnection>) -> EventStream![] {
    let config = Notifiable::<AgentConfig>::new(AgentConfig::new());
    let changed = Arc::clone(&config.changed);
    st.agents.lock().await.insert(new_conn.name.to_owned(), config);

    let stream = EventStream!{
        loop {
            changed.notified().await;
            yield Event::data("test");
        }
    };

    stream.heartbeat(Duration::from_secs(30))
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        connect,
        start,
        agents,
    ]
}
