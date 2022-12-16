use std::{time::Duration, sync::Arc};

use crate::error::Result;
use rocket::{response::stream::{Event}, get, serde::json::{Json, self}, State, http::Status};
use rocket::{Route, response::stream::EventStream};
use tail2::{tail2::NewConnection, client::agent_config::AgentConfig};

use crate::{Notifiable, state::Connections};

#[get("/start?<name>")]
async fn start(st: &State<Connections>, name: &str) -> Result<Status> {
    // let agent = st.agents.lock().await.get(name)?.inner;
    // agent.process(diff, state);
    Ok(Status::Ok)
}

#[get("/agents")]
async fn agents(st: &State<Connections>) -> Result<String> {
    let map = json::to_string(&*st.agents.lock().await)?;
    Ok(map)
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
