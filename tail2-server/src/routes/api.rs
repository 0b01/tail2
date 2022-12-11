use std::rc::Rc;

use rocket::{serde::{json::Json, self}, State, Route, get, response::stream::{EventStream, Event}};
use tail2::{calltree::inner::{serialize::Node, CallTreeFrame}, dto::FrameDto, symbolication::elf::ElfCache};

use crate::state::{CurrentCallTree};

#[get("/current")]
pub async fn current<'a>(ct: &State<CurrentCallTree>) -> String {
    let ct = ct.inner().ct.lock().await;
    let node = Node::new(
        ct.root,
        &ct.arena,
    );

    serde::json::to_string(&node).unwrap()
}

#[get("/events")]
fn events(ct: &State<CurrentCallTree>) -> EventStream![] {
    let changed = ct.changed.clone();
    EventStream! {
        loop {
            yield Event::empty();
            changed.notified().await;
        }
    }
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        current,
        events,
    ]
}