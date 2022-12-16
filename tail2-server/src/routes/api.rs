use std::rc::Rc;

use rocket::{
    get,
    response::stream::{Event, EventStream},
    serde::{self, json::Json},
    Route, State,
};
use tail2::{
    calltree::inner::{serialize::Node, CallTreeFrame},
    dto::FrameDto,
    symbolication::elf::ElfCache,
};

use crate::{state::CurrentCallTree, Notifiable};

#[get("/current")]
pub async fn current<'a>(ct: &State<Notifiable<CurrentCallTree>>) -> String {
    let ct = ct.inner().inner.ct.lock().await;
    let node = Node::new(ct.root, &ct.arena);

    serde::json::to_string(&node).unwrap()
}

#[get("/events")]
fn events(ct: &State<Notifiable<CurrentCallTree>>) -> EventStream![] {
    let changed = ct.changed.clone();
    EventStream! {
        loop {
            yield Event::empty();
            changed.notified().await;
        }
    }
}

pub fn routes() -> Vec<Route> {
    rocket::routes![current, events,]
}
