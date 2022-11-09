use rocket::{serde::{json::Json, self}, State, Route, get};
use tail2::{calltree::frames::{serialize::Node, CallTreeFrame}, dto::FrameDto};

use crate::state::CurrentCallTree;

#[get("/current")]
pub fn current<'a>(ct: &State<CurrentCallTree>) -> String {
    let ct = ct.inner().ct.lock().unwrap();
    let node = Node::new(
        ct.root,
        &ct.arena
    );
    let val = serde::json::to_string(&node).unwrap();
    val
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        current,
    ]
}