use rocket::{serde::json::Json, State, Route, get};
use tail2::{calltree::frames::{serialize::Node, CallTreeFrame}, dto::FrameDto};

use crate::state::CurrentCallTree;

#[get("/current")]
pub fn current<'a>(ct: &'a State<CurrentCallTree>) -> Json<Node<'a, CallTreeFrame<FrameDto>>> {
    let node = Node::new(ct.inner().ct.root, &ct.inner().ct.arena);
    Json(node)
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        current,
    ]
}