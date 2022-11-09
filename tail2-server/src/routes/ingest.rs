use log::info;
use rocket::{post, http::Status, Route};
use tail2::{dto::StackBatchDto, calltree::frames::CallTree};
use crate::error::Result;

#[post("/stack", data = "<var>")]
fn stack(var: StackBatchDto) -> Result<Status> {
    info!("{:#?}", var);

    let mut ct = CallTree::new();
    for stack in var.stacks {
        ct.merge(&CallTree::from_stack(&stack.frames));
    }

    info!("{:#?}", ct.root.debug_pretty_print(&ct.arena));

    Ok(Status::Ok)
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        stack,
    ]
}