use rocket::{post, http::Status, Route, tokio};
use tail2::{dto::StackBatchDto, calltree::frames::CallTree};
use crate::error::Result;

#[post("/stack", data = "<var>")]
fn stack(var: StackBatchDto) -> Result<Status> {
    tokio::spawn(async move {
        let mut ct = CallTree::new();
        for stack in var.stacks {
            ct.merge(&CallTree::from_stack(&stack.frames));
        }
    });

    Ok(Status::Ok)
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        stack,
    ]
}