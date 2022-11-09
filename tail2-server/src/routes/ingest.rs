use log::info;
use rocket::{post, http::Status, Route};
use crate::error::Result;

#[post("/stack", data = "<var>")]
fn stack(var: tail2::dto::StackBatchDto) -> Result<Status> {
    info!("{:#?}", var);
    Ok(Status::Ok)
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        stack,
    ]
}