use rocket::{post, http::Status, Route};
use crate::error::Result;

#[post("/stack")]
fn stack() -> Result<Status> {
    Ok(Status::Ok)
}


pub fn routes() -> Vec<Route> {
    rocket::routes![
        stack,
    ]
}