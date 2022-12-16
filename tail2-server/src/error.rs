use rocket::response::{self, Responder};
use rocket::Request;

#[derive(Debug)]
pub struct Error(pub anyhow::Error);

impl<E> From<E> for Error
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Error(error.into())
    }
}

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        let response = response::status::BadRequest(Some(self.0.to_string()));
        response.respond_to(request)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
