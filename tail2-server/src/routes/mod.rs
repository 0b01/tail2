use rocket::Route;

pub mod ingest;
pub mod pages;

pub(crate) fn routes() -> Vec<Route> {
    let mut routes = vec![];
    routes.append(&mut ingest::routes());
    routes.append(&mut pages::routes());
    routes
}