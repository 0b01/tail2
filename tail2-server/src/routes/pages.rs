use rocket::fs::relative;
use rocket::{fs::NamedFile, get, Route};
use rocket_dyn_templates::Template;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct LoginState {
    logged_in: bool,
    username: String,
}

#[get("/sample.json")]
async fn sample_json() -> Option<NamedFile> {
    NamedFile::open(relative!("./flamegraph/data/sample.txt"))
        .await
        .ok()
}

#[get("/app")]
async fn app() -> Option<NamedFile> {
    NamedFile::open(relative!("./flamegraph/app.html"))
        .await
        .ok()
}

#[get("/dashboard")]
async fn dashboard() -> Option<NamedFile> {
    NamedFile::open(relative!("./flamegraph/dashboard.html"))
        .await
        .ok()
}

#[get("/")]
async fn index() -> Option<NamedFile> {
    NamedFile::open(relative!("./flamegraph/index.html"))
        .await
        .ok()
}

pub fn routes() -> Vec<Route> {
    rocket::routes![index, app, dashboard, sample_json,]
}
