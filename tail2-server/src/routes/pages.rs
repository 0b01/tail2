use rocket::{Route, get, fs::NamedFile};
use rocket::fs::relative;
use rocket_dyn_templates::Template;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Default)]
struct LoginState {
    logged_in: bool,
    username: String,
}

#[get("/sample.json")]
async fn sample_json() -> Option<NamedFile> {
    NamedFile::open(relative!("./flamegraph/data/sample.txt")).await.ok()
}

#[get("/app")]
async fn app() -> Option<NamedFile> {
    NamedFile::open(relative!("./flamegraph/app.html")).await.ok()
}

#[get("/")]
async fn index() -> Option<NamedFile> {
    NamedFile::open(relative!("./flamegraph/index.html")).await.ok()
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        index,
        app,
        sample_json,
    ]
}