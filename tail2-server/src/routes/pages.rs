use rocket::{Route, get};
use rocket_dyn_templates::Template;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Default)]
struct LoginState {
    logged_in: bool,
    username: String,
}


#[get("/")]
fn index() -> Template {
    let context = LoginState::default();
    Template::render("index", context)
}


pub fn routes() -> Vec<Route> {
    rocket::routes![
        index,
    ]
}