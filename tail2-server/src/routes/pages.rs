use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct LoginState {
    logged_in: bool,
    username: String,
}