

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct LoginState {
    logged_in: bool,
    username: String,
}

// pub(crate) async fn sample_json() -> Option<NamedFile> {
//     NamedFile::open(relative!("./flamegraph/data/sample.txt"))
//         .await
//         .ok()
// }

// pub(crate) async fn app() -> Option<NamedFile> {
//     NamedFile::open(relative!("./flamegraph/app.html"))
//         .await
//         .ok()
// }

// pub(crate) async fn dashboard() -> Option<NamedFile> {
//     NamedFile::open(relative!("./flamegraph/dashboard.html"))
//         .await
//         .ok()
// }

// pub(crate) async fn index() -> Option<NamedFile> {
//     NamedFile::open(relative!("./flamegraph/index.html"))
//         .await
//         .ok()
// }