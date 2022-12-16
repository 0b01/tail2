#![allow(unused)]
use rocket::fs::{relative, FileServer};
use rocket_dyn_templates::Template;
use tail2::symbolication::elf::ElfCache;

extern crate rocket;

pub mod error;
pub mod routes;
pub mod state;

fn setup_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(fern::log_file("output.log")?)
        // .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[rocket::main]
async fn main() {
    // let _guard = sentry::init(("https://3fd48b3baff147f6bd7bf7d7164f5e3b@o1369772.ingest.sentry.io/6672951", sentry::ClientOptions {
    //     release: sentry::release_name!(),
    //     ..Default::default()
    // }));

    setup_logger().unwrap();

    let r = rocket::build()
        .mount("/", routes::routes())
        .mount("/", FileServer::from(relative!("./flamegraph")))
        .manage(state::CurrentCallTree::new())
        .attach(Template::fairing());

    let _ = r.launch().await.unwrap();
}
