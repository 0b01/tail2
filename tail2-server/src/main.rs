use rocket::fs::{FileServer, relative};
use rocket_dyn_templates::Template;

extern crate rocket;

pub mod routes;
pub mod error;

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

    let r = rocket::build();
    let r = r.mount("/", FileServer::from(relative!("./flamegraph")));
    let r = r.attach(Template::fairing());
    let r = r.mount("/", routes::routes());

    let _ = r.launch().await.unwrap();
}