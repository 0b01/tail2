use include_dir::{include_dir, Dir};
use axum::{
    body::{Bytes, self, Full, Empty},
    http::{StatusCode, HeaderValue, Response},
    response::IntoResponse,
    routing::{get, post},
    Router, extract::Path,
};
use reqwest::header;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower::{ServiceBuilder};
use tower_http::{
    trace::{TraceLayer, DefaultOnResponse, DefaultMakeSpan}, ServiceBuilderExt, timeout::TimeoutLayer, LatencyUnit,
};
use state::ServerState;


pub mod error;
pub mod routes;
pub mod state;
pub use state::notifiable::Notifiable;

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/flamegraph");

#[tokio::main]
async fn main() {
    // let _guard = sentry::init(("https://3fd48b3baff147f6bd7bf7d7164f5e3b@o1369772.ingest.sentry.io/6672951", sentry::ClientOptions {
    //     release: sentry::release_name!(),
    //     ..Default::default()
    // }));

    tracing_subscriber::fmt::init();

    // Build our middleware stack
    let middleware = ServiceBuilder::new()
        // Add high level tracing/logging to all requests
        .layer(
            TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                })
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros)),
        )
        // Set a timeout
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        // Box the response body so it implements `Default` which is required by axum
        .map_response_body(axum::body::boxed)
        // Compress responses
        .compression();

    let app = Router::new()
        .route("/agent/start_probe", get(routes::agents::start_probe))
        .route("/agent/stop_probe", get(routes::agents::stop_probe))
        .route("/agent/halt", get(routes::agents::halt))
        .route("/agents", get(routes::agents::agents))
        .route("/current", get(routes::api::current))
        .route("/stack", post(routes::ingest::stack))
        .route("/events", get(routes::api::events))
        .route("/connect", get(routes::agents::on_connect))

        .route("/*path", get(static_path))
        .route("/app", get(|| static_path(Path("/app.html".to_owned()))))
        .route("/", get(|| static_path(Path("/index.html".to_owned()))))
        .route("/dashboard", get(|| static_path(Path("/dashboard.html".to_owned()))))
        .route("/sample.json", get(|| static_path(Path("/data/sample.txt".to_owned()))))

        .layer(middleware)
        .with_state(Arc::new(ServerState::new()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn static_path(Path(path): Path<String>) -> impl IntoResponse {
    let path = path.trim_start_matches('/');
    let mime_type = mime_guess::from_path(path).first_or_text_plain();

    match STATIC_DIR.get_file(path) {
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(body::boxed(Empty::new()))
            .unwrap(),
        Some(file) => Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime_type.as_ref()).unwrap(),
            )
            .body(body::boxed(Full::from(file.contents())))
            .unwrap(),
    }
}
