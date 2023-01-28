use axum::{
    body::{Bytes, self, Full, Empty},
    http::{StatusCode, HeaderValue, Response},
    response::IntoResponse,
    routing::{get, post},
    Router, extract::Path};
use reqwest::header;
use tracing::debug;
use std::{net::SocketAddr, time::Duration};
use tower::ServiceBuilder;
use tower_http::{
    trace::{TraceLayer, DefaultOnResponse, DefaultMakeSpan}, ServiceBuilderExt, timeout::TimeoutLayer, LatencyUnit,
};
use state::ServerState;

pub mod error;
pub mod routes;
pub mod state;
pub use state::notifiable::Notifiable;

#[cfg(feature="deploy")]
static STATIC_DIR: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/static");

#[tokio::main]
async fn main() {
    // let _guard = sentry::init(("https://3fd48b3baff147f6bd7bf7d7164f5e3b@o1369772.ingest.sentry.io/6672951", sentry::ClientOptions {
    //     release: sentry::release_name!(),
    //     ..Default::default()
    // }));

    let appender = tracing_appender::rolling::never("./", "output.log");
    let (non_blocking_appender, _guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking_appender)
        .with_ansi(false)
        .init();

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
        .route("/api/agent/events", get(routes::agents::agent_events))
        .route("/api/agent/start_probe", get(routes::agents::start_probe))
        .route("/api/agent/stop_probe", get(routes::agents::stop_probe))
        .route("/api/agent/halt", get(routes::agents::halt))
        .route("/api/agents", get(routes::agents::agents))
        .route("/api/current", get(routes::api::current))
        .route("/api/stack", post(routes::ingest::stack))
        .route("/api/events", get(routes::api::events))
        .route("/api/connect", get(routes::agents::on_connect))

        .route("/dashboard", get(||static_path("dashboard", Path("index.html".to_owned()))))

        .route("/", get(|| static_path(".", Path("/index.html".to_owned()))))

        .route("/flamegraph/app.html", get(|| static_path("flamegraph", Path("/app.html".to_owned()))))

        // wildcards
        .route("/dashboard/*path", get(|p|static_path("dashboard", p)))
        .route("/*path", get(|p|static_path(".", p)))

        .layer(middleware)
        .with_state(ServerState::new());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    tracing::warn!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn static_path(prefix: &str, Path(path): Path<String>) -> impl IntoResponse {
    let path = path.trim_start_matches('/');
    let mime_type = mime_guess::from_path(path).first_or_text_plain();

    #[cfg(not(feature="deploy"))]
    {
        use std::{path::PathBuf, fs::File, io::Read};
        // dbg!(path);
        let path = PathBuf::from(format!("./tail2-server/static/{}/{}", prefix, path)).canonicalize().unwrap();
        if path.exists() {
            let mut buf = vec![];
            File::open(path).unwrap().read_to_end(&mut buf).unwrap();
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(mime_type.as_ref()).unwrap(),
                )
                .body(body::boxed(Full::from(buf)))
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(body::boxed(Empty::new()))
                .unwrap()
        }
    }

    #[cfg(feature="deploy")]
    {
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
}