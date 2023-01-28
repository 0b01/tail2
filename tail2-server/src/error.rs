use axum::{response::{IntoResponse, Response}, Json};
use reqwest::StatusCode;
use serde_json::json;

pub enum AppError {
    InternalServerError(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(inner: anyhow::Error) -> Self {
        AppError::InternalServerError(inner)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InternalServerError(inner) => {
                tracing::error!("{:#?}", inner);
                (StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
