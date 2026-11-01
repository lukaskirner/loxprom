use std::sync::Arc;

use axum::{Router, extract::State, http::header, response::IntoResponse, routing::get};

use crate::store::Store;

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(|| async { "ok\n" }))
        .with_state(store)
}

async fn metrics(State(store): State<Arc<Store>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        store.render(),
    )
}
