use axum::{
    extract::State,
    routing::MethodRouter,
    Json, Router,
};
use axum::response::IntoResponse;
use common::batch::LogBatch;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    storage: Arc<Mutex<Vec<LogBatch>>>,
}

#[derive(Serialize)]
struct SubmitResponse {
    status: String,
    message: String,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        storage: Arc::new(Mutex::new(Vec::new())),
    };

    let submit_route =
        MethodRouter::new().post(handler_submit_batch);

    let app = Router::new()
        .route("/submit", submit_route)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!(" Server listening on {}", addr);

    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app,
    )
    .await
    .unwrap();
}

async fn handler_submit_batch(
    State(state): State<AppState>,
    Json(batch): Json<LogBatch>,
) -> impl IntoResponse {
    submit_batch(state, batch).await
}

async fn submit_batch(
    state: AppState,
    batch: LogBatch,
) -> impl IntoResponse {
    if !batch.verify() {
        return Json(SubmitResponse {
            status: "error".into(),
            message: "invalid signature".into(),
        });
    }

    {
        let mut storage = state.storage.lock().unwrap();
        storage.push(batch);
    }

    Json(SubmitResponse {
        status: "ok".into(),
        message: "batch stored".into(),
    })
}
