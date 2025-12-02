use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use axum::response::IntoResponse;
use common::batch::LogBatch;
use serde::Serialize;
use sqlx::{SqlitePool};
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
}

#[derive(Serialize)]
struct SubmitResponse {
    status: String,
    message: String,
}

#[tokio::main]
async fn main() {
    // Initialize database pool
    let pool = SqlitePool::connect("sqlite://logchain.db")
        .await
        .unwrap();

    // Create table if not exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prev_hash BLOB NOT NULL,
            logs TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            signature BLOB NOT NULL,
            public_key BLOB NOT NULL
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let state = AppState { pool };

    let app = Router::new()
        .route("/submit", post(handler_submit_batch))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server listening on {}", addr);

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
    // Verify signature first
    if !batch.verify() {
        return Json(SubmitResponse {
            status: "error".into(),
            message: "invalid signature".into(),
        });
    }

    // Serialize logs → JSON
    let logs_json = serde_json::to_string(&batch.logs).unwrap();

    // Insert into SQLite append-only database
    let _ = sqlx::query(
        r#"
        INSERT INTO batches (prev_hash, logs, timestamp, signature, public_key)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(batch.prev_hash.to_vec())
    .bind(logs_json)
    .bind(batch.timestamp as i64)
    .bind(batch.signature.to_bytes().to_vec())
    .bind(batch.public_key.to_bytes().to_vec())
    .execute(&state.pool)
    .await
    .unwrap();

    Json(SubmitResponse {
        status: "ok".into(),
        message: "batch stored".into(),
    })
}
