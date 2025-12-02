use axum::{
    extract::{State, Path},
    routing::{post, get},
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
};
use common::batch::LogBatch;
use serde::Serialize;
use sqlx::{SqlitePool, Row};
use ed25519_dalek::{Signature, VerifyingKey};
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

#[derive(Serialize)]
struct QueryBatch {
    id: i64,
    batch: LogBatch,
}

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("sqlite://logchain.db")
        .await
        .unwrap();

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
        .route("/batches", get(handler_get_all))
        .route("/batches/:id", get(handler_get_one))
        .with_state(state);

    let addr = SocketAddr::from(([127,0,0,1], 3000));
    println!("Server listening on {}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

/* ----------------------- SUBMIT BATCH ----------------------- */

async fn handler_submit_batch(
    State(state): State<AppState>,
    Json(batch): Json<LogBatch>,
) -> impl IntoResponse {

    if !batch.verify() {
        return Json(SubmitResponse {
            status: "error".into(),
            message: "invalid signature".into(),
        });
    }

    let logs_json = serde_json::to_string(&batch.logs).unwrap();

    sqlx::query(
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

/* ----------------------- GET /batches ----------------------- */

async fn handler_get_all(
    State(state): State<AppState>,
) -> Result<Json<Vec<QueryBatch>>, StatusCode> {

    let rows = sqlx::query("SELECT * FROM batches ORDER BY id ASC")
        .fetch_all(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut results = Vec::new();

    for row in rows {
        results.push(row_to_query_batch(row)?);
    }

    Ok(Json(results))
}

/* ----------------------- GET /batches/:id ----------------------- */

async fn handler_get_one(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<QueryBatch>, StatusCode> {

    let row = sqlx::query("SELECT * FROM batches WHERE id = ?1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let row = match row {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    Ok(Json(row_to_query_batch(row)?))
}

/* ----------------------- Helper: Convert DB row → LogBatch ----------------------- */

fn row_to_query_batch(row: sqlx::sqlite::SqliteRow) -> Result<QueryBatch, StatusCode> {
    use std::convert::TryInto;

    let id: i64 = row.get("id");
    let prev_hash: Vec<u8> = row.get("prev_hash");
    let logs_json: String = row.get("logs");
    let timestamp: i64 = row.get("timestamp");
    let signature_vec: Vec<u8> = row.get("signature");
    let public_key_vec: Vec<u8> = row.get("public_key");

    let logs: Vec<String> = serde_json::from_str(&logs_json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Convert signature
    let sig_bytes: [u8; 64] = signature_vec
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let signature = Signature::from_bytes(&sig_bytes);

    // Convert public key
    let pk_bytes: [u8; 32] = public_key_vec
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let public_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Convert prev_hash
    let prev_hash_bytes: [u8; 32] = prev_hash
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let batch = LogBatch {
        prev_hash: prev_hash_bytes,
        logs,
        timestamp: timestamp as u64,
        signature,
        public_key,
    };

    Ok(QueryBatch { id, batch })
}
