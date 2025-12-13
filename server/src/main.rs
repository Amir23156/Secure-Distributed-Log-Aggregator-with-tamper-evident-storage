use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use common::batch::LogBatch;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Row, SqlitePool};
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
    hash: [u8; 32],
}

#[derive(Debug, Deserialize)]
struct ListParams {
    agent_id: Option<String>,
    since_seq: Option<u64>,
    limit: Option<u64>,
}

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("sqlite://logchain.db")
        .await
        .unwrap();

    // Drop + recreate to ensure schema upgrades for new columns.
    sqlx::query("DROP TABLE IF EXISTS batches")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            prev_hash BLOB NOT NULL,
            hash BLOB NOT NULL,
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

    sqlx::query(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_seq
        ON batches (agent_id, seq);
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

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
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
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitResponse {
                status: "error".into(),
                message: "invalid signature".into(),
            }),
        );
    }

    let computed_hash = batch.compute_hash();
    let logs_json = serde_json::to_string(&batch.logs).unwrap();

    // Validate hash chain + ordering for this agent.
    if let Err(msg) = validate_chain(&state.pool, &batch, &computed_hash).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitResponse {
                status: "error".into(),
                message: msg,
            }),
        );
    }

    sqlx::query(
        r#"
        INSERT INTO batches (agent_id, seq, prev_hash, hash, logs, timestamp, signature, public_key)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&batch.agent_id)
    .bind(batch.seq as i64)
    .bind(batch.prev_hash.to_vec())
    .bind(computed_hash.to_vec())
    .bind(logs_json)
    .bind(batch.timestamp as i64)
    .bind(batch.signature.to_bytes().to_vec())
    .bind(batch.public_key.to_bytes().to_vec())
    .execute(&state.pool)
    .await
    .unwrap();

    (
        StatusCode::CREATED,
        Json(SubmitResponse {
            status: "ok".into(),
            message: "batch stored".into(),
        }),
    )
}

/* ----------------------- GET /batches ----------------------- */

async fn handler_get_all(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<QueryBatch>>, StatusCode> {
    let mut builder = QueryBuilder::new("SELECT * FROM batches");

    let mut first_clause = true;
    if params.agent_id.is_some() || params.since_seq.is_some() {
        builder.push(" WHERE ");
        if let Some(agent) = &params.agent_id {
            builder.push("agent_id = ");
            builder.push_bind(agent);
            first_clause = false;
        }
        if let Some(seq) = params.since_seq {
            if !first_clause {
                builder.push(" AND ");
            }
            builder.push("seq >= ");
            builder.push_bind(seq as i64);
        }
    }

    builder.push(" ORDER BY agent_id ASC, seq ASC");

    if let Some(limit) = params.limit {
        builder.push(" LIMIT ");
        builder.push_bind(limit as i64);
    }

    let rows = builder
        .build()
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
    let agent_id: String = row.get("agent_id");
    let seq: i64 = row.get("seq");
    let prev_hash: Vec<u8> = row.get("prev_hash");
    let hash_vec: Vec<u8> = row.get("hash");
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

    // Convert hashes
    let prev_hash_bytes: [u8; 32] = prev_hash
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let hash: [u8; 32] = hash_vec
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let batch = LogBatch {
        prev_hash: prev_hash_bytes,
        logs,
        timestamp: timestamp as u64,
        agent_id,
        seq: seq as u64,
        signature,
        public_key,
    };

    Ok(QueryBatch { id, batch, hash })
}

async fn validate_chain(pool: &SqlitePool, batch: &LogBatch, computed_hash: &[u8; 32]) -> Result<(), String> {
    use std::convert::TryInto;

    let last_row = sqlx::query(
        "SELECT seq, hash FROM batches WHERE agent_id = ?1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(&batch.agent_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| "failed to check chain state".to_string())?;

    match last_row {
        None => {
            if batch.seq != 1 {
                return Err("first batch for agent must have seq=1".into());
            }
            if batch.prev_hash != [0u8; 32] {
                return Err("first batch prev_hash must be all zeros".into());
            }
        }
        Some(row) => {
            let last_seq: i64 = row.get("seq");
            let last_hash_vec: Vec<u8> = row.get("hash");
            let last_hash: [u8; 32] = last_hash_vec
                .try_into()
                .map_err(|_| "bad stored hash".to_string())?;

            if batch.seq != (last_seq as u64) + 1 {
                return Err(format!(
                    "seq must increment: expected {}, got {}",
                    last_seq + 1,
                    batch.seq
                ));
            }

            if batch.prev_hash != last_hash {
                return Err("prev_hash does not match last hash".into());
            }
        }
    }

    if batch.compute_hash() != *computed_hash {
        return Err("hash mismatch".into());
    }

    Ok(())
}
