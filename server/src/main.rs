use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use common::batch::LogBatch;
use ed25519_dalek::{Signature, VerifyingKey};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, Transaction};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::env;
use std::collections::HashMap;
use std::time::{Duration as StdDuration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{self, Duration};
use tokio::sync::Mutex;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    require_registration: bool,
    rate_limiter: Arc<RateLimiter>,
    auth_token: Option<String>,
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
    offset: Option<u64>,
    since_timestamp: Option<u64>,
    until_timestamp: Option<u64>,
    log_substring: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportParams {
    since_id: Option<i64>,
    limit: Option<u64>,
}

#[derive(Serialize)]
struct AgentCheckpoint {
    agent_id: String,
    last_seq: u64,
    last_hash: [u8; 32],
    count: u64,
}

fn log_submit_error(agent: &str, reason: &str) {
    eprintln!("submit rejected for agent {}: {}", agent, reason);
}

fn valid_auth(headers: &HeaderMap, expected: &str) -> bool {
    if let Some(hv) = headers.get("authorization") {
        if let Ok(v) = hv.to_str() {
            let pref = "Bearer ";
            if let Some(rest) = v.strip_prefix(pref) {
                return rest == expected;
            }
        }
    }
    false
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    agent_id: String,
    public_key_hex: String,
}

#[derive(Debug, Deserialize)]
struct RotateRequest {
    agent_id: String,
    new_public_key_hex: String,
    auth_signature_hex: String,
}

#[derive(Serialize)]
struct AgentResponse {
    status: String,
    message: String,
}

#[tokio::main]
async fn main() {
    let require_registration = std::env::var("REQUIRE_AGENT_REGISTRATION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let max_req_per_window = env::var("RATE_LIMIT_MAX")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(200);
    let window_secs = env::var("RATE_LIMIT_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);

    let rate_limiter = Arc::new(RateLimiter::new(
        max_req_per_window,
        StdDuration::from_secs(window_secs),
    ));

    let auth_token = env::var("SUBMIT_BEARER_TOKEN").ok();

    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://logchain.db".to_string());
    let pool = SqlitePool::connect(&db_url)
        .await
        .unwrap();

    configure_sqlite(&pool).await;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            prev_hash BLOB NOT NULL,
            hash BLOB NOT NULL,
            logs TEXT NOT NULL,
            logs_compressed BLOB,
            timestamp INTEGER NOT NULL,
            signature BLOB NOT NULL,
            public_key BLOB NOT NULL,
            received_at INTEGER NOT NULL DEFAULT 0,
            source TEXT
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            public_key BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    ensure_column(&pool, "batches", "received_at", "INTEGER NOT NULL DEFAULT 0").await;
    ensure_column(&pool, "batches", "source", "TEXT").await;
    ensure_column(&pool, "batches", "logs_compressed", "BLOB").await;
    ensure_append_only_triggers(&pool).await;

    sqlx::query(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_seq
        ON batches (agent_id, seq);
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_hash
        ON batches (agent_id, hash);
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_batches_agent_ts
        ON batches (agent_id, timestamp);
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_batches_ts
        ON batches (timestamp);
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    if let Ok(backup_path) = std::env::var("SQLITE_BACKUP_PATH") {
        let interval_secs = std::env::var("SQLITE_BACKUP_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300);
        let pool_clone = pool.clone();
        let backup_path_task = backup_path.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                if let Err(err) = snapshot_database(&pool_clone, &backup_path_task).await {
                    eprintln!("Failed to snapshot database: {err}");
                }
            }
        });
        println!(
            "Periodic SQLite snapshots enabled every {}s to {}",
            interval_secs, backup_path
        );
    }

    let state = AppState {
        pool,
        require_registration,
        rate_limiter,
        auth_token,
    };

    let app = Router::new()
        .route("/submit", post(handler_submit_batch))
        .route("/agents/register", post(handler_register_agent))
        .route("/agents/rotate", post(handler_rotate_agent))
        .route("/batches", get(handler_get_all))
        .route("/batches/checkpoints", get(handler_checkpoints))
        .route("/batches/export", get(handler_export))
        .route("/batches/:id", get(handler_get_one))
        .with_state(state);

    let bind_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let addr: SocketAddr = bind_addr
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 3000)));
    println!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

/* ----------------------- SUBMIT BATCH ----------------------- */

async fn handler_submit_batch(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(batch): Json<LogBatch>,
) -> impl IntoResponse {
    if !state.rate_limiter.allow(&addr.to_string()).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(SubmitResponse {
                status: "error".into(),
                message: "rate limit exceeded".into(),
            }),
        );
    }

    if let Some(expected) = &state.auth_token {
        if !valid_auth(&headers, expected) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SubmitResponse {
                    status: "error".into(),
                    message: "missing or invalid auth".into(),
                }),
            );
        }
    }

    if !batch.verify() {
        log_submit_error(&batch.agent_id, "invalid signature");
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
    let logs_compressed = match compress_json(&logs_json) {
        Ok(data) => data,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitResponse {
                    status: "error".into(),
                    message: format!("failed to compress logs: {err}"),
                }),
            )
        }
    };

    let mut tx = state.pool.begin().await.unwrap();

    // Ensure agent key is trusted/registered before accepting.
    if let Err(msg) = ensure_agent_key(&state, &mut tx, &batch).await {
        log_submit_error(&batch.agent_id, &msg);
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitResponse {
                status: "error".into(),
                message: msg,
            }),
        );
    }

    // Validate hash chain + ordering for this agent.
    if let Err(msg) = validate_chain(&mut tx, &batch, &computed_hash).await {
        log_submit_error(&batch.agent_id, &msg);
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitResponse {
                status: "error".into(),
                message: msg,
            }),
        );
    }

    // Deduplicate by hash per agent to drop resends.
    let duplicate = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM batches WHERE agent_id = ?1 AND hash = ?2 LIMIT 1",
    )
    .bind(&batch.agent_id)
    .bind(computed_hash.to_vec())
    .fetch_optional(tx.as_mut())
    .await;

    let duplicate = match duplicate {
        Ok(v) => v,
        Err(_) => {
            log_submit_error(&batch.agent_id, "duplicate check failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitResponse {
                    status: "error".into(),
                    message: "failed to check duplicates".into(),
                }),
            );
        }
    };

    if duplicate.is_some() {
        log_submit_error(&batch.agent_id, "duplicate batch content for agent");
        return (
            StatusCode::CONFLICT,
            Json(SubmitResponse {
                status: "error".into(),
                message: "duplicate batch content for agent".into(),
            }),
        );
    }

    let insert_res = sqlx::query(
        r#"
        INSERT INTO batches (agent_id, seq, prev_hash, hash, logs, logs_compressed, timestamp, signature, public_key, received_at, source)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&batch.agent_id)
    .bind(batch.seq as i64)
    .bind(batch.prev_hash.to_vec())
    .bind(computed_hash.to_vec())
    .bind(logs_json) // keep plaintext for search/filter, compressed for space
    .bind(logs_compressed)
    .bind(batch.timestamp as i64)
    .bind(batch.signature.to_bytes().to_vec())
    .bind(batch.public_key.to_bytes().to_vec())
    .bind(now_unix())
    .bind(addr.to_string())
    .execute(tx.as_mut())
    .await;

    if let Err(e) = insert_res {
        if let sqlx::Error::Database(db) = &e {
            if db.is_unique_violation() {
                return (
                    StatusCode::CONFLICT,
                    Json(SubmitResponse {
                        status: "error".into(),
                        message: "duplicate batch for agent".into(),
                    }),
                );
            }
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SubmitResponse {
                status: "error".into(),
                message: format!("failed to store batch: {}", e),
            }),
        );
    }

    tx.commit().await.unwrap();

    (
        StatusCode::CREATED,
        Json(SubmitResponse {
            status: "ok".into(),
            message: "batch stored".into(),
        }),
    )
}

/* ----------------------- REGISTER / ROTATE AGENT KEYS ----------------------- */

async fn handler_register_agent(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let pk = match parse_hex_public_key(&req.public_key_hex) {
        Ok(pk) => pk,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AgentResponse {
                    status: "error".into(),
                    message: msg,
                }),
            )
        }
    };

    let existing = sqlx::query("SELECT public_key FROM agents WHERE agent_id = ?1")
        .bind(&req.agent_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap();

    if let Some(row) = existing {
        let stored: Vec<u8> = row.get("public_key");
        if stored == pk.to_bytes() {
            return (
                StatusCode::OK,
                Json(AgentResponse {
                    status: "ok".into(),
                    message: "agent already registered with this key".into(),
                }),
            );
        } else {
            return (
                StatusCode::CONFLICT,
                Json(AgentResponse {
                    status: "error".into(),
                    message: "agent ID already registered with a different key".into(),
                }),
            );
        }
    }

    sqlx::query("INSERT INTO agents (agent_id, public_key, created_at) VALUES (?1, ?2, ?3)")
        .bind(&req.agent_id)
        .bind(pk.to_bytes().to_vec())
        .bind(now_unix())
        .execute(&state.pool)
        .await
        .unwrap();

    (
        StatusCode::CREATED,
        Json(AgentResponse {
            status: "ok".into(),
            message: "agent registered".into(),
        }),
    )
}

async fn handler_rotate_agent(
    State(state): State<AppState>,
    Json(req): Json<RotateRequest>,
) -> impl IntoResponse {
    let Some(row) = sqlx::query("SELECT public_key FROM agents WHERE agent_id = ?1")
        .bind(&req.agent_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap() else {
            return (
                StatusCode::NOT_FOUND,
                Json(AgentResponse {
                    status: "error".into(),
                    message: "agent not registered".into(),
                }),
            );
        };

    let stored: Vec<u8> = row.get("public_key");
    let current_pk = match stored.try_into() {
        Ok(bytes) => match VerifyingKey::from_bytes(&bytes) {
            Ok(pk) => pk,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AgentResponse {
                        status: "error".into(),
                        message: "stored public key is invalid".into(),
                    }),
                )
            }
        },
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AgentResponse {
                    status: "error".into(),
                    message: "stored public key is invalid".into(),
                }),
            )
        }
    };

    let new_pk = match parse_hex_public_key(&req.new_public_key_hex) {
        Ok(pk) => pk,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AgentResponse {
                    status: "error".into(),
                    message: msg,
                }),
            )
        }
    };

    let sig = match parse_hex_signature(&req.auth_signature_hex) {
        Ok(sig) => sig,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AgentResponse {
                    status: "error".into(),
                    message: msg,
                }),
            )
        }
    };

    let rotation_message =
        format!("rotate:{}:{}", req.agent_id, req.new_public_key_hex).into_bytes();

    if current_pk
        .verify_strict(&rotation_message, &sig)
        .is_err()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AgentResponse {
                status: "error".into(),
                message: "rotation signature invalid".into(),
            }),
        );
    }

    sqlx::query("UPDATE agents SET public_key = ?1 WHERE agent_id = ?2")
        .bind(new_pk.to_bytes().to_vec())
        .bind(&req.agent_id)
        .execute(&state.pool)
        .await
        .unwrap();

    (
        StatusCode::OK,
        Json(AgentResponse {
            status: "ok".into(),
            message: "agent key rotated".into(),
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

    if params.agent_id.is_some()
        || params.since_seq.is_some()
        || params.since_timestamp.is_some()
        || params.until_timestamp.is_some()
        || params.log_substring.is_some()
    {
        builder.push(" WHERE ");
    }

    if let Some(agent) = &params.agent_id {
        if !first_clause {
            builder.push(" AND ");
        }
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
        first_clause = false;
    }

    if let Some(ts) = params.since_timestamp {
        if !first_clause {
            builder.push(" AND ");
        }
        builder.push("timestamp >= ");
        builder.push_bind(ts as i64);
        first_clause = false;
    }

    if let Some(ts) = params.until_timestamp {
        if !first_clause {
            builder.push(" AND ");
        }
        builder.push("timestamp <= ");
        builder.push_bind(ts as i64);
        first_clause = false;
    }

    if let Some(sub) = &params.log_substring {
        if !first_clause {
            builder.push(" AND ");
        }
        builder.push("logs LIKE ");
        builder.push_bind(format!("%{}%", sub));
    }

    builder.push(" ORDER BY agent_id ASC, seq ASC");

    if let Some(limit) = params.limit {
        builder.push(" LIMIT ");
        builder.push_bind(limit as i64);
    }
    if let Some(offset) = params.offset {
        builder.push(" OFFSET ");
        builder.push_bind(offset as i64);
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

/* ----------------------- EXPORT /batches/export ----------------------- */

async fn handler_export(
    State(state): State<AppState>,
    Query(params): Query<ExportParams>,
) -> Result<Json<Vec<QueryBatch>>, StatusCode> {
    let mut builder = QueryBuilder::new("SELECT * FROM batches");

    if let Some(since_id) = params.since_id {
        builder.push(" WHERE id > ");
        builder.push_bind(since_id);
    }

    builder.push(" ORDER BY id ASC");

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

/* ----------------------- CHECKPOINTS /batches/checkpoints ----------------------- */

async fn handler_checkpoints(State(state): State<AppState>) -> Result<Json<Vec<AgentCheckpoint>>, StatusCode> {
    let rows = sqlx::query(
        r#"
        SELECT
            agent_id,
            MAX(seq) AS last_seq,
            COUNT(*) AS count,
            (SELECT hash FROM batches b2 WHERE b2.agent_id = b.agent_id ORDER BY seq DESC LIMIT 1) AS last_hash
        FROM batches b
        GROUP BY agent_id
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut checkpoints = Vec::new();
    for row in rows {
        let agent_id: String = row.get("agent_id");
        let last_seq: i64 = row.get("last_seq");
        let count: i64 = row.get("count");
        let last_hash_vec: Vec<u8> = row.get("last_hash");
        let last_hash: [u8; 32] = last_hash_vec
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        checkpoints.push(AgentCheckpoint {
            agent_id,
            last_seq: last_seq as u64,
            last_hash,
            count: count as u64,
        });
    }

    Ok(Json(checkpoints))
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
    let compressed: Option<Vec<u8>> = row.try_get("logs_compressed").ok();
    let logs_json: String = if let Some(blob) = compressed {
        decompress_json(&blob).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        row.get("logs")
    };
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

async fn validate_chain(
    tx: &mut Transaction<'_, Sqlite>,
    batch: &LogBatch,
    computed_hash: &[u8; 32],
) -> Result<(), String> {
    use std::convert::TryInto;

    let last_row = sqlx::query(
        "SELECT seq, hash FROM batches WHERE agent_id = ?1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(&batch.agent_id)
    .fetch_optional(tx.as_mut())
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

async fn ensure_agent_key(
    state: &AppState,
    tx: &mut Transaction<'_, Sqlite>,
    batch: &LogBatch,
) -> Result<(), String> {
    let existing = sqlx::query("SELECT public_key FROM agents WHERE agent_id = ?1")
        .bind(&batch.agent_id)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(|_| "failed to check agent registry".to_string())?;

    match existing {
        Some(row) => {
            let stored: Vec<u8> = row.get("public_key");
            if stored != batch.public_key.to_bytes() {
                return Err("public key does not match registered agent key".into());
            }
        }
        None => {
            if state.require_registration {
                return Err("agent not registered; register key before sending batches".into());
            }

            sqlx::query("INSERT INTO agents (agent_id, public_key, created_at) VALUES (?1, ?2, ?3)")
                .bind(&batch.agent_id)
                .bind(batch.public_key.to_bytes().to_vec())
                .bind(now_unix())
                .execute(tx.as_mut())
                .await
                .map_err(|_| "failed to auto-register agent key".to_string())?;
        }
    }

    Ok(())
}

fn parse_hex_public_key(hex: &str) -> Result<VerifyingKey, String> {
    let bytes = parse_hex_bytes::<32>(hex)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid public key bytes".into())
}

fn parse_hex_signature(hex: &str) -> Result<Signature, String> {
    let bytes = parse_hex_bytes::<64>(hex)?;
    Ok(Signature::from_bytes(&bytes))
}

fn parse_hex_bytes<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars", N * 2));
    }

    let mut out = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_val(chunk[0])?;
        let low = hex_val(chunk[1])?;
        out[i] = (high << 4) | low;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err("invalid hex".into()),
    }
}

fn compress_json(data: &str) -> Result<Vec<u8>, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data.as_bytes())
        .map_err(|e| e.to_string())?;
    encoder.finish().map_err(|e| e.to_string())
}

fn decompress_json(bytes: &[u8]) -> Result<String, String> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

async fn configure_sqlite(pool: &SqlitePool) {
    // WAL improves durability and allows concurrent readers.
    let _ = sqlx::query("PRAGMA journal_mode=WAL").execute(pool).await;
    let _ = sqlx::query("PRAGMA synchronous=FULL").execute(pool).await;
}

async fn snapshot_database(pool: &SqlitePool, path: &str) -> Result<(), String> {
    let escaped = path.replace('\'', "''");
    let vacuum_sql = format!("VACUUM INTO '{escaped}'");
    sqlx::query(&vacuum_sql)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn ensure_column(pool: &SqlitePool, table: &str, column: &str, definition: &str) {
    let sql = format!(
        "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
    );
    let exists: Option<(i64,)> = sqlx::query_as(&sql)
        .bind(column)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    if exists.is_some() {
        return;
    }

    let alter = format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    );
    let _ = sqlx::query(&alter).execute(pool).await;
}

async fn ensure_append_only_triggers(pool: &SqlitePool) {
    // Block updates/deletes to enforce append-only.
    let _ = sqlx::query("DROP TRIGGER IF EXISTS batches_no_update").execute(pool).await;
    let _ = sqlx::query("DROP TRIGGER IF EXISTS batches_no_delete").execute(pool).await;
    let _ = sqlx::query("DROP TRIGGER IF EXISTS batches_enforce_seq").execute(pool).await;

    sqlx::query(
        r#"
        CREATE TRIGGER batches_no_update
        BEFORE UPDATE ON batches
        BEGIN
            SELECT RAISE(ABORT, 'append-only: updates forbidden');
        END;
        "#,
    )
    .execute(pool)
    .await
    .ok();

    sqlx::query(
        r#"
        CREATE TRIGGER batches_no_delete
        BEFORE DELETE ON batches
        BEGIN
            SELECT RAISE(ABORT, 'append-only: deletes forbidden');
        END;
        "#,
    )
    .execute(pool)
    .await
    .ok();

    // Enforce monotonic seq and hash linkage per agent even if someone bypasses the API.
    sqlx::query(
        r#"
        CREATE TRIGGER batches_enforce_seq
        BEFORE INSERT ON batches
        BEGIN
            -- Detect last state for this agent.
            SELECT
                CASE
                    WHEN (SELECT COUNT(*) FROM batches WHERE agent_id = NEW.agent_id) = 0 THEN
                        CASE
                            WHEN NEW.seq != 1 THEN
                                RAISE(ABORT, 'append-only: first seq must be 1')
                            WHEN NEW.prev_hash != zeroblob(32) THEN
                                RAISE(ABORT, 'append-only: first prev_hash must be zero')
                        END
                    ELSE
                        CASE
                            WHEN NEW.seq != (SELECT seq + 1 FROM batches WHERE agent_id = NEW.agent_id ORDER BY seq DESC LIMIT 1) THEN
                                RAISE(ABORT, 'append-only: non-contiguous seq')
                            WHEN NEW.prev_hash != (SELECT hash FROM batches WHERE agent_id = NEW.agent_id ORDER BY seq DESC LIMIT 1) THEN
                                RAISE(ABORT, 'append-only: prev_hash mismatch')
                        END
                END;
        END;
        "#,
    )
    .execute(pool)
    .await
    .ok();
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct RateLimiter {
    max: u32,
    window: StdDuration,
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    fn new(max: u32, window: StdDuration) -> Self {
        Self {
            max,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    async fn allow(&self, key: &str) -> bool {
        let mut guard = self.buckets.lock().await;
        let now = Instant::now();
        let entry = guard.entry(key.to_string()).or_insert((now, 0));

        if now.duration_since(entry.0) > self.window {
            *entry = (now, 0);
        }

        if entry.1 >= self.max {
            return false;
        }

        entry.1 += 1;
        true
    }
}
