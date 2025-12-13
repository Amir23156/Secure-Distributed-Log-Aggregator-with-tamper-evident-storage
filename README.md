# Logchain

Tamper-evident log shipping with an **agent** that tails local logs, a **server** that verifies and stores signed batches, and a **CLI** that audits the stored chain per agent.

## Project layout
- `common/` – shared batch format, hashing, signing helpers.
- `server/` – Axum + SQLite API for ingesting, querying, and exporting batches; enforces append-only and per-agent sequencing.
- `agent/` – async tailer that batches lines, signs them with an Ed25519 key, and retries POSTing to the server.
- `cli/` – fetches batches from the server and verifies signature/chain integrity locally.

## How it works
Each batch includes `prev_hash`, `timestamp`, `seq`, `agent_id`, and the log lines. The agent signs the batch hash with its key and sends it to the server. The server:
1. Verifies the signature and (optionally) that the agent is registered.
2. Enforces per-agent monotonic `seq` and hash linkage.
3. Deduplicates by hash, stores plaintext JSON logs plus a compressed copy, and blocks updates/deletes via triggers.
The CLI re-fetches batches and recomputes hashes/signatures to detect tampering.

## Prerequisites
- Rust toolchain (2024 edition workspace).
- SQLite (used via `sqlx`); default DB is `sqlite://logchain.db`.

## Running
Build all: `cargo build --workspace`

### Server
```bash
cargo run -p server
```
Environment options:
- `SERVER_ADDR` (default `127.0.0.1:3000`)
- `DATABASE_URL` (default `sqlite://logchain.db`)
- `SUBMIT_BEARER_TOKEN` (if set, required as `Authorization: Bearer <token>`)
- `REQUIRE_AGENT_REGISTRATION` (`1`/`true` to block unregistered agents)
- `RATE_LIMIT_MAX` (default `200`), `RATE_LIMIT_WINDOW_SECS` (default `60`)
- `SQLITE_BACKUP_PATH` + `SQLITE_BACKUP_INTERVAL_SECS` (default `300`) to enable periodic `VACUUM INTO`

### Agent
Tails a log file, batching every 5 lines.
```bash
cargo run -p agent -- \
  --log-path /var/log/syslog \
  --server-url http://127.0.0.1:3000 \
  --state-dir ~/.logagent
```
Env overrides: `AGENT_LOG_PATH`, `AGENT_SERVER_URL`, `AGENT_STATE_DIR`, `AGENT_MAX_RETRIES` (default `5`), `AGENT_RETRY_BASE_MS` (default `500`). The agent stores its Ed25519 key in `state-dir/agent.key` and a persisted sequence counter in `state-dir/seq.txt`.

### CLI verifier
Fetches `/batches` and validates chains per agent.
```bash
cargo run -p cli -- --server-url http://127.0.0.1:3000
```
Or set `CLI_SERVER_URL`.

## API surface (server)
- `POST /submit` – ingest a signed `LogBatch`.
- `POST /agents/register` – register `agent_id` + public key.
- `POST /agents/rotate` – rotate an agent key with a signature from the current key.
- `GET /batches` – list batches with filters (`agent_id`, `since_seq`, `since_timestamp`, `until_timestamp`, `log_substring`, `limit`, `offset`).
- `GET /batches/:id` – fetch a single batch.
- `GET /batches/checkpoints` – last seq/hash per agent.
- `GET /batches/export` – paginated export by row `id`.

## Notes and defaults
- First batch per agent must have `seq = 1` and `prev_hash = 0x00..00`.
- Hashes and signatures use SHA-256 and Ed25519 (dalek).
- Rate limiting is per-remote address with a sliding window.
- SQLite triggers enforce append-only and contiguous per-agent sequences even if someone bypasses the HTTP API.
