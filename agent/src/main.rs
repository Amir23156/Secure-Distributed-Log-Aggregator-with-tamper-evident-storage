use common::batch::{generate_keypair, LogBatch};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{sleep, Duration};
use chrono::Utc;
use ed25519_dalek::Signature;
use anyhow::{anyhow, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use serde::Deserialize;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting agent...");

    let cli_args = AgentArgs::parse();
    let config = AgentConfig::load(cli_args)?;
    println!("Agent ID: {}", config.agent_id);
    println!("Tailing {}", config.log_path.display());
    println!("Sending to {}", config.server_url);
    println!(
        "Retries: max {} with base {}ms",
        config.max_retries, config.retry_base_ms
    );

    let mut key = load_or_generate_key(&config)?;
    let mut seq = load_seq(&config)?; // persistent monotonic counter
    let mut prev_hash = load_prev_hash(&config)?;

    // Try to align with server checkpoint so we don't send out-of-sync batches.
    match fetch_checkpoint(&config, &config.agent_id).await {
        Ok(Some(cp)) => {
            prev_hash = cp.last_hash;
            seq = cp.last_seq.saturating_add(1);
            persist_seq(&config, seq)?;
            persist_prev_hash(&config, prev_hash)?;
            println!(
                "Synced from server checkpoint: last_seq={}, next_seq={}, prev_hash={}",
                cp.last_seq,
                seq,
                to_hex(&prev_hash)
            );
        }
        Ok(None) => {
            // No batches stored for this agent; reset local state to the beginning.
            if seq != 1 || prev_hash != [0u8; 32] {
                println!("Server has no batches for this agent; resetting local chain state");
                seq = 1;
                prev_hash = [0u8; 32];
                persist_seq(&config, seq)?;
                persist_prev_hash(&config, prev_hash)?;
            }
        }
        Err(err) => {
            eprintln!(
                "Could not fetch checkpoints from server; using local state: {err}"
            );
        }
    }

    // Open log file
    let file = File::open(&config.log_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut buffer: Vec<String> = Vec::new();

    while let Some(line) = lines.next_line().await? {
        buffer.push(line);

        // Once buffer hits batch size (5)
        if buffer.len() >= 5 {
            let timestamp = Utc::now().timestamp() as u64;

            // Build batch (placeholder signature overwritten by .sign())
            let mut batch = LogBatch {
                prev_hash,
                logs: buffer.clone(),
                timestamp,
                agent_id: config.agent_id.clone(),
                seq,
                // Placeholder signature overwritten by `sign`
                signature: Signature::from_bytes(&[0u8; 64]),
                public_key: key.verifying_key(),
            };

            // Sign batch & compute expected hash
            batch.sign(&key);
            let next_hash = batch.compute_hash();

            println!("Produced batch: {:?}", prev_hash);

            // Send to server; on success advance chain/seq
            match send_batch(&config, &batch).await {
                Ok(_) => {
                    prev_hash = next_hash;
                    seq += 1;
                    persist_seq(&config, seq)?;
                    persist_prev_hash(&config, prev_hash)?;
                }
                Err(err) => {
                    eprintln!("Failed to send batch: {err:?}");
                    // regenerate key if it was invalidated on disk
                    key = load_or_generate_key(&config)?;
                }
            };

            buffer.clear();
        }
    }

    Ok(())
}

/* -------------------------
   POST BATCH TO SERVER
------------------------- */
async fn send_batch(config: &AgentConfig, batch: &LogBatch) -> Result<()> {
    let client = reqwest::Client::new();
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        let resp = client
            .post(format!("{}/submit", config.server_url))
            .json(batch)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                println!("Batch sent successfully (attempt {})", attempt);
                return Ok(());
            }
            Ok(r) => {
                eprintln!(
                    "Server rejected batch (attempt {}): status {}",
                    attempt,
                    r.status()
                );
            }
            Err(err) => {
                eprintln!("Network error sending batch (attempt {}): {err}", attempt);
            }
        }

        if attempt >= config.max_retries {
            return Err(anyhow::anyhow!(
                "exhausted retries after {} attempts",
                attempt
            ));
        }

        let backoff_ms = config.retry_base_ms.saturating_mul(1 << (attempt - 1));
        sleep(Duration::from_millis(backoff_ms)).await;
    }
}

struct AgentConfig {
    log_path: PathBuf,
    server_url: String,
    state_dir: PathBuf,
    agent_id: String,
    max_retries: u32,
    retry_base_ms: u64,
}

struct AgentArgs {
    log_path: Option<PathBuf>,
    server_url: Option<String>,
    state_dir: Option<PathBuf>,
    max_retries: Option<u32>,
    retry_base_ms: Option<u64>,
}

impl AgentArgs {
    fn parse() -> Self {
        let mut log_path = None;
        let mut server_url = None;
        let mut state_dir = None;
        let mut max_retries = None;
        let mut retry_base_ms = None;

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--log-path" => {
                    if let Some(v) = args.next() {
                        log_path = Some(PathBuf::from(v));
                    }
                }
                "--server-url" => {
                    if let Some(v) = args.next() {
                        server_url = Some(v);
                    }
                }
                "--state-dir" => {
                    if let Some(v) = args.next() {
                        state_dir = Some(PathBuf::from(v));
                    }
                }
                "--max-retries" => {
                    if let Some(v) = args.next() {
                        max_retries = v.parse().ok();
                    }
                }
                "--retry-base-ms" => {
                    if let Some(v) = args.next() {
                        retry_base_ms = v.parse().ok();
                    }
                }
                _ => {}
            }
        }

        Self {
            log_path,
            server_url,
            state_dir,
            max_retries,
            retry_base_ms,
        }
    }
}

impl AgentConfig {
    fn load(args: AgentArgs) -> Result<Self> {
        let home = env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let state_dir = args
            .state_dir
            .or_else(|| env::var("AGENT_STATE_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| home.join(".logagent"));
        fs::create_dir_all(&state_dir)?;

        let log_path = args
            .log_path
            .or_else(|| env::var("AGENT_LOG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/var/log/dpkg.log"));

        let server_url = args
            .server_url
            .or_else(|| env::var("AGENT_SERVER_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:3000".to_string());

        let max_retries = args
            .max_retries
            .or_else(|| env::var("AGENT_MAX_RETRIES").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(5);

        let retry_base_ms = args
            .retry_base_ms
            .or_else(|| env::var("AGENT_RETRY_BASE_MS").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(500);

        let key_path = Self::key_path(&state_dir);
        let agent_id = derive_agent_id(&key_path)?;

        Ok(Self {
            log_path,
            server_url,
            state_dir,
            agent_id,
            max_retries,
            retry_base_ms,
        })
    }

    fn key_path(state_dir: &Path) -> PathBuf {
        state_dir.join("agent.key")
    }

    fn seq_path(&self) -> PathBuf {
        self.state_dir.join("seq.txt")
    }

    fn prev_hash_path(&self) -> PathBuf {
        self.state_dir.join("prev_hash.txt")
    }
}

fn derive_agent_id(key_path: &Path) -> Result<String> {
    let key = load_or_generate_key_path(key_path)?;
    let pk = key.verifying_key();
    Ok(to_hex(&pk.to_bytes()))
}

fn load_or_generate_key(config: &AgentConfig) -> Result<ed25519_dalek::SigningKey> {
    load_or_generate_key_path(&AgentConfig::key_path(&config.state_dir))
}

fn load_or_generate_key_path(path: &Path) -> Result<ed25519_dalek::SigningKey> {
    if let Ok(bytes) = fs::read(path) {
        if bytes.len() == 32 {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            return Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes));
        }
    }

    let key = generate_keypair();
    fs::write(path, key.to_bytes())?;
    Ok(key)
}

fn load_seq(config: &AgentConfig) -> Result<u64> {
    let path = config.seq_path();
    if let Ok(contents) = fs::read_to_string(&path) {
        if let Ok(v) = contents.trim().parse::<u64>() {
            return Ok(v);
        }
    }
    Ok(1)
}

fn persist_seq(config: &AgentConfig, seq: u64) -> Result<()> {
    fs::write(config.seq_path(), seq.to_string())?;
    Ok(())
}

fn load_prev_hash(config: &AgentConfig) -> Result<[u8; 32]> {
    let path = config.prev_hash_path();
    if let Ok(contents) = fs::read_to_string(&path) {
        let hex = contents.trim();
        if hex.len() == 64 {
            let mut out = [0u8; 32];
            for i in 0..32 {
                let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                    .map_err(|e| anyhow!("invalid prev_hash hex: {e}"))?;
                out[i] = byte;
            }
            return Ok(out);
        }
    }
    Ok([0u8; 32])
}

fn persist_prev_hash(config: &AgentConfig, hash: [u8; 32]) -> Result<()> {
    fs::write(config.prev_hash_path(), to_hex(&hash))?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[derive(Deserialize)]
struct AgentCheckpoint {
    agent_id: String,
    last_seq: u64,
    last_hash: [u8; 32],
    #[serde(rename = "count")]
    _count: u64,
}

async fn fetch_checkpoint(config: &AgentConfig, agent_id: &str) -> Result<Option<AgentCheckpoint>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/batches/checkpoints", config.server_url))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "checkpoint request failed with status {}",
            resp.status()
        ));
    }

    let checkpoints: Vec<AgentCheckpoint> = resp.json().await?;
    Ok(checkpoints.into_iter().find(|cp| cp.agent_id == agent_id))
}
