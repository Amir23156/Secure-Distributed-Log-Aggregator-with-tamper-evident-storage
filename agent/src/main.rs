use common::batch::{LogBatch, generate_keypair};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use chrono::Utc;
use ed25519_dalek::Signature;
use anyhow::Result;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting agent...");

    let config = AgentConfig::load()?;
    println!("Agent ID: {}", config.agent_id);
    println!("Tailing {}", config.log_path.display());
    println!("Sending to {}", config.server_url);

    let mut key = load_or_generate_key(&config)?;
    let mut seq = load_seq(&config)?; // persistent monotonic counter

    // Open log file
    let file = File::open(&config.log_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut buffer: Vec<String> = Vec::new();
    let mut prev_hash = [0u8; 32];

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
            match send_batch(&config.server_url, &batch).await {
                Ok(_) => {
                    prev_hash = next_hash;
                    seq += 1;
                    persist_seq(&config, seq)?;
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
async fn send_batch(server_url: &str, batch: &LogBatch) -> Result<()> {
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/submit", server_url))
        .json(batch)
        .send()
        .await?;

    if resp.status().is_success() {
        println!("Batch sent successfully");
    } else {
        println!("Server rejected batch: {}", resp.status());
    }

    Ok(())
}

struct AgentConfig {
    log_path: PathBuf,
    server_url: String,
    state_dir: PathBuf,
    agent_id: String,
}

impl AgentConfig {
    fn load() -> Result<Self> {
        let home = env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let state_dir = env::var("AGENT_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".logagent"));
        fs::create_dir_all(&state_dir)?;

        let log_path = env::var("AGENT_LOG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/log/dpkg.log"));

        let server_url = env::var("AGENT_SERVER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());

        let key_path = Self::key_path(&state_dir);
        let agent_id = derive_agent_id(&key_path)?;

        Ok(Self {
            log_path,
            server_url,
            state_dir,
            agent_id,
        })
    }

    fn key_path(state_dir: &Path) -> PathBuf {
        state_dir.join("agent.key")
    }

    fn seq_path(&self) -> PathBuf {
        self.state_dir.join("seq.txt")
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

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
