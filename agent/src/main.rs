use common::{batch::LogBatch, batch::generate_keypair};
use notify::{Watcher, RecursiveMode, RecommendedWatcher, EventKind};
use std::path::Path;
use std::sync::mpsc::channel;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use chrono::Utc;
use ed25519_dalek::Signature;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting agent...");

    let log_path = "/var/log/dpkg.log";  
    //let log_path = "mylog.txt";
    let key = generate_keypair();

    // Open the file for tailing
    let file = File::open(log_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut buffer: Vec<String> = Vec::new();
    let mut prev_hash = [0u8; 32];

    println!("Tailing {}", log_path);

    loop {
        if let Some(line) = lines.next_line().await? {
            buffer.push(line);

            if buffer.len() >= 5 {
                // Build a batch
                let timestamp = Utc::now().timestamp() as u64;

                let mut batch = LogBatch {
                    prev_hash,
                    logs: buffer.clone(),
                    timestamp,
                    signature: Signature::from_bytes(&[0u8; 64]),
                    public_key: key.verifying_key(),
                };

                batch.sign(&key);
                prev_hash = batch.compute_hash();

                println!("Produced batch: {:?}", batch.compute_hash());

                buffer.clear();
            }
        }
    }
}
