use common::batch::{LogBatch, generate_keypair};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use chrono::Utc;
use ed25519_dalek::Signature;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting agent...");

    let log_path = "/var/log/dpkg.log";
    let key = generate_keypair();

    // Open log file
    let file = File::open(log_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut buffer: Vec<String> = Vec::new();
    let mut prev_hash = [0u8; 32];

    println!("Tailing {}", log_path);

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
                // Placeholder signature overwritten by `sign`
                signature: Signature::from_bytes(&[0u8; 64]),
                public_key: key.verifying_key(),
            };

            // Sign batch & update hash chain
            batch.sign(&key);
            prev_hash = batch.compute_hash();

            println!("Produced batch: {:?}", prev_hash);

            // Send to server
            send_batch(&batch).await?;

            buffer.clear();
        }
    }

    Ok(())
}

/* -------------------------
   POST BATCH TO SERVER
------------------------- */
async fn send_batch(batch: &LogBatch) -> Result<()> {
    let client = reqwest::Client::new();

    let resp = client
        .post("http://127.0.0.1:3000/submit")
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
