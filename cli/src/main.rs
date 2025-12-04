use common::batch::LogBatch;
use reqwest::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Fetching batches from server...");

    let batches: Vec<serde_json::Value> = Client::new()
        .get("http://127.0.0.1:3000/batches")
        .send()
        .await?
        .json()
        .await?;

    println!("Received {} batches", batches.len());

    // Deserialize into our real type
    let mut chain: Vec<(i64, LogBatch)> = Vec::new();

    for entry in batches {
        let id = entry["id"].as_i64().unwrap();
        let batch: LogBatch = serde_json::from_value(entry["batch"].clone()).unwrap();
        chain.push((id, batch));
    }

    verify_chain(&chain);

    Ok(())
}

fn verify_chain(chain: &Vec<(i64, LogBatch)>) {
    println!("Verifying chain integrity...\n");

    if chain.is_empty() {
        println!("No batches found.");
        return;
    }

    let mut prev_hash = [0u8; 32];

    for (i, (id, batch)) in chain.iter().enumerate() {
        // 1. Verify signature
        if batch.verify() == false {
            println!("Signature INVALID at batch {}", id);
            return;
        }

        // 2. Check hash link
        if i > 0 {
            if batch.prev_hash != prev_hash {
                println!("Hash chain broken at batch {}", id);
                println!("Expected prev_hash = {:02x?}", prev_hash);
                println!("Found prev_hash    = {:02x?}", batch.prev_hash);
                return;
            }
        }

        // Compute expected hash for next step
        prev_hash = batch.compute_hash();
    }

    println!("✔️ Chain valid. No tampering detected.");
}
