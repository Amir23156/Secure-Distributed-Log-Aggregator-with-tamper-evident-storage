use common::batch::LogBatch;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;

#[derive(Default)]
struct CliArgs {
    server_url: Option<String>,
}

impl CliArgs {
    fn parse() -> Self {
        let mut server_url = None;
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--server-url" {
                if let Some(v) = args.next() {
                    server_url = Some(v);
                }
            }
        }
        Self { server_url }
    }
}

#[derive(Deserialize)]
struct RemoteBatch {
    id: i64,
    batch: LogBatch,
    hash: [u8; 32],
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let server_url = args
        .server_url
        .or_else(|| env::var("CLI_SERVER_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:3000".to_string());

    println!("Fetching batches from server {}...", server_url);

    let batches: Vec<RemoteBatch> = Client::new()
        .get(format!("{}/batches", server_url))
        .send()
        .await?
        .json()
        .await?;

    println!("Received {} batches", batches.len());
    verify_chain(&batches);

    Ok(())
}

fn verify_chain(chain: &[RemoteBatch]) {
    println!("Verifying chain integrity per agent...\n");

    if chain.is_empty() {
        println!("No batches found.");
        return;
    }

    let mut per_agent: HashMap<String, Vec<&RemoteBatch>> = HashMap::new();
    for batch in chain {
        per_agent
            .entry(batch.batch.agent_id.clone())
            .or_default()
            .push(batch);
    }

    for (agent, batches) in per_agent.iter_mut() {
        batches.sort_by_key(|b| b.batch.seq);
        println!("Agent {}: {} batches", agent, batches.len());

        let mut expected_prev = [0u8; 32];
        let mut expected_seq = 1u64;
        for entry in batches.iter() {
            let id = entry.id;
            let batch = &entry.batch;

            if !batch.verify() {
                println!("  ✗ signature INVALID at id {}", id);
                return;
            }

            if batch.seq != expected_seq {
                println!(
                    "  ✗ sequence gap for agent {} at id {} (expected {}, found {})",
                    agent, id, expected_seq, batch.seq
                );
                return;
            }

            if batch.prev_hash != expected_prev {
                println!(
                    "  ✗ hash chain broken for agent {} at id {} (expected {:02x?}, found {:02x?})",
                    agent, id, expected_prev, batch.prev_hash
                );
                return;
            }

            let computed_hash = batch.compute_hash();
            if computed_hash != entry.hash {
                println!(
                    "  ✗ hash mismatch at id {} for agent {} (computed {:02x?}, stored {:02x?})",
                    id, agent, computed_hash, entry.hash
                );
                return;
            }

            expected_prev = computed_hash;
            expected_seq += 1;
        }

        println!("  ✓ chain valid");
    }

    println!("\nAll chains valid. No tampering detected.");
}
