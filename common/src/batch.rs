use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::Signer;

/// A tamper-evident batch of logs sent from an agent to the server.
///
/// Each batch includes:
/// - `prev_hash`: the hash of the previous batch in the chain
/// - `logs`: the log lines
/// - `timestamp`: unix time when batch was created
/// - `signature`: digital signature of the batch content
/// - `public_key`: the agent's public key (used to verify signature)
/// - `agent_id`: stable identifier for the producing agent
/// - `seq`: monotonically increasing sequence number per agent
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogBatch {
    pub prev_hash: [u8; 32],
    pub logs: Vec<String>,
    pub timestamp: u64,
    pub agent_id: String,
    pub seq: u64,
    pub signature: Signature,
    pub public_key: VerifyingKey,
}

impl LogBatch {
    /// Computes the SHA-256 hash of this batch (excluding the signature).
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(self.prev_hash);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.seq.to_le_bytes());
        hasher.update(self.agent_id.as_bytes());

        for log in &self.logs {
            hasher.update(log.as_bytes());
        }

        let result = hasher.finalize();
        result.into()
    }

    /// Signs the batch content and stores signature + public key.
    pub fn sign(&mut self, signer: &SigningKey) {
        let hash = self.compute_hash();
        self.signature = signer.sign(&hash);
        self.public_key = signer.verifying_key();
    }

    /// Verifies the stored signature matches this batch's contents.
    pub fn verify(&self) -> bool {
        let hash = self.compute_hash();
        self.public_key.verify_strict(&hash, &self.signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let mut batch = LogBatch {
            prev_hash: [1u8; 32],
            logs: vec!["line1".into(), "line2".into()],
            timestamp: 1234,
            agent_id: "agent-a".into(),
            seq: 1,
            signature: Signature::from_bytes(&[0u8; 64]),
            public_key: generate_keypair().verifying_key(),
        };

        let signer = generate_keypair();
        batch.sign(&signer);
        assert!(batch.verify(), "signature must verify");
    }

    #[test]
    fn tamper_changes_hash_and_breaks_signature() {
        let mut batch = LogBatch {
            prev_hash: [2u8; 32],
            logs: vec!["a".into()],
            timestamp: 1,
            agent_id: "agent-b".into(),
            seq: 1,
            signature: Signature::from_bytes(&[0u8; 64]),
            public_key: generate_keypair().verifying_key(),
        };

        let signer = generate_keypair();
        batch.sign(&signer);
        assert!(batch.verify());

        // Tamper
        batch.logs.push("evil".into());
        assert!(!batch.verify(), "tampering should fail verification");
    }
}

/// Utility: create a new signing key (agent identity).
pub fn generate_keypair() -> SigningKey {
    let mut bytes = [0u8; 32];
    OsRng.fill(&mut bytes);
    SigningKey::from_bytes(&bytes)
}
