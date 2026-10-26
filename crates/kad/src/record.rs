//! A signed record stored in the DHT (PutValue / IPNS analog).

use super::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// Peer that signed (published) this record.
    pub publisher: PeerId,
    /// Unix timestamp when the record was published.
    pub timestamp: u64,
    /// ed25519 signature over `key || value || timestamp` by `publisher`.
    pub signature: Vec<u8>,
}

impl Record {
    pub fn new(key: Vec<u8>, value: Vec<u8>, publisher: PeerId, timestamp: u64, signature: Vec<u8>) -> Self {
        Self { key, value, publisher, timestamp, signature }
    }

    /// Freshness check against `max_record_age`.
    pub fn is_fresh(&self, now_unix: u64, max_age: std::time::Duration) -> bool {
        now_unix.saturating_sub(self.timestamp) < max_age.as_secs()
    }
}

