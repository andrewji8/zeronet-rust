//! Tunable DHT parameters. Defaults mirror libp2p/go-libp2p-kad-dht `amino`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default parameters for a public Kademlia DHT (Amino-tuned).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KadConfig {
    /// k: max peers per k-bucket. Default 20 (Amino).
    pub bucket_size: u8,
    /// alpha: concurrent query width. Default 10 (Amino); 8 recommended for light nodes.
    pub concurrency: u8,
    /// beta: closest peers that must have responded to terminate lookup. Default 3.
    pub resiliency: u8,
    /// Max age of value records before re-put. Default 48h.
    pub max_record_age: Duration,
    /// Republish providers every 22h so the DHT always has fresh records.
    pub reprovide_interval: Duration,
    /// Routing-table refresh period. Default 10min.
    pub rt_refresh_period: Duration,
    /// Max peers from the same /24 IP group in the whole table. Default 3.
    pub max_peers_per_ip_group: u8,
    /// Max peers from the same /24 IP group within one k-bucket. Default 2.
    pub max_peers_per_ip_group_per_cpl: u8,
    /// Well-known bootstrap peers.
    pub bootstrap_peers: Vec<String>,
}

impl Default for KadConfig {
    fn default() -> Self {
        Self {
            bucket_size: 20,
            concurrency: 10,
            resiliency: 3,
            max_record_age: Duration::from_secs(48 * 3600),
            reprovide_interval: Duration::from_secs(22 * 3600),
            rt_refresh_period: Duration::from_secs(10 * 60),
            max_peers_per_ip_group: 3,
            max_peers_per_ip_group_per_cpl: 2,
            bootstrap_peers: Vec::new(),
        }
    }
}

impl KadConfig {
    /// Light-node preset: lower concurrency to save bandwidth on home connections.
    pub fn light_node() -> Self {
        Self {
            concurrency: 8,
            ..Self::default()
        }
    }
}
