//! Kademlia DHT discovery layer (Amino-tuned parameters).
//!
//! Design reference:
//! - libp2p/go-libp2p-kad-dht: k=20, alpha=10, beta=3, record age 48h,
//!   reprovide 22h, RT refresh 10min, max_peers_per_ip_group=3.
//!
//! Public API: `Kademlia::new`, `lookup_peers`, `find_providers`.

pub mod config;
pub mod persist;
pub mod provide;
pub mod query;
pub mod record;
pub mod refresh;
pub mod rt;

pub use config::KadConfig;
pub use persist::{DbError as RtDbError, RtDb};
pub use provide::ProviderStore;

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::Mutex;

/// Identifier of a peer. In a real deployment this is an ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        write!(f, "{}", &s[..8])
    }
}

/// Common prefix length between two peer ids (bucket index, big-endian).
pub fn cpl(a: &PeerId, b: &PeerId) -> u32 {
    let mut n = 0u32;
    for i in 0..32 {
        if a.0[i] == b.0[i] {
            n += 8;
        } else {
            let x = a.0[i] ^ b.0[i];
            n += x.leading_zeros();
            return n;
        }
    }
    256
}

/// 256-bit XOR distance as a `(hi, lo)` big-endian pair.
/// Lexicographic comparison of the pair equals magnitude order of the 256-bit XOR,
/// which is exactly Kademlia's "closeness" ordering.
pub fn xor_distance(a: &PeerId, b: &PeerId) -> (u128, u128) {
    let mut hi: u128 = 0;
    for i in 0..16 {
        hi = (hi << 8) | (a.0[i] ^ b.0[i]) as u128;
    }
    let mut lo: u128 = 0;
    for i in 16..32 {
        lo = (lo << 8) | (a.0[i] ^ b.0[i]) as u128;
    }
    (hi, lo)
}

#[derive(Clone)]
/// The Kademlia DHT node.
pub struct Kademlia {
    pub config: KadConfig,
    pub self_id: PeerId,
    pub rt: Arc<Mutex<rt::RoutingTable>>,
    /// Shared provider records. The wire transport / server read and write
    /// this; it is what makes `find_providers` real (not just "closest peers").
    pub providers: Arc<Mutex<ProviderStore>>,
}

impl Kademlia {
    pub fn new(self_id: PeerId, config: KadConfig) -> Self {
        let rt = Arc::new(Mutex::new(rt::RoutingTable::new(self_id, config.clone())));
        Self {
            config,
            self_id,
            rt,
            providers: Arc::new(Mutex::new(ProviderStore::default())),
        }
    }

    /// Use a caller-provided shared provider store (so the server and the
    /// transport answer from the same records).
    pub fn with_providers(
        self_id: PeerId,
        config: KadConfig,
        providers: std::sync::Arc<Mutex<ProviderStore>>,
    ) -> Self {
        let rt = std::sync::Arc::new(Mutex::new(rt::RoutingTable::new(self_id, config.clone())));
        Self {
            config,
            self_id,
            rt,
            providers,
        }
    }

    /// Seed peers for bootstrap lookups.
    pub fn bootstrap(&self, peers: impl IntoIterator<Item = PeerId>) {
        let mut rt = self.rt.blocking_lock();
        for p in peers {
            rt.add_seed(p);
        }
    }

    /// Kademlia lookup: return the `bucket_size` closest peers to `target`.
    ///
    /// Conforms to `runQuery` in go-libp2p-kad-dht/query.go:
    /// - alpha-wide concurrent wave, beta-closest termination,
    ///   starvation termination, follow-up pass over Heard/Waiting top-K.
    pub async fn lookup_peers<T: query::lookup::QueryTransport>(
        &self,
        target: &PeerId,
        transport: &T,
    ) -> Vec<PeerId> {
        query::lookup::run_lookup(self, target, transport)
            .await
            .closest
    }

    /// Find providers of a content key (multihash of site address).
    pub async fn find_providers(&self, key: &[u8]) -> Vec<PeerId> {
        let synthetic = PeerId(hash_key(key));
        provide::find_providers(self, &synthetic, key).await
    }
}

/// Key hash used as the DHT lookup target for providers.
pub fn hash_key(key: &[u8]) -> [u8; 32] {
    use std::hash::{DefaultHasher, Hasher as StdHasher};
    let mut h = DefaultHasher::new();
    h.write(key);
    let digest = h.finish();
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&digest.to_be_bytes());
    out
}

/// Simple bounded ring buffer.
#[derive(Default)]
pub struct LruCache<T> {
    items: VecDeque<T>,
    cap: usize,
}

impl<T> LruCache<T> {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            items: VecDeque::new(),
            cap,
        }
    }

    pub fn push(&mut self, item: T) {
        if self.items.len() >= self.cap {
            self.items.pop_front();
        }
        self.items.push_back(item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_distance_identical_is_zero() {
        let a = pid_at(0, 0xab);
        assert_eq!(xor_distance(&a, &a), (0, 0));
    }

    /// Build a PeerId with a single byte set at a given index (0 = most significant).
    fn pid_at(idx: usize, val: u8) -> PeerId {
        let mut out = [0u8; 32];
        out[idx] = val;
        PeerId(out)
    }

    #[test]
    fn xor_distance_lowest_array_byte_is_smallest() {
        // Differing only in the last (least-significant) byte yields (0, 1).
        assert_eq!(xor_distance(&pid_at(31, 0), &pid_at(31, 1)), (0, 1));
    }

    #[test]
    fn xor_distance_higher_byte_differs_more() {
        // A difference in an earlier (more-significant) byte is "closer" (larger XOR).
        let low = xor_distance(&pid_at(31, 0), &pid_at(31, 1));
        let high = xor_distance(&pid_at(0, 0), &pid_at(0, 1));
        assert!(high > low);
    }

    #[test]
    fn hash_key_is_deterministic() {
        let a = hash_key(b"site-a");
        let b = hash_key(b"site-a");
        let c = hash_key(b"site-b");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
