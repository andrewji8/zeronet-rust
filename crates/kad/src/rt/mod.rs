//! Routing table: k-buckets keyed by common prefix length (big-endian peer ids),
//! LRU eviction on overflow, and IP-diversity capping (Amino).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{cpl, KadConfig, PeerId};

#[derive(Debug, Clone)]
pub struct RtPeer {
    pub id: PeerId,
    /// Optional /24 IP-group label used for diversity capping.
    pub ip_group: Option<u32>,
}

pub(crate) struct Bucket {
    pub id: PeerId,
    pub peers: VecDeque<RtPeer>,
}

/// The Kademlia routing table.
pub struct RoutingTable {
    pub self_id: PeerId,
    pub config: KadConfig,
    /// Buckets indexed by CPL (0..=256).
    buckets: HashMap<u32, Bucket>,
    /// Seed peers not yet in the table.
    seeds: VecDeque<RtPeer>,
    last_useful: AtomicU64,
}

impl RoutingTable {
    pub fn new(self_id: PeerId, config: KadConfig) -> Self {
        Self {
            self_id,
            config,
            buckets: HashMap::new(),
            seeds: VecDeque::new(),
            last_useful: AtomicU64::new(0),
        }
    }

    pub fn add_seed(&mut self, id: PeerId) {
        if id == self.self_id {
            return;
        }
        let cap = self.config.bucket_size as usize;
        if self.seeds.len() < cap.max(10) {
            self.seeds.push_back(RtPeer { id, ip_group: None });
        }
    }

    /// Returns `true` when the peer was newly added.
    pub fn add_peer(&mut self, peer: RtPeer) -> bool {
        if peer.id == self.self_id {
            return false;
        }
        if let Some(pos) = self.seeds.iter().position(|s| s.id == peer.id) {
            self.seeds.remove(pos);
        }

        let prefix = cpl(&self.self_id, &peer.id);
        let k = self.config.bucket_size as usize;
        let bucket = self.buckets.entry(prefix).or_insert_with(|| Bucket {
            id: peer.id,
            peers: VecDeque::with_capacity(k),
        });

        if let Some(group) = peer.ip_group {
            let same_group = bucket.peers.iter().filter(|p| p.ip_group == Some(group)).count();
            if same_group >= self.config.max_peers_per_ip_group_per_cpl as usize {
                return false;
            }
        }

        if bucket.peers.len() < k {
            bucket.peers.push_back(peer);
            true
        } else {
            if bucket.peers.pop_front().is_some() {
                bucket.peers.push_back(peer);
                self.last_useful.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }

    /// Closest peers to `target` up to `n`, ordered by 256-bit XOR distance.
    pub fn nearest_peers(&self, target: &PeerId, n: usize) -> Vec<RtPeer> {
        let mut seen: HashMap<PeerId, (u128, u128)> = HashMap::new();
        for s in &self.seeds {
            seen.insert(s.id, crate::xor_distance(&s.id, target));
        }
        for b in self.buckets.values() {
            for p in b.peers.iter() {
                seen.insert(p.id, crate::xor_distance(&p.id, target));
            }
        }
        let mut entries: Vec<(PeerId, (u128, u128))> = seen.into_iter().collect();
        entries.sort_by(|a, b| a.1.cmp(&b.1));
        let mut out: Vec<RtPeer> = Vec::new();
        for (id, _) in entries.into_iter().take(n) {
            if let Some(p) = self.find(&id) {
                out.push(p.clone());
            }
        }
        out
    }

    pub fn find(&self, id: &PeerId) -> Option<&RtPeer> {
        for b in self.buckets.values() {
            if let Some(p) = b.peers.iter().find(|p| &p.id == id) {
                return Some(p);
            }
        }
        self.seeds.iter().find(|p| &p.id == id)
    }

    pub fn len(&self) -> usize {
        self.buckets.values().map(|b| b.peers.len()).sum::<usize>() + self.seeds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Buckets that have not been recently touched (for RT refresh).
    pub fn stale_bucket_ids(&self) -> Vec<PeerId> {
        self.buckets.values().map(|b| b.id).collect()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::KadConfig;

    fn pid(bytes: &[u8; 4]) -> PeerId {
        let mut out = [0u8; 32];
        out[..4].copy_from_slice(bytes);
        PeerId(out)
    }

    #[test]
    fn cpl_of_same_id_is_full() {
        let a = pid(&[0xab, 0xcd, 0xef, 0x01]);
        assert_eq!(crate::cpl(&a, &a), 256);
    }

    #[test]
    fn cpl_of_first_byte_diff() {
        let a = pid(&[0x00, 0, 0, 0]);
        let b = pid(&[0x80, 0, 0, 0]); // differ on most significant bit
        assert_eq!(crate::cpl(&a, &b), 0);
    }

    #[test]
    fn cpl_of_second_byte_diff() {
        let a = pid(&[0xff, 0x00, 0, 0]);
        let b = pid(&[0xff, 0x80, 0, 0]); // first byte same, differ on MSB of second byte
        assert_eq!(crate::cpl(&a, &b), 8);
    }

    #[test]
    fn add_and_find_peer() {
        let me = pid(&[0, 0, 0, 0]);
        let mut rt = RoutingTable::new(me, KadConfig::default());
        let p = pid(&[0x10, 0, 0, 0]);
        assert!(rt.add_peer(RtPeer { id: p, ip_group: None }));
        assert!(rt.find(&p).is_some());
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn ip_diversity_cap_enforced() {
        let me = pid(&[0, 0, 0, 0]);
        let cfg = KadConfig { max_peers_per_ip_group_per_cpl: 2, ..KadConfig::default() };
        let mut rt = RoutingTable::new(me, cfg);
        // Same CPL (same high byte) and same IP group.
        let p1 = pid(&[0x10, 0, 0, 0]);
        let p2 = pid(&[0x11, 0, 0, 0]);
        let p3 = pid(&[0x12, 0, 0, 0]);
        assert!(rt.add_peer(RtPeer { id: p1, ip_group: Some(1) }));
        assert!(rt.add_peer(RtPeer { id: p2, ip_group: Some(1) }));
        // Third peer from same IP group in the same bucket is rejected.
        assert!(!rt.add_peer(RtPeer { id: p3, ip_group: Some(1) }));
    }
}

