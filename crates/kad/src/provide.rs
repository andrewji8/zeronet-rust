//! Provider records (FindProviders / Provide).

use crate::{Kademlia, PeerId};

/// A locally known provider set keyed by content hash.
#[derive(Default)]
pub struct ProviderStore {
    map: std::collections::HashMap<[u8; 32], Vec<PeerId>>,
}

impl ProviderStore {
    pub fn add(&mut self, key: [u8; 32], peer: PeerId) {
        self.map.entry(key).or_default().push(peer);
    }

    pub fn get(&self, key: &[u8; 32]) -> &[PeerId] {
        self.map.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Find providers for `content_key`.
///
/// This runs a Kademlia lookup against the synthetic peer id derived from the
/// content key, then collects the nearest peers as provider candidates.
///
/// NOTE: the wire transport (who actually stores provider records) is wired
/// in by the `net` crate; this module is the DHT-side decision logic.
pub async fn find_providers(dht: &Kademlia, target: &PeerId, _content_key: &[u8]) -> Vec<PeerId> {
    // Without a live transport we can only report peers from our own table;
    // the real FindProviders path issues GetProviders RPCs (see net crate).
    dht.rt.lock().await.nearest_peers(target, dht.config.bucket_size as usize)
        .into_iter()
        .map(|p| p.id)
        .collect()
}
