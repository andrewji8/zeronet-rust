//! Hash field index: fast lookup of which files are in the local cache.
//!
//! Replaces ZeroNet's `PeerHashfield` (a binary trie of file hashes).

use std::collections::HashSet;

/// An in-memory set of hashes for files currently present locally.
#[derive(Default)]
pub struct HashField {
    hashes: HashSet<[u8; 32]>,
}

impl HashField {
    pub fn new() -> Self {
        Self {
            hashes: HashSet::new(),
        }
    }

    pub fn insert(&mut self, h: [u8; 32]) {
        self.hashes.insert(h);
    }

    pub fn remove(&mut self, h: [u8; 32]) -> bool {
        self.hashes.remove(&h)
    }

    pub fn has(&self, h: &[u8; 32]) -> bool {
        self.hashes.contains(h)
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Which of `wanted` hashes are NOT present locally.
    pub fn missing(&self, wanted: &[[u8; 32]]) -> Vec<[u8; 32]> {
        wanted.iter().filter(|h| !self.has(h)).copied().collect()
    }

    /// All stored hashes (for persistence).
    pub fn all(&self) -> Vec<[u8; 32]> {
        self.hashes.iter().copied().collect()
    }
}
