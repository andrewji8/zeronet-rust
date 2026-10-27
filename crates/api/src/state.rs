//! Shared state passed to every axum handler.

use std::path::PathBuf;
use std::sync::Arc;

use kad::{Kademlia, ProviderStore};
use net::AddressBook;

/// Everything an API handler may need, cheaply cloned (`Arc` internals).
#[derive(Clone)]
pub struct ApiState {
    /// The node's Kademlia DHT (routing table + self id).
    pub dht: Arc<Kademlia>,
    /// Shared provider records (who provides what).
    pub providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    /// Discovered peer addresses.
    pub addr_book: Arc<AddressBook>,
    /// Local site directories (for file serving).
    pub site_root: PathBuf,
}

/// Hex-encode a 32-byte key (peer id / content key).
pub fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Parse a 64-hex-char string into 32 bytes.
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
