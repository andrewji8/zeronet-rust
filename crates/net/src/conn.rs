//! Connection pool keyed by peer id.

use std::net::SocketAddr;

use kad::PeerId;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Connection pool keyed by peer id.
pub struct Pool {
    conns: Mutex<std::collections::HashMap<PeerId, (SocketAddr, TcpStream)>>,
}

impl Pool {
    pub fn new() -> Self {
        Self {
            conns: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Register or replace the connection for `id`.
    pub async fn insert(&self, id: PeerId, addr: SocketAddr, stream: TcpStream) {
        self.conns.lock().await.insert(id, (addr, stream));
    }

    /// Number of live connections.
    pub async fn len(&self) -> usize {
        self.conns.lock().await.len()
    }

    /// Whether any live connections exist.
    pub async fn is_empty(&self) -> bool {
        self.conns.lock().await.is_empty()
    }

    /// Look up the address for a known peer.
    pub async fn addr_of(&self, id: &PeerId) -> Option<SocketAddr> {
        self.conns.lock().await.get(id).map(|(a, _)| *a)
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}
