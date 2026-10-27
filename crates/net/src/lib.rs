//! Network transport layer: TCP connections, message framing, DHT RPC.
//!
//! Replaces ZeroNet's `Connection`/`ConnectionServer`/`Peer` modules with
//! tokio-native sockets (no gevent monkey-patch).

pub mod conn;
pub mod dht;
pub mod frame;
pub mod peer;
pub mod rpc;
pub mod secure;
pub mod server;

use std::net::SocketAddr;
use std::sync::Arc;

use kad::{Kademlia, PeerId};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// An outbound/inbound connection to a single peer.
pub struct PeerConn {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub stream: TcpStream,
}

/// Wire DHT helpers (transport, address book, provider exchange).
pub use dht::{
    find_providers_over_wire, peer_addr, provide_over_wire, AddressBook, NetQueryTransport,
};

/// Secure Noise-XX transport API (X25519 + HKDF + ChaCha20-Poly1305).
///
/// This is the formal P2P encryption layer that replaces ZeroNet's
/// `fakedomains` SNI anti-DPI hack: it authenticates both peers (mutual
/// static keys) and is forward-secret (fresh ephemeral key per session).
pub use secure::{
    initiator_handshake, responder_handshake, sec_get_file, NoiseIdentity, SecErr, SecureConn,
};

/// Manage a pool of peer connections.
pub struct ConnectionManager {
    pub kademlia: Arc<Kademlia>,
    pub inbound: Arc<Mutex<Vec<PeerConn>>>,
    pub listen_addr: SocketAddr,
}

impl ConnectionManager {
    pub async fn start(dht: Arc<Kademlia>, listen: SocketAddr) -> Result<Self, NetError> {
        let _listener = TcpListener::bind(listen).await?;
        Ok(Self {
            kademlia: dht,
            inbound: Arc::new(Mutex::new(Vec::new())),
            listen_addr: listen,
        })
    }

    /// Open an outbound connection to target at addr.
    pub async fn connect_outbound(
        &self,
        target: PeerId,
        addr: SocketAddr,
    ) -> Result<TcpStream, NetError> {
        let stream = TcpStream::connect(addr).await?;
        // In a full implementation, record the connection in the pool keyed by target
        // and run the handshake + DHT protocol on top of it.
        let _ = target;
        Ok(stream)
    }
}

/// Errors in the network layer.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
}
