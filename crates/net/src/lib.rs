//! Network transport layer: TCP connections, message framing, DHT RPC.
//!
//! Replaces ZeroNet's `Connection`/`ConnectionServer`/`Peer` modules with
//! tokio-native sockets (no gevent monkey-patch).

pub mod conn;
pub mod frame;
pub mod rpc;
pub mod peer;

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

/// Manage a pool of peer connections.
pub struct ConnectionManager {
    pub kademlia: Arc<Kademlia>,
    pub inbound: Arc<Mutex< Vec<PeerConn>  >>,
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

    /// Open an outbound connection to 	arget at ddr.
    pub async fn connect_outbound(&self, target: PeerId, addr: SocketAddr) -> Result<TcpStream, NetError> {
        let stream = TcpStream::connect(addr).await?;
        // In a full implementation, record the connection in the pool keyed by 	arget
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



