//! HTTP / WebSocket API: site browsing, admin commands.
//!
//! Replaces ZeroNet's 949-line `UiRequest` + 1000-line `UiWebsocket`
//! with a clean axum/tokio-based router.

pub mod http;
pub mod ws;


/// The API server for a single node.
pub struct ApiServer {
    pub listen: std::net::SocketAddr,
}

impl ApiServer {
    pub fn new(listen: std::net::SocketAddr) -> Self {
        Self { listen }
    }
}

