//! HTTP / WebSocket API: node status, site browsing, DHT download trigger.
//!
//! Replaces ZeroNet's 949-line `UiRequest` + 1000-line `UiWebsocket` with a
//! clean axum router.

pub mod http;
pub mod state;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use kad::{Kademlia, ProviderStore};
use net::AddressBook;
use tokio::net::TcpListener;

use state::ApiState;

/// Build the axum router for a node.
pub fn build_router(
    dht: Arc<Kademlia>,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    site_root: std::path::PathBuf,
) -> Router {
    let s = ApiState {
        dht,
        providers,
        addr_book,
        site_root,
    };
    Router::new()
        .route("/status", axum::routing::get(http::status))
        .route("/sites/{site}/{path}", axum::routing::get(http::serve_site))
        .route("/download", axum::routing::post(http::download))
        .route("/ws", axum::routing::get(ws::ws_endpoint))
        .with_state(s)
}

/// Start the API server on `listen`, serving until the process exits.
pub async fn start_at(
    dht: Arc<Kademlia>,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    site_root: std::path::PathBuf,
    listen: SocketAddr,
) -> Result<(), std::io::Error> {
    let app = build_router(dht, providers, addr_book, site_root);
    let listener = TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
