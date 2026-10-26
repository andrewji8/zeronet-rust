//! Download + verify + store path.
//!
//! Ties together: `net::peer` (fetch over TCP), `storage::store_verified`
//! (BLAKE3 check + path-traversal guard + write). This is the "real"
//! download path replacing the earlier NotImplemented stub.

use std::net::SocketAddr;

use net::peer::{self, PeerError};

/// Download one file from `addr` and store it under `root/rel_path`,
/// after BLAKE3-verifying it against `expected`.
pub async fn download_and_store(
    addr: SocketAddr,
    site: &str,
    rel_path: &str,
    expected: [u8; 32],
    root: &std::path::Path,
) -> Result<std::path::PathBuf, DownloadError> {
    let data = peer::get_file(addr, site, rel_path).await?;
    storage::store_verified(root, expected, rel_path, &data)
        .await
        .map_err(|e| DownloadError::Store(e.to_string()))?;
    Ok(root.join(rel_path))
}

/// Download a file and return its bytes (no store), for callers that want
/// to verify / hash themselves.
pub async fn fetch_file(
    addr: SocketAddr,
    site: &str,
    path: &str,
) -> Result<Vec<u8>, DownloadError> {
    let b = peer::get_file(addr, site, path).await?;
    Ok(b)
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("peer: {0}")]
    Peer(#[from] PeerError),
    #[error("store: {0}")]
    Store(String),
}

/// Map a peer error to a human-readable stage for logs.
pub fn stage_of(err: &DownloadError) -> &'static str {
    match err {
        DownloadError::Peer(PeerError::Io(_)) => "connect",
        DownloadError::Peer(PeerError::Frame(_)) => "frame",
        DownloadError::Peer(PeerError::Json(_)) => "parse",
        DownloadError::Peer(PeerError::PeerError(_)) => "peer-reply",
        DownloadError::Store(_) => "verify-or-write",
    }
}

