//! Download + verify + store path.
//!
//! Ties together: `net::peer` (fetch over TCP), `storage::store_verified`
//! (BLAKE3 check + path-traversal guard + write). This is the "real"
//! download path replacing the earlier NotImplemented stub.
//!
//! `download_via_dht` closes the full chain: discover providers over the DHT
//! (`net::dht`), resolve each to a reachable address, and download until one
//! verifies.

use std::net::SocketAddr;
use std::path::Path;

use net::peer::{self, PeerError};
use net::AddressBook;

/// Download one file from `addr` and store it under `root/rel_path`,
/// after BLAKE3-verifying it against `expected`.
pub async fn download_and_store(
    addr: SocketAddr,
    site: &str,
    rel_path: &str,
    expected: [u8; 32],
    root: &Path,
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

/// The full chain: **discover -> download -> verify -> store**.
///
/// 1. `net::dht::find_providers_over_wire` asks the known nodes who provides
///    `content_key`.
/// 2. Each returned provider is resolved to a reachable address (from the
///    provider record or the address book).
/// 3. `download_and_store` is tried on each provider in turn; the first that
///    BLAKE3-verifies wins.
///
/// This is what makes a node genuinely useful: it asks the network where a
/// file lives, then fetches and verifies it — no tracker, no central list.
pub async fn download_via_dht(
    addr_book: &AddressBook,
    content_key: &[u8],
    site: &str,
    path: &str,
    expected: [u8; 32],
    root: &Path,
    provider_count: u32,
) -> Result<std::path::PathBuf, DownloadError> {
    let providers =
        net::dht::find_providers_over_wire(addr_book, content_key, provider_count).await;
    if providers.is_empty() {
        return Err(DownloadError::NoProvider);
    }

    let mut last_err = None;
    for (peer_id, known_addr) in &providers {
        let addr = (*known_addr).or_else(|| net::dht::peer_addr(addr_book, peer_id));
        let addr = match addr {
            Some(a) => a,
            None => continue,
        };
        match download_and_store(addr, site, path, expected, root).await {
            Ok(p) => return Ok(p),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(DownloadError::NoProvider))
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("peer: {0}")]
    Peer(#[from] PeerError),
    #[error("secure: {0}")]
    Secure(String),
    #[error("store: {0}")]
    Store(String),
    #[error("no reachable provider found for content key")]
    NoProvider,
}

/// Map a download error to a human-readable stage for logs.
pub fn stage_of(err: &DownloadError) -> &'static str {
    match err {
        DownloadError::Peer(PeerError::Io(_)) => "connect",
        DownloadError::Peer(PeerError::Frame(_)) => "frame",
        DownloadError::Peer(PeerError::Json(_)) => "parse",
        DownloadError::Peer(PeerError::PeerError(_)) => "peer-reply",
        DownloadError::Store(_) => "verify-or-write",
        DownloadError::Secure(_) => "secure-channel",
        DownloadError::NoProvider => "discovery",
    }
}

/// Fetch a file over a Noise-XX-encrypted channel, returning the bytes.
///
/// Connect + handshake to `addr` (a `net::server::start_secure` endpoint),
/// then one encrypted `GetFile` round-trip. This is the encrypted twin of
/// [`fetch_file`].
pub async fn secure_fetch_file(
    addr: SocketAddr,
    identity: &net::NoiseIdentity,
    site: &str,
    path: &str,
) -> Result<Vec<u8>, DownloadError> {
    net::sec_get_file(addr, identity, site, path)
        .await
        .map_err(|e| DownloadError::Secure(e.to_string()))
}

/// The full encrypted chain: **discover -> download (Noise) -> verify ->
/// store**.
///
/// 1. `net::dht::find_providers_over_wire_secure` asks the known nodes who
///    provides `content_key`, each query running inside its own Noise-XX
///    handshake.
/// 2. Each provider is resolved to a reachable address (from the provider
///    record or the address book).
/// 3. `net::sec_get_file` fetches the bytes over a fresh encrypted channel;
///    the first provider that BLAKE3-verifies wins.
#[allow(clippy::too_many_arguments)]
pub async fn download_via_dht_secure(
    addr_book: &AddressBook,
    identity: &net::NoiseIdentity,
    content_key: &[u8],
    site: &str,
    path: &str,
    expected: [u8; 32],
    root: &Path,
    provider_count: u32,
) -> Result<std::path::PathBuf, DownloadError> {
    let providers =
        net::dht::find_providers_over_wire_secure(addr_book, identity, content_key, provider_count)
            .await;
    if providers.is_empty() {
        return Err(DownloadError::NoProvider);
    }

    let mut last_err = None;
    for (peer_id, known_addr) in &providers {
        let addr = (*known_addr).or_else(|| net::dht::peer_addr(addr_book, peer_id));
        let addr = match addr {
            Some(a) => a,
            None => continue,
        };
        match secure_fetch_file(addr, identity, site, path).await {
            Ok(data) => {
                storage::store_verified(root, expected, path, &data)
                    .await
                    .map_err(|e| DownloadError::Store(e.to_string()))?;
                return Ok(root.join(path));
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(DownloadError::NoProvider))
}
