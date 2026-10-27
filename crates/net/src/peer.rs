//! A client that talks to a single peer over TCP.
//!
//! Wire protocol: one JSON `Rpc` request per length-prefixed frame (see
//! `frame.rs`). `GetFile` responses use the `FileResponse` shape.

use std::net::SocketAddr;

use base64::Engine;
use serde_json::json;
use tokio::net::TcpStream;

use crate::frame::{read_frame, write_frame, NetErr};
use crate::rpc::{FileResponse, Rpc};

/// Errors for peer operations.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("framing: {0}")]
    Frame(#[from] NetErr),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("peer returned error: {0}")]
    PeerError(String),
}

/// Perform a `GetFile` RPC against `addr`, returning the raw file bytes.
///
/// The request is framed as a JSON `Rpc::GetFile`; the response is a JSON
/// `FileResponse` with base64 data. A single round-trip.
pub async fn get_file(addr: SocketAddr, site: &str, path: &str) -> Result<Vec<u8>, PeerError> {
    let mut stream = TcpStream::connect(addr).await?;

    let req = json!(Rpc::GetFile {
        site: site.to_string(),
        path: path.to_string(),
    });
    write_frame(&mut stream, req.to_string().as_bytes()).await?;

    let resp_bytes = read_frame(&mut stream).await?;
    let resp: FileResponse = serde_json::from_slice(&resp_bytes)?;
    if !resp.ok {
        return Err(PeerError::PeerError(
            resp.error.unwrap_or_else(|| "no error detail".into()),
        ));
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(&resp.data_b64)
        .map_err(|e| PeerError::PeerError(format!("bad base64: {e}")))?;
    Ok(data)
}
