//! Wire RPC messages.
//!
//! DHT RPCs (GetValue/PutValue/...) coexist with content-download RPCs
//! (GetFile). Requests are serialized to a JSON body inside a length-prefixed
//! frame (see `frame.rs`); `GetFile` responses use the distinct `FileResponse`
//! shape.

use serde::{Deserialize, Serialize};

/// A request sent from client to peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rpc {
    // --- DHT discovery / value ---
    /// Get the value stored at a DHT key.
    GetValue { key: Vec<u8> },
    /// Put a signed value into the DHT under a key.
    PutValue { key: Vec<u8>, record: Vec<u8> },
    /// Find providers of a content key.
    FindProviders { content_key: Vec<u8>, count: u32 },
    /// Get the K closest peers to a target.
    GetClosestPeers { target: [u8; 32] },

    // --- handshake ---
    /// Protocol handshake exchanged on connect. The peer echoes it back.
    Handshake {
        peer: String,
        protocol: String,
    },

    // --- content download ---
    /// Fetch one file by site address + relative path.
    GetFile { site: String, path: String },
}

/// Response to a `GetFile` request: base64-encoded file bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResponse {
    pub ok: bool,
    pub path: String,
    /// base64 of the file bytes (empty when `ok` is false).
    #[serde(default)]
    pub data_b64: String,
    #[serde(default)]
    pub error: Option<String>,
}
