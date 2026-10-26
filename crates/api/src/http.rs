//! HTTP endpoints: serve site files, DHT status, admin commands.

use serde_json::json;

/// Response body types for the HTTP API.
pub struct StatusResponse {
    pub version: &'static str,
    pub rt_peers: usize,
}

/// Serialize a status response.
pub fn status_json(v: &str, rt_peers: usize) -> String {
    json!({ "version": v, "rt_peers": rt_peers }).to_string()
}
