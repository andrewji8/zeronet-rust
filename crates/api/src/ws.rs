//! WebSocket endpoints: real-time site status, admin commands.

use serde::{Deserialize, Serialize};

/// Commands sent over the WebSocket from the UI.
#[derive(Debug, Serialize, Deserialize)]
pub enum WsCommand {
    SiteReload { inner_path: String },
    SitePublish { inner_path: String, sign: bool },
    PeerPing { ip: String, port: u16 },
}
