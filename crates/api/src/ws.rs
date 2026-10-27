//! WebSocket endpoint: accept UI commands, reply with live node status.
//!
//! axum 0.7 pattern: the route handler takes a `WebSocketUpgrade`; calling
//! `on_upgrade` hands the real `WebSocket` to a follow-up handler.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::ApiState;

/// `GET /ws` — the upgrade endpoint. Replaces ZeroNet's 1000-line
/// `UiWebsocket` with one focused handler.
pub async fn ws_endpoint(State(s): State<ApiState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| socket_handler(s, socket))
}

/// Post-upgrade logic: send an initial status snapshot, then reply to any
/// command the UI sends with a fresh status.
async fn socket_handler(s: ApiState, mut socket: WebSocket) {
    let rt_len = s.dht.rt.lock().await.len();
    let status = json!({
        "type": "status",
        "rt_peers": rt_len,
        "version": env!("CARGO_PKG_VERSION"),
    });
    if socket
        .send(Message::Text(status.to_string().into()))
        .await
        .is_err()
    {
        return;
    }

    while let Some(Ok(msg)) = socket.recv().await {
        if let Message::Text(t) = msg {
            // Any command triggers a status reply. `t` is axum's Utf8Bytes in 0.8.
            let t = t.to_string();
            let rt_len = s.dht.rt.lock().await.len();
            let reply = json!({ "type": "ack", "cmd": t, "rt_peers": rt_len });
            if socket
                .send(Message::Text(reply.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    }
}
