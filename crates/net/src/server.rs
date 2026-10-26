//! Inbound peer RPC server: accepts TCP connections, speaks the
//! length-prefixed JSON frame protocol, and dispatches `Rpc` requests.
//!
//! This is what makes a node actually *run*: it listens, answers
//! `GetClosestPeers` from its Kademlia table, serves `GetFile` from the local
//! site directory, and echoes `Handshake`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use kad::{Kademlia, PeerId};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::frame::{read_frame, write_frame};
use crate::rpc::{FileResponse, Rpc};

/// A running inbound server. Call `stop()` to shut the accept loop down and
/// wait for it to finish.
pub struct ServerHandle {
    pub addr: SocketAddr,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl ServerHandle {
    /// Stop the accept loop and wait for it to drain.
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

/// Start an inbound RPC server serving local sites under `site_root`,
/// answering `GetClosestPeers` from the Kademlia routing table.
pub async fn start(dht: Arc<Kademlia>, site_root: PathBuf) -> Result<ServerHandle, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(run_accept(listener, dht, site_root, stop_rx));
    Ok(ServerHandle {
        addr,
        stop_tx: Some(stop_tx),
        handle: Some(handle),
    })
}

async fn run_accept(
    listener: TcpListener,
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        let dht = Arc::clone(&dht);
                        let root = site_root.clone();
                        tokio::spawn(handle_conn(stream, dht, root, peer_addr));
                    }
                    Err(_) => continue,
                }
            }
        }
    }
}

/// Handle one client connection: process request frames until it closes or
/// errors.
async fn handle_conn(
    stream: tokio::net::TcpStream,
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    _peer: SocketAddr,
) {
    let mut stream = stream;
    loop {
        let req_bytes = match read_frame(&mut stream).await {
            Ok(b) => b,
            Err(_) => break,
        };
        let resp = dispatch(&dht, &site_root, &req_bytes).await;
        if write_frame(&mut stream, &resp).await.is_err() {
            break;
        }
    }
}

/// Turn a raw request frame into a raw response frame body.
async fn dispatch(dht: &Kademlia, site_root: &Path, req_bytes: &[u8]) -> Vec<u8> {
    let rpc: Rpc = match serde_json::from_slice(req_bytes) {
        Ok(r) => r,
        Err(_) => {
            return json!({ "ok": false, "error": "bad request" }).to_string().into_bytes()
        }
    };

    match rpc {
        Rpc::Handshake { peer, protocol } => {
            json!({ "Handshake": { "peer": peer, "protocol": protocol, "ok": true } })
                .to_string()
                .into_bytes()
        }
        Rpc::GetClosestPeers { target } => {
            let target_peer = PeerId(target);
            let peers = {
                let rt = dht.rt.lock().await;
                rt.nearest_peers(&target_peer, dht.config.bucket_size as usize)
            };
            let ids: Vec<String> = peers.iter().map(peer_hex).collect();
            json!({ "GetClosestPeers": { "ok": true, "peers": ids } })
                .to_string()
                .into_bytes()
        }
        Rpc::GetFile { site, path } => {
            let file_path = site_root.join(&site).join(&path);
            // Path-traversal guard: the resolved path must stay under site_root.
            let safe = file_path.starts_with(site_root);
            let resp: FileResponse = match tokio::fs::read(&file_path).await {
                Ok(bytes) if safe => FileResponse {
                    ok: true,
                    path: path.clone(),
                    data_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
                    error: None,
                },
                Ok(_) => FileResponse {
                    ok: false,
                    path,
                    data_b64: String::new(),
                    error: Some("unsafe path (outside site_root)".to_string()),
                },
                Err(e) => FileResponse {
                    ok: false,
                    path,
                    data_b64: String::new(),
                    error: Some(e.to_string()),
                },
            };
            let v: serde_json::Value = serde_json::to_value(&resp).unwrap_or_default();
            v.to_string().into_bytes()
        }
        Rpc::GetValue { .. } | Rpc::PutValue { .. } | Rpc::FindProviders { .. } => {
            // DHT value/provider RPCs are not wired to a live network yet.
            json!({ "ok": false, "error": "not implemented in this node build" })
                .to_string()
                .into_bytes()
        }
    }
}

/// Hex-encode a peer id for wire output.
fn peer_hex(p: &kad::rt::RtPeer) -> String {
    p.id.0
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

