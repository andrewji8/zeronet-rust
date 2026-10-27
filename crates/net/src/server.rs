//! Inbound peer RPC server: accepts TCP connections, speaks the
//! length-prefixed JSON frame protocol, and dispatches `Rpc` requests.
//!
//! This is what makes a node actually *run*: it listens, answers
//! `GetClosestPeers` from its Kademlia table (with learned addresses),
//! exchanges `PutValue`/`FindProviders` provider records, serves `GetFile`
//! from the local site directory, and echoes `Handshake`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use kad::{Kademlia, PeerId, ProviderStore};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::dht::{peer_hex, AddressBook};
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
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

/// Start an inbound RPC server on an ephemeral loopback port
/// (`127.0.0.1:0`). Convenience wrapper around [`start_at`].
pub async fn start(
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
) -> Result<ServerHandle, std::io::Error> {
    start_at(
        dht,
        site_root,
        providers,
        addr_book,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
}

/// Start an inbound RPC server on `listen`, serving local sites under
/// `site_root`, answering `GetClosestPeers` from the Kademlia routing table
/// and `PutValue`/`FindProviders` from the shared provider store.
pub async fn start_at(
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    listen: SocketAddr,
) -> Result<ServerHandle, std::io::Error> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(run_accept(
        listener, dht, site_root, providers, addr_book, stop_rx,
    ));
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
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
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
                        let prov = Arc::clone(&providers);
                        let ab = Arc::clone(&addr_book);
                        tokio::spawn(handle_conn(stream, dht, root, prov, ab, peer_addr));
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
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    _peer: SocketAddr,
) {
    let mut stream = stream;
    loop {
        let req_bytes = match read_frame(&mut stream).await {
            Ok(b) => b,
            Err(_) => break,
        };
        let resp = dispatch(&dht, &site_root, &providers, &addr_book, &req_bytes).await;
        if write_frame(&mut stream, &resp).await.is_err() {
            break;
        }
    }
}

/// Turn a raw request frame into a raw response frame body.
pub(crate) async fn dispatch(
    dht: &Kademlia,
    site_root: &Path,
    providers: &Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: &Arc<AddressBook>,
    req_bytes: &[u8],
) -> Vec<u8> {
    let rpc: Rpc = match serde_json::from_slice(req_bytes) {
        Ok(r) => r,
        Err(_) => {
            return json!({ "ok": false, "error": "bad request" })
                .to_string()
                .into_bytes()
        }
    };

    match rpc {
        Rpc::Handshake { peer: _, protocol } => {
            // Echo our own id + address so the caller can register us.
            json!({
                "ok": true,
                "protocol": protocol,
                "self_peer": peer_hex(&dht.self_id),
            })
            .to_string()
            .into_bytes()
        }
        Rpc::GetClosestPeers { target } => {
            let target_peer = PeerId(target);
            let peers = {
                let rt = dht.rt.lock().await;
                rt.nearest_peers(&target_peer, dht.config.bucket_size as usize)
            };
            let items: Vec<Value> = peers
                .iter()
                .map(|p| {
                    let ab = addr_book.get(&p.id);
                    json!({
                        "id": peer_hex(&p.id),
                        "addr": ab.map(|a| a.to_string()),
                    })
                })
                .collect();
            json!({ "ok": true, "peers": items })
                .to_string()
                .into_bytes()
        }
        Rpc::PutValue { key, record } => {
            // `record` carries the provider peer id (hex). Store it under key.
            let provider = PeerId(hex_to_bytes32(&record_hex(&record)));
            {
                let mut store = providers.lock().await;
                let mut out = [0u8; 32];
                // key is a 32-byte hash; pad/truncate.
                let n = key.len().min(32);
                out[..n].copy_from_slice(&key[..n]);
                store.add(out, provider);
            }
            json!({ "ok": true }).to_string().into_bytes()
        }
        Rpc::FindProviders { content_key, count } => {
            let mut out = [0u8; 32];
            let n = content_key.len().min(32);
            out[..n].copy_from_slice(&content_key[..n]);
            let provs = providers.lock().await.get(&out).to_vec();
            let items: Vec<Value> = provs
                .iter()
                .map(|p| {
                    let ab = addr_book.get(p);
                    json!({
                        "id": peer_hex(p),
                        "addr": ab.map(|a| a.to_string()),
                    })
                })
                .take(count as usize)
                .collect();
            json!({ "ok": true, "peers": items })
                .to_string()
                .into_bytes()
        }
        Rpc::GetValue { key } => {
            // We do not store arbitrary values in this build; report empty.
            let _ = key;
            json!({ "ok": false, "error": "not a provider" })
                .to_string()
                .into_bytes()
        }
        Rpc::GetFile { site, path } => {
            let file_path = site_root.join(&site).join(&path);
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
    }
}

fn record_hex(record: &[u8]) -> String {
    std::str::from_utf8(record).unwrap_or("").to_string()
}

fn hex_to_bytes32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    out
}

/// A running secure inbound server: accepts TCP, performs the Noise-XX
/// responder handshake, and serves encrypted frames through the same
/// `dispatch` the plaintext server uses.
pub struct SecureServerHandle {
    pub addr: SocketAddr,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl SecureServerHandle {
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

/// Start a secure inbound server on an ephemeral loopback port.
pub async fn start_secure(
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    identity: &crate::secure::NoiseIdentity,
) -> Result<SecureServerHandle, std::io::Error> {
    start_secure_at(
        dht,
        site_root,
        providers,
        addr_book,
        identity,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
}

/// Start a secure inbound server on `listen`.
pub async fn start_secure_at(
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    identity: &crate::secure::NoiseIdentity,
    listen: SocketAddr,
) -> Result<SecureServerHandle, std::io::Error> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let id2 = identity.clone();
    let handle = tokio::spawn(run_secure_accept(
        listener, dht, site_root, providers, addr_book, id2, stop_rx,
    ));
    Ok(SecureServerHandle {
        addr,
        stop_tx: Some(stop_tx),
        handle: Some(handle),
    })
}

async fn run_secure_accept(
    listener: TcpListener,
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    identity: crate::secure::NoiseIdentity,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let dht = Arc::clone(&dht);
                        let root = site_root.clone();
                        let prov = Arc::clone(&providers);
                        let ab = Arc::clone(&addr_book);
                        let id = identity.clone();
                        tokio::spawn(handle_secure_conn(stream, dht, root, prov, ab, id));
                    }
                    Err(_) => continue,
                }
            }
        }
    }
}

/// One secure client: run the responder-side Noise-XX handshake, then serve
/// encrypted request frames until the channel errors or closes.
async fn handle_secure_conn(
    stream: tokio::net::TcpStream,
    dht: Arc<Kademlia>,
    site_root: PathBuf,
    providers: Arc<tokio::sync::Mutex<ProviderStore>>,
    addr_book: Arc<AddressBook>,
    identity: crate::secure::NoiseIdentity,
) {
    let mut conn = match crate::secure::responder_handshake(stream, &identity).await {
        Ok((c, _)) => c,
        Err(_) => return,
    };
    loop {
        let req_bytes = match conn.recv().await {
            Ok(b) => b,
            Err(_) => break,
        };
        let resp = dispatch(&dht, &site_root, &providers, &addr_book, &req_bytes).await;
        if conn.send(&resp).await.is_err() {
            break;
        }
    }
}
