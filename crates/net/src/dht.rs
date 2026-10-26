//! Wire DHT: the transport that turns Kademlia lookups into real TCP RPCs,
//! plus provider exchange over the wire.
//!
//! - `AddressBook` maps `PeerId -> SocketAddr` so a discovered peer id can be
//!   reached.
//! - `NetQueryTransport` implements `kad::query::lookup::QueryTransport` over
//!   real TCP: it sends `GetClosestPeers` to each seeded peer and returns the
//!   closer peers, while registering newly learned `(peer, addr)` pairs.
//! - `provide_over_wire` / `find_providers_over_wire` move provider records
//!   between nodes so `find_providers` is real, not just "closest peers".

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::net::TcpStream;

use kad::PeerId;
use kad::query::lookup::QueryTransport;

use crate::frame::{read_frame, write_frame};
use crate::rpc::Rpc;

/// `PeerId -> SocketAddr`, shared across the node.
pub struct AddressBook {
    map: Mutex<HashMap<PeerId, SocketAddr>>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }

    pub fn add(&self, id: PeerId, addr: SocketAddr) {
        self.map.lock().unwrap().insert(id, addr);
    }

    pub fn get(&self, id: &PeerId) -> Option<SocketAddr> {
        self.map.lock().unwrap().get(id).copied()
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    /// All known `(peer, addr)` pairs (for bootstrap / provider fan-out).
    pub fn drain(&self) -> Vec<(PeerId, SocketAddr)> {
        self.map.lock().unwrap().iter().map(|(k, v)| (*k, *v)).collect()
    }
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

/// One RPC request/response over a fresh TCP connection.
async fn rpc_roundtrip(addr: SocketAddr, req: &Rpc) -> Result<Value, String> {
    let mut stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let body = serde_json::to_string(req).map_err(|e| e.to_string())?;
    write_frame(&mut stream, body.as_bytes()).await.map_err(|e| e.to_string())?;
    let resp = read_frame(&mut stream).await.map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&resp).map_err(|e| e.to_string())?;
    Ok(v)
}

/// Parse the `peers` field of a `GetClosestPeers` reply:
/// `[{"id":"hex","addr":"host:port"}]` -> `Vec<(PeerId, Option<SocketAddr>)>`.
fn parse_peers(v: &Value) -> Vec<(PeerId, Option<SocketAddr>)> {
    let arr = match v.get("peers") {
        Some(Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for p in arr {
        if let Some(obj) = p.as_object() {
            let id_hex = obj.get("id").and_then(|s| s.as_str()).unwrap_or("");
            let id = PeerId(hex_to_bytes32(id_hex));
            let addr = obj
                .get("addr")
                .and_then(|s| s.as_str())
                .and_then(|a| a.parse::<SocketAddr>().ok());
            out.push((id, addr));
        }
    }
    out
}

fn hex_to_bytes32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    out
}

pub fn peer_hex(p: &PeerId) -> String {
    p.0.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A `QueryTransport` that issues `GetClosestPeers` over real TCP.
///
/// While querying it also learns `(peer, addr)` pairs (from the `addr` field
/// of the reply) and records them in the shared `AddressBook`, and registers
/// closer peers into the routing table — this is how two nodes actually
/// discover each other.
pub struct NetQueryTransport {
    pub addr_book: Arc<AddressBook>,
    /// Kademlia routing table to register learned peers into.
    pub dht: Option<Arc<kad::Kademlia>>,
}

impl NetQueryTransport {
    pub fn new(addr_book: Arc<AddressBook>) -> Self {
        Self { addr_book, dht: None }
    }

    pub fn with_dht(mut self, dht: Arc<kad::Kademlia>) -> Self {
        self.dht = Some(dht);
        self
    }
}

impl QueryTransport for NetQueryTransport {
    async fn query_peers(
        &self,
        peer: &PeerId,
        target: &PeerId,
    ) -> Result<Vec<PeerId>, String> {
        let addr = self.addr_book.get(peer).ok_or_else(|| format!("no address for {peer:?}"))?;
        let req = Rpc::GetClosestPeers { target: target.0 };
        let resp = rpc_roundtrip(addr, &req).await?;
        if resp.get("ok") != Some(&json!(true)) {
            return Err(format!("peer refused: {}", resp.get("error").unwrap_or(&json!("?"))));
        }
        let learned = parse_peers(&resp);
        let mut out: Vec<PeerId> = Vec::new();
        for (id, maybe_addr) in &learned {
            // register learned address
            if let Some(a) = *maybe_addr {
                self.addr_book.add(*id, a);
            }
            // register closer peer in the routing table
            if let Some(dht) = &self.dht {
                if let Ok(mut g) = dht.rt.try_lock() {
                    let _ = g.add_peer(kad::rt::RtPeer { id: *id, ip_group: None });
                }
            }
            out.push(*id);
        }
        Ok(out)
    }
}

/// Ask the `n` known peers to record `provider` as a provider of `content_key`.
///
/// Sends `PutValue { key, record: <provider hex> }` to each peer in the
/// address book. Each peer's server stores it in its shared provider store.
pub async fn provide_over_wire(
    local_store: &Arc<tokio::sync::Mutex<kad::ProviderStore>>,
    addr_book: &AddressBook,
    content_key: &[u8],
    provider: PeerId,
    count: usize,
) -> Result<(), String> {
    let key32 = kad::hash_key(content_key);
    // Local accounting: a provider always knows it provides its content.
    local_store.lock().await.add(key32, provider);
    let key = key32.to_vec();

    let mut targets = addr_book.drain();
    targets.truncate(count.max(1));
    if targets.is_empty() {
        return Err("no peers to provide to".into());
    }
    let record = peer_hex(&provider);
    for (_peer, addr) in targets {
        let req = Rpc::PutValue { key: key.clone(), record: record.clone().into_bytes() };
        let _ = rpc_roundtrip(addr, &req).await;
    }
    Ok(())
}

/// Find providers of `content_key` by asking the known peers; returns
/// `(provider peer id, optional address)` pairs actually stored on the wire.
pub async fn find_providers_over_wire(
    addr_book: &AddressBook,
    content_key: &[u8],
    count: u32,
) -> Vec<(PeerId, Option<SocketAddr>)> {
    let targets = addr_book.drain();
    let key = kad::hash_key(content_key).to_vec();
    let mut out: Vec<(PeerId, Option<SocketAddr>)> = Vec::new();
    for (_peer, addr) in targets.iter() {
        let req = Rpc::FindProviders { content_key: key.clone(), count };
        let resp = rpc_roundtrip(*addr, &req).await.ok();
        if let Some(v) = resp {
            if v.get("ok") == Some(&json!(true)) {
                for p in parse_peers(&v) {
                    if !out.iter().any(|(o, _)| o == &p.0) {
                        out.push(p);
                    }
                }
            }
        }
    }
    out
}


/// Connect to `addr`, exchange a `Handshake`, learn the remote peer's id and
/// address, and register both in this node's routing table and address book.
///
/// This is the bootstrap primitive that lets two otherwise-unknown nodes
/// discover each other: after `connect_and_bootstrap` succeeds, `remote` is a
/// known peer of this node (and, symmetrically, this node is a known peer of
/// `remote` once it does the same).
pub async fn connect_and_bootstrap(
    dht: Arc<kad::Kademlia>,
    addr_book: &AddressBook,
    addr: SocketAddr,
) -> Result<PeerId, String> {
    let req = Rpc::Handshake {
        peer: peer_hex(&dht.self_id),
        protocol: "zrs/1".to_string(),
    };
    let resp = rpc_roundtrip(addr, &req).await?;
    if resp.get("ok") != Some(&json!(true)) {
        return Err(format!("handshake refused: {}", resp.get("error").unwrap_or(&json!("?"))));
    }
    let hex = resp.get("self_peer").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let remote = PeerId(hex_to_bytes32(&hex));
    addr_book.add(remote, addr);
    if let Ok(mut g) = dht.rt.try_lock() {
        let _ = g.add_peer(kad::rt::RtPeer { id: remote, ip_group: None });
    }
    Ok(remote)
}






/// Resolve a peer id to a reachable `SocketAddr` using the address book.
///
/// Provider ids returned by `find_providers_over_wire` are reachable only if
/// we learned their address (either from a `GetClosestPeers` reply that
/// carries `addr`, or from a bootstrap/handshake). This helper centralizes
/// that lookup for the download path.
pub fn peer_addr(addr_book: &AddressBook, id: &PeerId) -> Option<SocketAddr> {
    addr_book.get(id)
}
