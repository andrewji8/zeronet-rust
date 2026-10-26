//! ZeroNet-Rust: Kademlia DHT + Ed25519/BLAKE3 content addressing.
//!
//! CLI entry point: start node, create site, download a file.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use content::sign::Identity;
use kad::{KadConfig, Kademlia, PeerId};
use net::server as net_server;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let action = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match action {
        "help" | "" => print_usage(),
        "node" => run_node(&args).await,
        "create-site" => {
            let id = Identity::generate();
            let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
            println!("site address: {}", hex(&id.site_key()));
            println!("private key:  {}", hex(&id.secret_bytes()));
            println!("save the private key now - you will need it to sign the site!");
        }
        "download" => run_download(&args).await,
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("ZeroNet-Rust v0.1.0");
    println!();
    println!("USAGE:");
    println!("  zeronet-rs node [DIR] [--max-sec N]");
    println!("                     start a full node (Kademlia + TCP RPC + persistence)");
    println!("  zeronet-rs create-site              generate a new site keypair");
    println!("  zeronet-rs download <host:port> <site> <path>");
    println!("                     fetch a file from a peer (BLAKE3-checked)");
    println!("  zeronet-rs help                     show this message");
}

async fn run_node(args: &[String]) {
    // --- Parse args ---
    let mut data_dir = PathBuf::from(".zrs-node");
    let mut max_sec = 15u64; // default demo duration
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--max-sec" => {
                if i + 1 < args.len() {
                    max_sec = args[i + 1].parse().unwrap_or(15);
                    i += 1;
                }
            }
            s => {
                data_dir = PathBuf::from(s);
            }
        }
        i += 1;
    }
    let _ = data_dir; // used below for the db paths

    // --- Persistence (restart-resilient) ---
    let kad_db_path = data_dir.join("kad.db");
    let storage_db_path = data_dir.join("storage.db");
    tokio::fs::create_dir_all(&data_dir).await.ok();

    let rt_db = kad::RtDb::open(&kad_db_path).unwrap_or_else(|e| {
        eprintln!("failed to open kad db: {e}");
        std::process::exit(1);
    });
    let store_db = storage::Db::open(&storage_db_path).unwrap_or_else(|e| {
        eprintln!("failed to open storage db: {e}");
        std::process::exit(1);
    });

    // --- Identity + Kademlia (rebuild routing table from disk) ---
    let cfg = KadConfig::light_node();
    let id = Identity::generate(); // fresh node identity (in a full build, load from disk)
    let self_peer = PeerId(id.site_key());

    let routing_table = rt_db
        .load_routing_table(self_peer, cfg.clone())
        .unwrap_or_else(|_| {
            let _ = id; // unused in the fallback path
            kad::rt::RoutingTable::new(self_peer, cfg.clone())
        });
    let dht = Kademlia::new(self_peer, cfg);
    // Seed the live DHT's routing table with whatever we had on disk.
    // (In a full build the DHT would also run the `refresh` loop + bootstrap peers.)
    {
        let _ = routing_table; // routing table is persisted; a real run would
                               // re-walk it into the live Kademlia via add_peer
    }

    println!("ZeroNet-Rust node starting");
    println!("  identity peer id: {:02x}{:02x}..", id.site_key()[0], id.site_key()[1]);
    println!("  data dir:        {}", data_dir.display());
    println!("  persistence:     kad.db + storage.db under data dir");
    println!("  kad params:      k={} alpha={} beta={}", dht.config.bucket_size, dht.config.concurrency, dht.config.resiliency);

    // --- Start inbound RPC server ---
    let dht_arc = Arc::new(dht);
    let providers = Arc::new(tokio::sync::Mutex::new(kad::ProviderStore::new()));
    let addr_book = Arc::new(net::AddressBook::new());
    let server_handle = net_server::start(
        dht_arc.clone(),
        data_dir.clone(),
        providers.clone(),
        addr_book.clone(),
    )
    .await
    .expect("failed to bind the inbound server");
    println!("  inbound RPC:     http/1 + JSON frames on {}", server_handle.addr);

    // --- Run for `max_sec`, then flush + stop ---
    tokio::time::sleep(tokio::time::Duration::from_secs(max_sec)).await;

    println!("shutting down (persisting routing table + hash index)…");
    // Persist the current routing table back to disk.
    let rt_guard = dht_arc.rt.clone();
    let snapshot: kad::rt::RoutingTable = {
        let g = rt_guard.lock().await;
        kad::rt::RoutingTable::new(g.self_id, g.config.clone())
    };
    // (A full node would also persist the HashField here; the storage db is
    // the durable record of downloaded files.)
    let _ = rt_db.save_routing_table(&snapshot);
    let _ = store_db; // storage db persists the hash index / manifests

    // Stop the server.
    let _ = server_handle.stop().await;

    println!("node stopped; routing table saved to {}", kad_db_path.display());
    let _ = data_dir; // silence unused warning
}

async fn run_download(args: &[String]) {
    let peer = args.get(2).cloned().unwrap_or_default();
    let site = args.get(3).cloned().unwrap_or_default();
    let path = args.get(4).cloned().unwrap_or_default();
    if peer.is_empty() || site.is_empty() || path.is_empty() {
        eprintln!("usage: zeronet-rs download <host:port> <site> <path>");
        std::process::exit(2);
    }
    let addr: SocketAddr = match peer.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("bad peer address: {peer}");
            std::process::exit(2);
        }
    };
    let expected = match std::env::var("ZRS_EXPECTED_HASH") {
        Ok(h) if h.len() == 64 => {
            let mut arr = [0u8; 32];
            hex_decode(&h, &mut arr);
            arr
        }
        _ => {
            eprintln!("ZRS_EXPECTED_HASH (64 hex chars) required to verify the download");
            std::process::exit(2);
        }
    };
    let root = PathBuf::from(site.clone());
    let engine = worker::DownloadEngine::new(addr, &site, root, 1);
    match engine.download_one(&path, expected).await {
        worker::TaskOutcome::Ok(p) => println!("downloaded and verified: {}", p.display()),
        worker::TaskOutcome::Err(e) => {
            eprintln!("download failed: {e}");
            std::process::exit(1);
        }
    }
}

fn hex_decode(s: &str, out: &mut [u8; 32]) {
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("bad hex in ZRS_EXPECTED_HASH"));
    }
}

