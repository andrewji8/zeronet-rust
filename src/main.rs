//! ZeroNet-Rust: Kademlia DHT + Ed25519/BLAKE3 content addressing.
//!
//! CLI entry point: start node, create site, verify site.

use std::net::SocketAddr;

use content::sign::Identity;
use kad::KadConfig;

fn hex_decode(s: &str, out: &mut [u8; 32]) {
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("bad hex in ZRS_EXPECTED_HASH"));
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let action = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match action {
        "help" => print_usage(),
        "node" => run_node(SocketAddr::from(([0, 0, 0, 0], 15441))).await,
        "download" => {
            let peer = args.get(2).cloned().unwrap_or_default();
            let site = args.get(3).cloned().unwrap_or_default();
            let path = args.get(4).cloned().unwrap_or_default();
            if peer.is_empty() || site.is_empty() || path.is_empty() {
                eprintln!("usage: zeronet-rs download <host:port> <site> <path>");
                std::process::exit(2);
            }
            let addr: std::net::SocketAddr = peer.parse().unwrap_or_else(|_| {
                eprintln!("bad peer address: {peer}");
                std::process::exit(2);
            });
            // Expected BLAKE3 hash is supplied via env for now; in a full node it
            // comes from the site manifest (content.json) fetched from the DHT.
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
            let root = std::path::PathBuf::from(site.clone());
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let engine = worker::DownloadEngine::new(addr, &site, root, 1);
                    match engine.download_one(&path, expected).await {
                        worker::TaskOutcome::Ok(p) => {
                            println!("downloaded and verified: {}", p.display());
                        }
                        worker::TaskOutcome::Err(e) => {
                            eprintln!("download failed: {e}");
                            std::process::exit(1);
                        }
                    }
                });
        }
        "create-site" => {
            let id = Identity::generate();
            let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
            println!("site address: {}",  hex(&id.site_key()));
            println!("private key:  {}",  hex(&id.secret_bytes()));
            println!("save the private key now - you will need it to sign the site!");
        }
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("ZeroNet-Rust v0.1.0");
    println!();
    println!("USAGE:");
    println!("  zeronet-rs node                     start a full node");
    println!("  zeronet-rs create-site              generate a new site keypair");
    println!("  zeronet-rs download PEER_SITE PATH  fetch a file from a peer");
    println!("    PEER = host:port  SITE = site address  PATH = file path");
    println!("    the file is BLAKE3-checked and written under ./<site>/<path>");
    println!("  zeronet-rs help                     show this message");
}

async fn run_node(addr: SocketAddr) {
    let id = Identity::generate();
    let cfg = KadConfig::light_node();
    println!("starting ZeroNet-Rust node at {}", addr);
    println!("node identity: {:?}", id);
    println!("kademlia: k={} alpha={} beta={}", cfg.bucket_size, cfg.concurrency, cfg.resiliency);
    let dht = std::sync::Arc::new(kad::Kademlia::new(kad::PeerId(id.site_key()), cfg));
    // Bootstrap peers would be wired here once a live network exists; without
    // them the DHT cannot discover peers, so this is a no-op placeholder.
    let _ = &dht;
    println!();
    println!("NOTE: full node operation requires a live DHT network and content storage layer");
    println!("wire-up - both are present in the source but need a network bootstrap peer.");
}








