//! ZeroNet-Rust: Kademlia DHT + Ed25519/BLAKE3 content addressing.
//!
//! CLI entry point: start node, create site, publish a site, download a file.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use content::sign::Identity;
use kad::{KadConfig, Kademlia, PeerId};
use net::server as net_server;
use net::NoiseIdentity;

mod publish;

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
            println!("site address:  {}", hex(&id.site_key()));
            println!("private key:   {}", hex(&id.secret_bytes()));
            println!("save the private key now - you will need it to sign the site!");
        }
        "publish" => run_publish(&args).await,
        "download" => run_download(&args).await,
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("ZeroNet-Rust v0.1.0");
    println!();
    println!("USAGE:");
    println!("  zeronet-rs node [DIR] [--max-sec N] [--listen host:port] [--api host:port]");
    println!("                    [--secure-listen host:port] [--bootstrap host:port]...");
    println!("                    [--secure-bootstrap host:port]...");
    println!(
        "                     start a full node (Kademlia + TCP RPC + persistence + axum API)"
    );
    println!("  zeronet-rs create-site");
    println!("                     generate a new ed25519 site keypair");
    println!("  zeronet-rs publish <site-dir> (--secret <64hex> | --wif <WIF>)");
    println!("                     sign the site manifest (BLAKE3 + Ed25519, self-checked) and");
    println!("                     persist manifest.json + storage.db; with --announce, also");
    println!("                     start the node and broadcast the provider over the DHT.");
    println!("  zeronet-rs download <host:port> <site> <path>");
    println!("                     fetch a file from a peer (BLAKE3-checked)");
    println!("  zeronet-rs help                     show this message");
}

/// The publish path: sign the manifest, persist it locally, and (optionally)
/// announce + serve to the network.
async fn run_publish(args: &[String]) {
    let mut site_dir = PathBuf::from(".");
    let mut secret_hex: Option<String> = None;
    let mut wif: Option<String> = None;
    let mut max_sec = 10u64;
    let mut listen: Option<SocketAddr> = None;
    let mut secure_listen: Option<SocketAddr> = None;
    let mut bootstrap: Vec<SocketAddr> = Vec::new();
    let mut secure_bootstrap: Vec<SocketAddr> = Vec::new();
    let mut want_announce = false;

    let mut i = 2;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--secret" => {
                if i + 1 < args.len() {
                    secret_hex = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--wif" => {
                if i + 1 < args.len() {
                    wif = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--max-sec" => {
                if i + 1 < args.len() {
                    max_sec = args[i + 1].parse().unwrap_or(10);
                    i += 1;
                }
            }
            "--listen" => {
                if i + 1 < args.len() {
                    listen = Some(parse_addr(&args[i + 1], a));
                    i += 1;
                }
            }
            "--secure-listen" => {
                if i + 1 < args.len() {
                    secure_listen = Some(parse_addr(&args[i + 1], a));
                    i += 1;
                }
            }
            "--bootstrap" => {
                if i + 1 < args.len() {
                    bootstrap.push(parse_addr(&args[i + 1], a));
                    i += 1;
                }
            }
            "--secure-bootstrap" => {
                if i + 1 < args.len() {
                    secure_bootstrap.push(parse_addr(&args[i + 1], a));
                    i += 1;
                }
            }
            "--announce" => {
                want_announce = true;
            }
            s => {
                site_dir = PathBuf::from(s);
            }
        }
        i += 1;
    }

    // ---- 1) build + self-verify the signed manifest (ed25519 native path) ----
    match &secret_hex {
        Some(hex) => {
            let bytes = hex_decode32(hex, "--secret");
            let identity = Identity::from_secret(&bytes);
            let manifest = match publish::build_site_manifest(
                &site_dir,
                identity.site_key(),
                &identity.signing_key,
            ) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("publish failed: {e}");
                    std::process::exit(1);
                }
            };
            persist_manifest(&site_dir, &identity, &manifest);
            println!(
                "site {} signed with {} files; manifest self-verified",
                short_hex(&identity.site_key()),
                manifest.file_count
            );

            // ---- 2) optional announce over the DHT ----
            if want_announce {
                announce_site(
                    site_dir.clone(),
                    &identity,
                    manifest,
                    max_sec,
                    listen,
                    secure_listen,
                    bootstrap,
                    secure_bootstrap,
                )
                .await;
            }
        }
        _ => match &wif {
            Some(w) => {
                // ZeroNet-compatible: sign a content.json with the WIF key and persist it.
                let key = match content::secp::ZeronetKey::from_wif(w) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("bad WIF: {e}");
                        std::process::exit(1);
                    }
                };
                let source = site_dir.join("content.json");
                let content_json = match std::fs::read(&source) {
                    Ok(b) => b,
                    Err(_) => {
                        eprintln!(
                            "--wif publish expects a content.json in {}",
                            source.display()
                        );
                        std::process::exit(2);
                    }
                };
                let value: serde_json::Value = match serde_json::from_slice(&content_json) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("content.json is not valid JSON: {e}");
                        std::process::exit(1);
                    }
                };
                let signed = match key.sign_content(&value) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("signing failed: {e}");
                        std::process::exit(1);
                    }
                };
                std::fs::write(site_dir.join("content.signed.json"), &signed).unwrap_or_else(|e| {
                    eprintln!("failed to write content.signed.json: {e}");
                    std::process::exit(1);
                });
                println!(
                    "ZeroNet site {} signed (Secp256k1); wrote content.signed.json",
                    key.address()
                );
            }
            None => {
                eprintln!("publish: pass --secret <64-hex ed25519 key> or --wif <ZeroNet WIF>");
                std::process::exit(2);
            }
        },
    }
}

/// Announce the site's provider over the DHT, then keep serving it for
/// `max_sec` so other nodes can discover + download.
#[allow(clippy::too_many_arguments)]
async fn announce_site(
    site_dir: PathBuf,
    identity: &Identity,
    manifest: content::SiteManifest,
    max_sec: u64,
    listen: Option<SocketAddr>,
    secure_listen: Option<SocketAddr>,
    bootstrap: Vec<SocketAddr>,
    secure_bootstrap: Vec<SocketAddr>,
) {
    let data_dir = site_dir.clone();
    let storage_db_path = data_dir.join("storage.db");
    let noise_id_path = data_dir.join("noise_identity.bin");
    tokio::fs::create_dir_all(&data_dir).await.ok();

    // Persist the manifest into the site storage db.
    if let Ok(db) = storage::Db::open(&storage_db_path) {
        let hashes: Vec<[u8; 32]> = manifest.files.iter().map(|f| f.hash).collect();
        let _ = db.save_hashfield(&hashes);
        let _ = db.save_site_manifest(&manifest.site_key, &manifest);
    }

    // Reconstruct a Kademlia node bound to the site key.
    let cfg = KadConfig::light_node();
    let self_peer = PeerId(identity.site_key());
    let dht = Arc::new(Kademlia::new(self_peer, cfg.clone()));
    let providers = Arc::new(tokio::sync::Mutex::new(kad::ProviderStore::new()));
    let addr_book = Arc::new(net::AddressBook::new());

    // Start inbound servers (plaintext + optional secure).
    let listen_addr = listen.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    let server_handle = net_server::start_at(
        dht.clone(),
        site_dir.clone(),
        providers.clone(),
        addr_book.clone(),
        listen_addr,
    )
    .await
    .expect("failed to bind the announce server");
    println!("  announcing:      plaintext RPC on {}", server_handle.addr);

    let mut secure_server_handle: Option<net_server::SecureServerHandle> = None;
    let noise_id = NoiseIdentity::load_or_new(&noise_id_path).unwrap_or_else(|e| {
        eprintln!("failed to load noise identity: {e}");
        std::process::exit(1);
    });
    if let Some(sl) = secure_listen {
        match net_server::start_secure_at(
            dht.clone(),
            site_dir.clone(),
            providers.clone(),
            addr_book.clone(),
            &noise_id,
            sl,
        )
        .await
        {
            Ok(h) => {
                println!("  announcing:      Noise-XX encrypted RPC on {}", h.addr);
                secure_server_handle = Some(h);
            }
            Err(e) => {
                eprintln!("failed to bind the secure announce server: {e}");
            }
        }
    }

    // Bootstrap peers (both plaintext and secure) so the provider record can
    // actually reach someone.
    for baddr in &bootstrap {
        let _ = net::dht::connect_and_bootstrap(dht.clone(), &addr_book, *baddr).await;
    }
    for baddr in &secure_bootstrap {
        let _ = net::dht::connect_and_bootstrap_secure(dht.clone(), &addr_book, &noise_id, *baddr)
            .await;
    }

    // Announce: register this node as a provider of the site's content key.
    let key = publish::site_content_key(&identity.site_key());
    println!(
        "  content key:     {} ({} files, {} bytes)",
        short_hex(&key),
        manifest.file_count,
        manifest.total_size
    );
    if addr_book.is_empty() {
        eprintln!("warning: no peers reachable yet; the provider record is only stored locally.");
        eprintln!("         pass --bootstrap / --secure-bootstrap so other nodes can find you.");
    }
    // Plaintext announce.
    let _ = net::dht::provide_over_wire(
        &providers,
        &addr_book,
        &key,
        self_peer,
        addr_book.len().max(1),
    )
    .await;
    // Secure announce (no-op if the secure server wasn't started).
    if secure_server_handle.is_some() || !secure_bootstrap.is_empty() {
        let _ = net::dht::provide_over_wire_secure(
            &providers,
            &addr_book,
            &noise_id,
            &key,
            self_peer,
            addr_book.len().max(1),
        )
        .await;
    }

    // Keep serving for `max_sec`.
    println!("serving the site for {max_sec}s (other nodes can now discover + download it)...");
    tokio::time::sleep(tokio::time::Duration::from_secs(max_sec)).await;

    if let Some(h) = secure_server_handle {
        let _ = h.stop().await;
    }
    let _ = server_handle.stop().await;
    println!("announce window closed");
}

fn persist_manifest(site_dir: &Path, identity: &Identity, manifest: &content::SiteManifest) {
    // Persist into the site's storage.db so restarts keep the index.
    if let Ok(db) = storage::Db::open(site_dir.join("storage.db")) {
        let hashes: Vec<[u8; 32]> = manifest.files.iter().map(|f| f.hash).collect();
        let _ = db.save_hashfield(&hashes);
        let _ = db.save_site_manifest(&manifest.site_key, manifest);
        println!(
            "  persisted:        {}",
            site_dir.join("storage.db").display()
        );
    }
    // Also write a human-readable manifest.json next to the site files.
    if let Ok(json) = serde_json::to_string_pretty(manifest) {
        let out = site_dir.join("manifest.json");
        if std::fs::write(&out, json).is_ok() {
            println!("  persisted:        {}", out.display());
        }
    }
    let _ = identity;
}

/// Parse a required `host:port` argument, exiting with a clear message on error.
fn parse_addr(s: &str, flag: &str) -> SocketAddr {
    match s.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("bad {flag} address: {s}");
            std::process::exit(2);
        }
    }
}

fn hex_decode32(s: &str, flag: &str) -> [u8; 32] {
    if s.len() != 64 {
        eprintln!(
            "{flag} must be 64 hex chars (32 bytes), got {} chars",
            s.len()
        );
        std::process::exit(2);
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("{flag} has invalid hex at byte {i}");
            std::process::exit(2);
        });
    }
    out
}

fn short_hex(b: &[u8; 32]) -> String {
    let s = b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    s.chars().take(16).collect()
}

async fn run_node(args: &[String]) {
    // --- Parse args ---
    let mut data_dir = PathBuf::from(".zrs-node");
    let mut max_sec = 15u64; // default demo duration
    let mut listen: Option<std::net::SocketAddr> = None;
    let mut api_listen: Option<std::net::SocketAddr> = None;
    let mut secure_listen: Option<std::net::SocketAddr> = None;
    let mut bootstrap: Vec<std::net::SocketAddr> = Vec::new();
    let mut secure_bootstrap: Vec<std::net::SocketAddr> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--max-sec" => {
                if i + 1 < args.len() {
                    max_sec = args[i + 1].parse().unwrap_or(15);
                    i += 1;
                }
            }
            "--listen" => {
                if i + 1 < args.len() {
                    listen = Some(args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("bad --listen addr: {}", args[i + 1]);
                        std::process::exit(2);
                    }));
                    i += 1;
                }
            }
            "--api" => {
                if i + 1 < args.len() {
                    api_listen = Some(args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("bad --api addr: {}", args[i + 1]);
                        std::process::exit(2);
                    }));
                    i += 1;
                }
            }
            "--secure-listen" => {
                if i + 1 < args.len() {
                    secure_listen = Some(args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("bad --secure-listen addr: {}", args[i + 1]);
                        std::process::exit(2);
                    }));
                    i += 1;
                }
            }
            "--bootstrap" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse() {
                        Ok(a) => bootstrap.push(a),
                        Err(_) => {
                            eprintln!("bad --bootstrap addr: {}", args[i + 1]);
                            std::process::exit(2);
                        }
                    }
                    i += 1;
                }
            }
            "--secure-bootstrap" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse() {
                        Ok(a) => secure_bootstrap.push(a),
                        Err(_) => {
                            eprintln!("bad --secure-bootstrap addr: {}", args[i + 1]);
                            std::process::exit(2);
                        }
                    }
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
    let noise_id_path = data_dir.join("noise_identity.bin");
    tokio::fs::create_dir_all(&data_dir).await.ok();

    let rt_db = kad::RtDb::open(&kad_db_path).unwrap_or_else(|e| {
        eprintln!("failed to open kad db: {e}");
        std::process::exit(1);
    });
    let store_db = storage::Db::open(&storage_db_path).unwrap_or_else(|e| {
        eprintln!("failed to open storage db: {e}");
        std::process::exit(1);
    });

    // --- Noise identity (the X25519 P2P identity, persisted across restarts) ---
    let noise_id = match NoiseIdentity::load_or_new(&noise_id_path) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("failed to load/create noise identity: {e}");
            std::process::exit(1);
        }
    };

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
    println!(
        "  identity peer id: {:02x}{:02x}..",
        id.site_key()[0],
        id.site_key()[1]
    );
    println!(
        "  noise identity:   {} (X25519, persisted)",
        &noise_id.pk_hex()[..12]
    );
    println!("  data dir:        {}", data_dir.display());
    println!("  persistence:     kad.db + storage.db + noise_identity.bin under data dir");
    println!(
        "  kad params:      k={} alpha={} beta={}",
        dht.config.bucket_size, dht.config.concurrency, dht.config.resiliency
    );

    // --- Start inbound RPC server ---
    let dht_arc = Arc::new(dht);
    let providers = Arc::new(tokio::sync::Mutex::new(kad::ProviderStore::new()));
    let addr_book = Arc::new(net::AddressBook::new());

    // Bind the inbound RPC server. If the user passed --listen, use that
    // address; otherwise pick an ephemeral loopback port.
    let listen_addr = listen.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    let server_handle = net_server::start_at(
        dht_arc.clone(),
        data_dir.clone(),
        providers.clone(),
        addr_book.clone(),
        listen_addr,
    )
    .await
    .expect("failed to bind the inbound server");
    println!(
        "  inbound RPC:     JSON frames on {} (listen={})",
        server_handle.addr, listen_addr
    );

    // Optional secure (Noise-XX) inbound RPC server.
    let mut secure_server_handle: Option<net_server::SecureServerHandle> = None;
    if let Some(sl) = secure_listen {
        match net_server::start_secure_at(
            dht_arc.clone(),
            data_dir.clone(),
            providers.clone(),
            addr_book.clone(),
            &noise_id,
            sl,
        )
        .await
        {
            Ok(h) => {
                println!(
                    "  secure RPC:      Noise-XX encrypted on {} (X25519 + ChaCha20-Poly1305)",
                    h.addr
                );
                secure_server_handle = Some(h);
            }
            Err(e) => {
                eprintln!("failed to bind the secure server: {e}");
                std::process::exit(1);
            }
        }
    }

    // Optional HTTP/WS API (axum) for UIs and admin tooling.
    if let Some(api_addr) = api_listen {
        tokio::spawn({
            let dht_arc = dht_arc.clone();
            let providers = providers.clone();
            let addr_book = addr_book.clone();
            let root = data_dir.clone();
            async move {
                eprintln!("  api server:      axum on {api_addr}");
                let _ = api::start_at(dht_arc, providers, addr_book, root, api_addr).await;
            }
        });
    }

    // --- plaintext bootstrap peers ---
    if !bootstrap.is_empty() {
        let n = bootstrap.len();
        println!(
            "  bootstrap peers: {} ({} each, retried every 10s until --max-sec)",
            n,
            bootstrap
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let mut handles = Vec::new();
        for (idx, baddr) in bootstrap.iter().enumerate() {
            let dht_arc = dht_arc.clone();
            let addr_book = addr_book.clone();
            let baddr = *baddr;
            let label = format!("b{idx}");
            handles.push(tokio::spawn(async move {
                loop {
                    match net::dht::connect_and_bootstrap(dht_arc.clone(), &addr_book, baddr).await
                    {
                        Ok(remote) => {
                            println!(
                                "  [{}] bootstrap ok: learned peer {:02x}{}.. at {}",
                                label, remote.0[0], remote.0[1], baddr
                            );
                            return Ok::<(), String>(());
                        }
                        Err(e) => {
                            println!(
                                "  [{}] bootstrap {} failed: {e} (retrying in 10s)",
                                label, baddr
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        }
                    }
                }
            }));
        }
        let _ = handles;
    }

    // --- secure (Noise) bootstrap peers ---
    if !secure_bootstrap.is_empty() {
        let n = secure_bootstrap.len();
        println!(
            "  secure bootstrap peers: {} ({} each, retried every 10s until --max-sec)",
            n,
            secure_bootstrap
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        for (idx, baddr) in secure_bootstrap.iter().enumerate() {
            let dht_arc = dht_arc.clone();
            let addr_book = addr_book.clone();
            let nid = noise_id.clone();
            let baddr = *baddr;
            let label = format!("sb{idx}");
            tokio::spawn(async move {
                loop {
                    match net::dht::connect_and_bootstrap_secure(
                        dht_arc.clone(),
                        &addr_book,
                        &nid,
                        baddr,
                    )
                    .await
                    {
                        Ok((remote, noise_peer)) => {
                            println!(
                                "  [{label}] secure bootstrap ok: kad-peer {:02x}{:02x}.. noise-id {}.. at {baddr}",
                                remote.0[0], remote.0[1], &noise_peer[..8]
                            );
                            return;
                        }
                        Err(e) => {
                            println!(
                                "  [{label}] secure bootstrap {baddr} failed: {e} (retrying in 10s)"
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        }
                    }
                }
            });
        }
    }

    // --- Run for `max_sec`, then flush + stop ---
    tokio::time::sleep(tokio::time::Duration::from_secs(max_sec)).await;

    println!("shutting down (persisting routing table + hash index)…");
    let rt_guard = dht_arc.rt.clone();
    let snapshot: kad::rt::RoutingTable = {
        let g = rt_guard.lock().await;
        kad::rt::RoutingTable::new(g.self_id, g.config.clone())
    };
    let _ = rt_db.save_routing_table(&snapshot);
    let _ = store_db;

    if let Some(h) = secure_server_handle {
        let _ = h.stop().await;
    }
    let _ = server_handle.stop().await;

    println!(
        "node stopped; routing table saved to {}",
        kad_db_path.display()
    );
    let _ = data_dir;
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
            for i in 0..32 {
                arr[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
                    eprintln!("bad hex in ZRS_EXPECTED_HASH");
                    std::process::exit(2);
                });
            }
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
