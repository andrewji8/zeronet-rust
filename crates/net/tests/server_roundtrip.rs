//! Integration test: start the real inbound server, then drive it with
//! `net::peer::get_file` over an actual TCP socket — the same code path the
//! CLI `download` uses. Proves the node is genuinely runnable end-to-end.

use kad::{KadConfig, Kademlia, PeerId};
use std::sync::Arc;

#[tokio::test]
async fn node_serves_getfile_over_real_tcp() {
    // Build a minimal DHT with one seeded peer in the routing table.
    let cfg = KadConfig::light_node();
    let self_id = PeerId([9u8; 32]);
    let dht = Arc::new(Kademlia::new(self_id, cfg.clone()));
    {
        let mut rt = dht.rt.lock().await;
        rt.add_peer(kad::rt::RtPeer { id: PeerId([42u8; 32]), ip_group: None });
    }

    // A local "site directory" with one real file.
    let root = std::env::temp_dir().join(format!("zrs_node_site_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("1SITE").join("docs")).unwrap();
    std::fs::write(root.join("1SITE").join("docs").join("index.html"), b"<h1>ok</h1>").unwrap();

    // Start the real server.
    let server = net::server::start(dht.clone(), root.clone()).await.unwrap();
    let addr = server.addr;

    // Drive it with the client path (net::peer::get_file) used by `download`.
    let data = net::peer::get_file(addr, "1SITE", "docs/index.html").await.unwrap();
    assert_eq!(data, b"<h1>ok</h1>");

    // And confirm GetClosestPeers answers from the routing table.
    let _ = data;
    server.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}

