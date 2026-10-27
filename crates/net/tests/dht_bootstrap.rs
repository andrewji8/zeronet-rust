//! Two-node test: start two real servers, connect them via `connect_and_bootstrap`,
//! exchange provider records via `provide_over_wire`, and confirm
//! `find_providers_over_wire` returns them.

use kad::{KadConfig, Kademlia, PeerId, ProviderStore};
use net::AddressBook;
use std::sync::Arc;

#[tokio::test]
async fn two_nodes_discover_each_other() {
    // --- Node A ---
    let a_id = PeerId([0xAAu8; 32]);
    let a_cfg = KadConfig::light_node();
    let a_dht = Arc::new(Kademlia::new(a_id, a_cfg.clone()));
    let a_prov = Arc::new(tokio::sync::Mutex::new(ProviderStore::new()));
    let a_ab = Arc::new(AddressBook::new());
    let a_root = std::env::temp_dir().join(format!("zrs_a_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&a_root);
    let a_server = net::server::start(a_dht.clone(), a_root.clone(), a_prov.clone(), a_ab.clone())
        .await
        .unwrap();

    // --- Node B ---
    let b_id = PeerId([0xBBu8; 32]);
    let b_cfg = KadConfig::light_node();
    let b_dht = Arc::new(Kademlia::new(b_id, b_cfg.clone()));
    let b_prov = Arc::new(tokio::sync::Mutex::new(ProviderStore::new()));
    let b_ab = Arc::new(AddressBook::new());
    let b_root = std::env::temp_dir().join(format!("zrs_b_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&b_root);
    let b_server = net::server::start(b_dht.clone(), b_root.clone(), b_prov.clone(), b_ab.clone())
        .await
        .unwrap();

    // Bootstrap: A learns B, B learns A (symmetric).
    let b_as_seen_by_a = net::dht::connect_and_bootstrap(a_dht.clone(), &a_ab, b_server.addr)
        .await
        .unwrap();
    assert_eq!(b_as_seen_by_a, b_id, "A should learn B's id");
    let a_as_seen_by_b = net::dht::connect_and_bootstrap(b_dht.clone(), &b_ab, a_server.addr)
        .await
        .unwrap();
    assert_eq!(a_as_seen_by_b, a_id, "B should learn A's id");

    // B claims to be a provider of content key "xyz" (locally + to A).
    let key = b"xyz";
    net::dht::provide_over_wire(&b_prov, &b_ab, key, b_id, 1)
        .await
        .unwrap();
    // A claims too (locally + to B).
    net::dht::provide_over_wire(&a_prov, &a_ab, key, a_id, 1)
        .await
        .unwrap();

    // A's provider store should now contain B (sent by B) and A itself.
    let a_providers: Vec<_> = { a_prov.lock().await.get(&kad::hash_key(key)).to_vec() };
    assert!(
        a_providers.contains(&b_id),
        "A's provider store should contain B after wire exchange: {a_providers:?}"
    );

    // A queries the wire for providers of "xyz" and should find B.
    let found = net::dht::find_providers_over_wire(&a_ab, key, 4).await;
    assert!(
        found.iter().any(|(p, _)| *p == b_id),
        "wire find should return B: {found:?}"
    );

    // Confirm A's DHT routing table also gained B (via the GetClosestPeers transport path
    // is not exercised here, but the bootstrap path added B explicitly).
    {
        let rt = a_dht.rt.lock().await;
        assert!(
            rt.find(&b_id).is_some(),
            "A's routing table should contain B after bootstrap"
        );
    }
    {
        let rt = b_dht.rt.lock().await;
        assert!(
            rt.find(&a_id).is_some(),
            "B's routing table should contain A after bootstrap"
        );
    }

    let _ = a_server.stop().await;
    let _ = b_server.stop().await;
    let _ = std::fs::remove_dir_all(&a_root);
    let _ = std::fs::remove_dir_all(&b_root);
}

/// The complete chain: discover a provider over the DHT, then download the
/// file from it via `worker::download_via_dht` (BLAKE3-verified).
#[tokio::test]
async fn full_chain_discover_then_download() {
    use kad::{KadConfig, Kademlia, PeerId, ProviderStore};
    use net::AddressBook;
    use std::sync::Arc;

    // --- Provider node (serves a real file, announces itself) ---
    let site = "1PROV";
    let path = "index.html";
    let file = b"<html>full chain</html>";
    let expected = *blake3::hash(file).as_bytes();
    let content_key = b"site-1PROV-index";

    let p_id = PeerId([0x77u8; 32]);
    let p_cfg = KadConfig::light_node();
    let p_dht = Arc::new(Kademlia::new(p_id, p_cfg));
    let p_prov = Arc::new(tokio::sync::Mutex::new(ProviderStore::new()));
    let p_ab = Arc::new(AddressBook::new());
    let p_root = std::env::temp_dir().join(format!("zrs_prov_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p_root);
    std::fs::create_dir_all(p_root.join(site)).unwrap();
    std::fs::write(p_root.join(site).join(path), file).unwrap();
    let p_server = net::server::start(p_dht, p_root.clone(), p_prov, p_ab.clone())
        .await
        .unwrap();

    // --- Fetch node (discovers + downloads) ---
    let f_id = PeerId([0x66u8; 32]);
    let f_cfg = KadConfig::light_node();
    let f_dht = Arc::new(Kademlia::new(f_id, f_cfg));
    let f_prov = Arc::new(tokio::sync::Mutex::new(ProviderStore::new()));
    let f_ab = Arc::new(AddressBook::new());

    // Bootstrap: fetch node learns the provider's address + id.
    let learned = net::dht::connect_and_bootstrap(f_dht, &f_ab, p_server.addr)
        .await
        .unwrap();
    assert_eq!(learned, p_id, "fetch node must learn the provider id");

    // Provider announces it serves the content, pushing to the fetch node.
    net::dht::provide_over_wire(&f_prov, &f_ab, content_key, p_id, 1)
        .await
        .unwrap();

    // The fetch node discovers the provider over the DHT, then downloads.
    let out_root = std::env::temp_dir().join(format!("zrs_fetch_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_root);

    let stored = worker::download_via_dht(&f_ab, content_key, site, path, expected, &out_root, 4)
        .await
        .expect("full-chain download must succeed");

    let downloaded = std::fs::read(&stored).unwrap();
    assert_eq!(downloaded, file, "downloaded bytes must match the original");

    let _ = p_server.stop().await;
    let _ = std::fs::remove_dir_all(&p_root);
    let _ = std::fs::remove_dir_all(&out_root);
}
