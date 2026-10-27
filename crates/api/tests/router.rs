//! Exercise the axum router in-process (tower oneshot, no real socket):
//! /status, site file serving, /download 400 on bad input.

use std::sync::Arc;

use axum::body::Body;
use axum::http;
use kad::{KadConfig, Kademlia, PeerId, ProviderStore};
use net::AddressBook;
use tower::ServiceExt;
fn make_router(dht: Arc<Kademlia>) -> axum::Router {
    let providers = Arc::new(tokio::sync::Mutex::new(ProviderStore::new()));
    let addr_book = Arc::new(AddressBook::new());
    let root = std::env::temp_dir().join(format!("zrs_api_root_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("1SITE")).unwrap();
    std::fs::write(root.join("1SITE").join("index.html"), b"<h1>api</h1>").unwrap();
    api::build_router(dht, providers, addr_book, root)
}

#[tokio::test]
async fn status_reports_self_peer() {
    let dht = Arc::new(Kademlia::new(PeerId([0x11u8; 32]), KadConfig::light_node()));
    let app = make_router(dht);
    let resp = app
        .oneshot(
            http::Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["rt_peers"], 0u8);
    assert!(v.get("self_peer").is_some());
}

#[tokio::test]
async fn serve_site_returns_local_file() {
    let dht = Arc::new(Kademlia::new(PeerId([0x22u8; 32]), KadConfig::light_node()));
    let app = make_router(dht);
    let req = http::Request::builder()
        .uri("/sites/1SITE/index.html")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"<h1>api</h1>");
}

#[tokio::test]
async fn serve_site_rejects_traversal() {
    let dht = Arc::new(Kademlia::new(PeerId([0x33u8; 32]), KadConfig::light_node()));
    let app = make_router(dht);
    let req = http::Request::builder()
        .uri("/sites/1SITE/../../etc/passwd")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.status() != http::StatusCode::OK);
}

#[tokio::test]
async fn download_rejects_bad_hash() {
    let dht = Arc::new(Kademlia::new(PeerId([0x44u8; 32]), KadConfig::light_node()));
    let app = make_router(dht);
    let json = serde_json::json!({
        "content_key": "zz", "site": "1SITE", "path": "index.html", "expected_hash": "nothex"
    })
    .to_string();
    let req = http::Request::builder()
        .method("POST")
        .uri("/download")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}
