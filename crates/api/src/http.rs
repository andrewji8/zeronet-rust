//! axum handlers: node status, local site file serving, DHT download trigger.

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::{unhex32, ApiState};

/// `GET /status` -> node + DHT health snapshot.
pub async fn status(State(s): State<ApiState>) -> impl IntoResponse {
    let rt = s.dht.rt.lock().await;
    let rt_len = rt.len();
    drop(rt);
    let prov = s.providers.lock().await.len();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "self_peer": crate::state::hex32(&s.dht.self_id.0),
        "rt_peers": rt_len,
        "provider_keys": prov,
        "known_peers": s.addr_book.len(),
    }))
}

/// `GET /sites/{site}/{path}...` -> serve a locally stored site file.
pub async fn serve_site(
    State(s): State<ApiState>,
    AxumPath((site, path)): AxumPath<(String, String)>,
) -> Result<axum::body::Bytes, (StatusCode, String)> {
    let file = s.site_root.join(&site).join(&path);
    // Path-traversal guard: the resolved path must stay under site_root.
    if !file.starts_with(s.site_root.as_path()) {
        return Err((StatusCode::FORBIDDEN, "unsafe path".to_string()));
    }
    match tokio::fs::read(&file).await {
        Ok(b) => Ok(axum::body::Bytes::from(b)),
        Err(_) => Err((StatusCode::NOT_FOUND, "not found".to_string())),
    }
}

/// `POST /download` body -> run the full DHT discover->download->verify chain.
#[derive(Deserialize, Serialize)]
pub struct DownloadReq {
    /// Hex of the content key to look up providers for.
    pub content_key: String,
    /// Site address (directory under site_root) the file belongs to.
    pub site: String,
    /// Relative file path.
    pub path: String,
    /// 64-hex BLAKE3 hash the file must verify against.
    pub expected_hash: String,
}

pub async fn download(
    State(s): State<ApiState>,
    Json(req): Json<DownloadReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let expected = unhex32(&req.expected_hash).ok_or((
        StatusCode::BAD_REQUEST,
        "expected_hash must be 64 hex chars".to_string(),
    ))?;
    let key_bytes: [u8; 32] = match unhex32(&req.content_key) {
        Some(k) => k,
        None => {
            // content_key may be a raw site address; hash it as a key.
            let mut out = [0u8; 32];
            let kb = req.content_key.as_bytes();
            out[..kb.len().min(32)].copy_from_slice(&kb[..kb.len().min(32)]);
            out
        }
    };
    match worker::download_via_dht(
        &s.addr_book,
        &key_bytes,
        &req.site,
        &req.path,
        expected,
        s.site_root.as_path(),
        4,
    )
    .await
    {
        Ok(p) => Ok(Json(json!({ "ok": true, "path": p.to_string_lossy() }))),
        Err(e) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
    }
}

/// Plain 404 body for unknown routes.
pub async fn not_found() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "not found")
}
