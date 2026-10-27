//! A small concurrent download engine.
//!
//! Consumes `(path, expected-hash)` items, downloads each via
//! `download_and_store` in bounded-concurrency windows, and returns one
//! `TaskOutcome` per input (in order). Replaces ZeroNet's
//! `WorkerManager.checkTasks` loop.

use std::path::PathBuf;

use crate::download::download_and_store;

/// The result of a single download task.
#[derive(Clone)]
pub enum TaskOutcome {
    /// The file was BLAKE3-verified and stored; `path` is where it landed.
    Ok(PathBuf),
    /// Download / verify / write failed.
    Err(DownloadTaskError),
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum DownloadTaskError {
    #[error("peer: {0}")]
    Peer(String),
    #[error("secure: {0}")]
    Secure(String),
    #[error("hash or store: {0}")]
    Store(String),
    #[error("no reachable provider for content key")]
    NoProvider,
}

/// Concurrent download engine bound to one peer and one site.
///
/// In a full node the peer/site come from the DHT `find_providers` result;
/// this engine takes them as configuration so the download path can be
/// tested against a loopback peer.
pub struct DownloadEngine {
    addr: std::net::SocketAddr,
    site: String,
    root: PathBuf,
    pool_size: usize,
}

impl DownloadEngine {
    pub fn new(addr: std::net::SocketAddr, site: &str, root: PathBuf, pool_size: usize) -> Self {
        Self {
            addr,
            site: site.to_string(),
            root,
            pool_size: pool_size.max(1),
        }
    }

    /// Download a single file by `rel_path`, BLAKE3-verifying it against
    /// `expected`, then writing it under `root/rel_path`.
    pub async fn download_one(&self, rel_path: &str, expected: [u8; 32]) -> TaskOutcome {
        match download_and_store(self.addr, &self.site, rel_path, expected, &self.root).await {
            Ok(p) => TaskOutcome::Ok(p),
            Err(e) => TaskOutcome::Err(e.into()),
        }
    }

    /// Run a batch of `(path, expected-hash)` downloads concurrently, bounded
    /// to `pool_size` in-flight. Returns one outcome per input, in order.
    pub async fn download_batch(&self, items: &[(String, [u8; 32])]) -> Vec<TaskOutcome> {
        let n = items.len();
        let mut out: Vec<Option<TaskOutcome>> = vec![None; n];

        let mut start = 0;
        while start < n {
            let end = (start + self.pool_size).min(n);
            let mut jobs = Vec::with_capacity(end - start);
            for (offset, item) in items[start..end].iter().enumerate() {
                let idx = start + offset;
                let path = item.0.clone();
                let hash = item.1;
                let addr = self.addr;
                let site = self.site.clone();
                let root = self.root.clone();
                jobs.push(async move {
                    let result = download_and_store(addr, &site, &path, hash, &root).await;
                    (idx, result)
                });
            }
            for (i, res) in futures::future::join_all(jobs).await {
                out[i] = Some(match res {
                    Ok(p) => TaskOutcome::Ok(p),
                    Err(e) => TaskOutcome::Err(e.into()),
                });
            }
            start = end;
        }

        out.into_iter()
            .map(|o| o.expect("every window index is filled"))
            .collect()
    }
}

impl From<crate::DownloadError> for DownloadTaskError {
    fn from(e: crate::DownloadError) -> Self {
        match e {
            crate::DownloadError::Peer(p) => DownloadTaskError::Peer(p.to_string()),
            crate::DownloadError::Store(s) => DownloadTaskError::Store(s),
            crate::DownloadError::NoProvider => DownloadTaskError::NoProvider,
            crate::DownloadError::Secure(msg) => DownloadTaskError::Secure(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn blake_of(b: &[u8]) -> [u8; 32] {
        *blake3::hash(b).as_bytes()
    }

    /// Start a fake peer on a loopback port. Accepts one connection, reads one
    /// JSON frame (the `GetFile` RPC), replies with one `FileResponse` frame
    /// carrying the base64-encoded bytes.
    async fn spawn_fake_peer(file_bytes: Vec<u8>, path: &str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&file_bytes);
        let path = path.to_string();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await.unwrap();
            let len = u32::from_be_bytes(len_bytes) as usize;
            let mut req_buf = vec![0u8; len];
            stream.read_exact(&mut req_buf).await.unwrap();

            let resp = serde_json::json!({
                "ok": true,
                "path": path,
                "data_b64": data_b64,
            })
            .to_string();
            let resp_bytes = resp.as_bytes();
            let resp_len = (resp_bytes.len() as u32).to_be_bytes();
            stream.write_all(&resp_len).await.unwrap();
            stream.write_all(resp_bytes).await.unwrap();
        });

        addr
    }

    #[tokio::test]
    async fn download_loopback_roundtrip() {
        let file_bytes = b"hello zeronet-rust download test";
        let expected = blake_of(file_bytes);
        let peer_addr = spawn_fake_peer(file_bytes.to_vec(), "index.html").await;

        let tmp = std::env::temp_dir().join(format!("zrs_dl_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let engine = DownloadEngine::new(peer_addr, "1TESTSITE", tmp.clone(), 4);
        let outcome = engine.download_one("index.html", expected).await;

        match outcome {
            TaskOutcome::Ok(p) => {
                assert_eq!(
                    std::fs::read(&p).unwrap(),
                    file_bytes,
                    "stored bytes must match"
                );
            }
            TaskOutcome::Err(e) => panic!("unexpected error: {e}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn download_rejects_bad_hash() {
        let file_bytes = b"some content";
        let bad_expected: [u8; 32] = [0; 32];
        let peer_addr = spawn_fake_peer(file_bytes.to_vec(), "f.txt").await;

        let tmp = std::env::temp_dir().join(format!("zrs_dl_bad_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let engine = DownloadEngine::new(peer_addr, "1TEST", tmp.clone(), 1);
        let outcome = engine.download_one("f.txt", bad_expected).await;
        match outcome {
            TaskOutcome::Ok(_) => panic!("should have failed the hash check"),
            TaskOutcome::Err(e) => assert!(
                matches!(e, DownloadTaskError::Store(_)),
                "expected a store/hash error, got: {e}"
            ),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn download_batch_returns_ordered_outcomes() {
        let file = b"batch test file";
        let expected = blake_of(file);
        let addr = spawn_fake_peer(file.to_vec(), "batch.txt").await;

        let tmp = std::env::temp_dir().join(format!("zrs_dl_batch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let engine = DownloadEngine::new(addr, "1BATCH", tmp.clone(), 3);
        let items: Vec<(String, [u8; 32])> = vec![("batch.txt".to_string(), expected)];
        let results = engine.download_batch(&items).await;
        assert_eq!(results.len(), 1);
        match &results[0] {
            TaskOutcome::Ok(p) => assert_eq!(std::fs::read(p).unwrap(), file.to_vec()),
            TaskOutcome::Err(e) => panic!("batch failed: {e}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
