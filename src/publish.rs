//! Site publish logic: collect a site directory, hash + sign its manifest,
//! and persist it locally (and optionally announce it to the network).
//!
//! This is the "write" side of the content-addressing chain:
//! `create-site` (identity) -> `publish` (this module) -> providers announce
//! over the DHT -> other nodes discover and download (verified by BLAKE3).

use std::path::Path;

use content::{merkle, FileEntry, SiteManifest};

/// Publish error.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature: {0}")]
    Signature(#[from] merkle::SignatureError),
    #[error("no files found in {0}")]
    NoFiles(String),
    #[error("file {0} exceeds MAX_BLOCK_SIZE ({1} bytes)")]
    TooLarge(String, u64),
}

/// File names that are *publish artifacts* and must never be hashed into the
/// site manifest. Including them would make re-publishing grow the manifest
/// with its own previous output (manifest.json / storage.db / signed copy).
pub const PUBLISH_ARTIFACTS: &[&str] = &[
    "manifest.json",
    "storage.db",
    "kad.db",
    "content.signed.json",
    "noise_identity.bin",
];

/// Recursively collect regular files under `site_dir`, returning
/// `(relative forward-slash path, bytes, size)` triples. Publish artifacts
/// (see `PUBLISH_ARTIFACTS`) are skipped so a site never signs its own output.
pub fn collect_files(site_dir: &Path) -> Result<Vec<(String, Vec<u8>, u64)>, PublishError> {
    let mut out: Vec<(String, Vec<u8>, u64)> = Vec::new();
    let mut stack = vec![site_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                // Skip publish artifacts so the manifest never signs its own output.
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if PUBLISH_ARTIFACTS.contains(&name) {
                        continue;
                    }
                }
                let bytes = std::fs::read(&p)?;
                let rel = p
                    .strip_prefix(site_dir)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let size = bytes.len() as u64;
                out.push((rel, bytes, size));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Build a signed `SiteManifest` from the files in `site_dir`.
///
/// - each file is BLAKE3-hashed and checked against the 15 MB block cap;
/// - the manifest is signed with the site's ed25519 `secret_key`;
/// - the result is verified with `merkle::verify_manifest` before returning,
///   so a returned manifest is always self-consistent.
pub fn build_site_manifest(
    site_dir: &Path,
    site_key: [u8; 32],
    secret_key: &ed25519_dalek::SigningKey,
) -> Result<SiteManifest, PublishError> {
    let files = collect_files(site_dir)?;
    if files.is_empty() {
        return Err(PublishError::NoFiles(site_dir.display().to_string()));
    }
    let mut entries: Vec<FileEntry> = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    for (rel, bytes, size) in &files {
        if *size > merkle::MAX_BLOCK_SIZE {
            return Err(PublishError::TooLarge(rel.clone(), *size));
        }
        entries.push(FileEntry {
            path: rel.clone(),
            hash: merkle::file_hash(bytes),
            size: *size,
            optional: false,
        });
    }
    let manifest = merkle::build_manifest(site_key, entries, secret_key, now);
    merkle::verify_manifest(&manifest)?;
    Ok(manifest)
}

/// Deterministic DHT content key for a site: the SHA-256-free BLAKE3 of
/// `b"site:" || hex(site_key)`. Every node that publishes / looks up the
/// same site uses the same key, which is what makes `announce` + `discover`
/// line up.
pub fn site_content_key(site_key: &[u8; 32]) -> [u8; 32] {
    let mut inb = Vec::with_capacity(3 + 64);
    inb.extend_from_slice(b"site:");
    inb.extend_from_slice(hex_of(site_key).as_bytes());
    *blake3::hash(&inb).as_bytes()
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use content::sign::Identity;

    #[test]
    fn publish_builds_a_verifiable_manifest() {
        let dir = std::env::temp_dir().join(format!("zrs_pub_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("index.html"), b"<h1>hi</h1>").unwrap();
        std::fs::write(dir.join("sub").join("a.txt"), b"payload").unwrap();

        let id = Identity::generate();
        let m = build_site_manifest(&dir, id.site_key(), &id.signing_key).unwrap();
        assert_eq!(m.file_count, 2);
        merkle::verify_manifest(&m).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn site_content_key_is_deterministic() {
        let k1 = site_content_key(&[7u8; 32]);
        let k2 = site_content_key(&[7u8; 32]);
        let k3 = site_content_key(&[8u8; 32]);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn collect_files_skips_publish_artifacts() {
        // A directory that already contains publish output must not sign that
        // output (a beginner's footgun: re-publishing would otherwise grow the
        // manifest with its own manifest.json / storage.db).
        let dir = std::env::temp_dir().join(format!("zrs_pub_art_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), b"x").unwrap();
        std::fs::write(dir.join("manifest.json"), b"{...}").unwrap();
        std::fs::write(dir.join("storage.db"), b"sqlite").unwrap();

        let files = collect_files(&dir).unwrap();
        let names: Vec<String> = files.iter().map(|f| f.0.clone()).collect();
        assert_eq!(
            names,
            vec!["index.html"],
            "only real content, got {names:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    use content::sign::Identity;

    #[test]
    fn collect_files_orders_nested_paths_deterministically() {
        let dir = std::env::temp_dir().join(format!("zrs_pub_order_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("z")).unwrap();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::write(dir.join("b.txt"), b"b").unwrap();
        std::fs::write(dir.join("z").join("c.txt"), b"c").unwrap();
        std::fs::write(dir.join("a").join("d.txt"), b"d").unwrap();

        let files = collect_files(&dir).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
        assert_eq!(paths, vec!["a/d.txt", "b.txt", "z/c.txt"], "got {paths:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_publish_flow_writes_manifest_and_db() {
        let dir = std::env::temp_dir().join(format!("zrs_pub_it_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("css")).unwrap();
        std::fs::write(dir.join("index.html"), b"<html>test</html>").unwrap();
        std::fs::write(dir.join("css").join("main.css"), b"body {}").unwrap();

        let id = Identity::generate();
        let m = build_site_manifest(&dir, id.site_key(), &id.signing_key).unwrap();
        assert_eq!(m.file_count, 2);
        merkle::verify_manifest(&m).unwrap();

        // Persist exactly as main.rs does.
        let db = storage::Db::open(dir.join("storage.db")).unwrap();
        let hashes: Vec<[u8; 32]> = m.files.iter().map(|f| f.hash).collect();
        db.save_hashfield(&hashes).unwrap();
        db.save_site_manifest(&m.site_key, &m).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&m).unwrap(),
        )
        .unwrap();

        assert!(dir.join("manifest.json").exists());
        assert!(dir.join("storage.db").exists());
        let loaded = storage::Db::open(dir.join("storage.db"))
            .unwrap()
            .load_site_manifests()
            .unwrap();
        assert_eq!(loaded.len(), 1);
        merkle::verify_manifest(&loaded[0].1).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
