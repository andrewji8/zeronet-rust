//! BLAKE3 Merkle tree over file entries.
//!
//! Block cap mirrors Hypercore's `MAX_SUGGESTED_BLOCK_SIZE = 15 MB`.

use super::{FileEntry, SiteManifest};
use blake3::Hasher;

pub const MAX_BLOCK_SIZE: u64 = 15 * 1024 * 1024;

/// Compute the BLAKE3 tree root for a set of file entries.
///
/// Tree construction: each leaf = BLAKE3(path || hash || size). The root is
/// BLAKE3 over all leaves (flat, depth-1 tree) for simplicity; a full
/// balanced tree can replace this without changing the API.
pub fn tree_hash(files: &[FileEntry]) -> [u8; 32] {
    let mut root = Hasher::new();
    for f in files {
        let mut leaf = Hasher::new();
        leaf.update(f.path.as_bytes());
        leaf.update(&f.hash);
        leaf.update(f.size.to_be_bytes().as_slice());
        let leaf_hash = *leaf.finalize().as_bytes();
        root.update(leaf_hash.as_slice());
    }
    *root.finalize().as_bytes()
}

/// BLAKE3 hash of raw file bytes.
pub fn file_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Verify a downloaded file against its manifest entry.
pub fn verify_file(entry: &FileEntry, data: &[u8]) -> bool {
    file_hash(data) == entry.hash && data.len() as u64 == entry.size
}

/// Build a fresh manifest from local files, signing it with `secret_key`.
pub fn build_manifest(
    site_key: [u8; 32],
    files: Vec<FileEntry>,
    secret_key: &ed25519_dalek::SigningKey,
    now_unix: i64,
) -> SiteManifest {
    let tree = tree_hash(&files);
    let total_size: u64 = files.iter().filter(|f| !f.optional).map(|f| f.size).sum();
    let signable = signable_block(&site_key, &tree, files.len() as u64, 0, now_unix as u64);
    use ed25519_dalek::Signer;
    let sig = Signer::sign(secret_key, &signable);
    SiteManifest {
        site_key,
        tree_hash: tree,
        file_count: files.len() as u32,
        total_size,
        modified: now_unix,
        signature: sig.to_bytes().to_vec(),
        files,
    }
}

/// Verify a manifest's Ed25519 signature against its signable block.
pub fn verify_manifest(m: &SiteManifest) -> Result<(), SignatureError> {
    let signable = signable_block(
        &m.site_key,
        &m.tree_hash,
        m.file_count as u64,
        0,
        m.modified as u64,
    );
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(&m.site_key)
        .map_err(|e| SignatureError::BadKey(e.to_string()))?;
    let sig = ed25519_dalek::Signature::from_slice(&m.signature)
        .map_err(|e| SignatureError::BadSignature(e.to_string()))?;
    use ed25519_dalek::Verifier;
    public_key
        .verify(&signable, &sig)
        .map_err(|e| SignatureError::BadSignature(e.to_string()))?;
    Ok(())
}

/// 112-byte signable block: site_key(32) + tree_hash(32) + file_count(8) +
/// fork(8) + modified(8) + 24 reserved bytes. Mirrors Hypercore's
/// `treeSignable` shape (TREE + manifestHash + treeHash + length + fork).
pub fn signable_block(
    site_key: &[u8; 32],
    tree_hash: &[u8; 32],
    file_count: u64,
    fork: u64,
    modified: u64,
) -> [u8; 112] {
    let mut out = [0u8; 112];
    out[0..32].copy_from_slice(site_key);
    out[32..64].copy_from_slice(tree_hash);
    out[64..72].copy_from_slice(&file_count.to_be_bytes());
    out[72..80].copy_from_slice(&fork.to_be_bytes());
    out[80..88].copy_from_slice(&modified.to_be_bytes());
    out
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("invalid site key: {0}")]
    BadKey(String),
    #[error("invalid signature: {0}")]
    BadSignature(String),
}

// Test that build_manifest + verify_manifest roundtrip works.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{build_manifest, file_hash, verify_manifest};
    use crate::sign::Identity;

    #[test]
    fn test_manifest_roundtrip() {
        let id = Identity::generate();
        let file_bytes = b"hello world";
        let files = vec![FileEntry {
            path: "index.html".to_string(),
            hash: file_hash(file_bytes),
            size: file_bytes.len() as u64,
            optional: false,
        }];

        let m = build_manifest(id.site_key(), files, &id.signing_key, 0);
        assert!(verify_manifest(&m).is_ok(), "valid manifest should verify");
    }

    #[test]
    fn test_file_hash_matches() {
        let data = b"test data";
        let h = file_hash(data);
        let entry = FileEntry {
            path: "f".into(),
            hash: h,
            size: data.len() as u64,
            optional: false,
        };
        assert!(crate::merkle::verify_file(&entry, data));
        let bad = b"wrong data";
        assert!(!crate::merkle::verify_file(&entry, bad));
    }
}
