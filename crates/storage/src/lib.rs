//! Local storage layer: site directories, hash index, content.json cache.
//!
//! Replaces ZeroNet's `SiteStorage` + `ContentDbDict` with typed,
//! testable modules.

pub mod site;
pub mod hashfield;
pub mod persist;

pub use persist::{Db, DbError};

use content::SiteManifest;
use std::path::PathBuf;
use tokio::fs;

/// The on-disk layout of a single site.
pub struct SiteStore {
    /// Root directory for this site (contains content.json + files/).
    pub root: PathBuf,
    /// The site's manifest (in-memory).
    pub manifest: SiteManifest,
}

impl SiteStore {
    /// Open (or create) the store for a site.
    pub async fn open(root: PathBuf, manifest: SiteManifest) -> Result<Self, StorageError> {
        fs::create_dir_all(&root).await?;
        Ok(Self { root, manifest })
    }

    /// Write a file into the site, verifying it against the manifest.
    pub async fn write_file(&self, rel_path: &str, data: &[u8]) -> Result<(), StorageError> {
        let entry = self.manifest.files.iter().find(|f| f.path == rel_path)
            .ok_or(StorageError::FileNotInManifest(rel_path.to_string()))?;
        if !content::merkle::verify_file(entry, data) {
            return Err(StorageError::HashMismatch(rel_path.to_string()));
        }
        let target = self.root.join(rel_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&target, data).await?;
        Ok(())
    }

    /// Read a file back.
    pub async fn read_file(&self, rel_path: &str) -> Result<Vec<u8>, StorageError> {
        fs::read(self.root.join(rel_path)).await.map_err(Into::into)
    }
}

/// Verify `data` against an expected BLAKE3 hash and write it to
/// `root/rel_path`, guarding against path traversal.
///
/// This is the primitive the download path uses: after a file arrives from a
/// peer we BLAKE3-check it before touching the filesystem, so a malicious or
/// corrupted peer can never write an unexpected file.
pub async fn store_verified(
    root: &std::path::Path,
    expected: [u8; 32],
    rel_path: &str,
    data: &[u8],
) -> Result<std::path::PathBuf, StorageError> {
    if content::merkle::file_hash(data) != expected {
        return Err(StorageError::HashMismatch(rel_path.to_string()));
    }
    let target = safe_join(root, rel_path)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(&target, data).await?;
    Ok(target)
}

/// `root.join(rel)` with a "no `..` component" guard.
fn safe_join(root: &std::path::Path, rel: &str) -> Result<std::path::PathBuf, StorageError> {
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        return Err(StorageError::BadPath(rel.to_string()));
    }
    for c in p.components() {
        if matches!(c, std::path::Component::ParentDir) {
            return Err(StorageError::BadPath(rel.to_string()));
        }
    }
    Ok(root.join(p))
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("file not in manifest: {0}")]
    FileNotInManifest(String),
    #[error("hash mismatch: {0}")]
    HashMismatch(String),
    #[error("unsafe path: {0}")]
    BadPath(String),
}


