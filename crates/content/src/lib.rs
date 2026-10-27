//! Content-addressing layer: Ed25519 + BLAKE3 Merkle trees, with a ZeroNet
//! compatibility shim (Secp256k1 content.json).
//!
//! - `manifest`: site manifest (tree root + signature)
//! - `merkle`:   BLAKE3 Merkle tree, 15 MB max block
//! - `sign`:     Ed25519 keypair, 112-byte signable block
//! - `compat`:   parse / emit ZeroNet `content.json` (Secp256k1 + sha512)

pub mod compat;
pub mod manifest;
pub mod merkle;
pub mod secp;
pub mod sign;

use serde::{Deserialize, Serialize};

/// A file entry inside a site manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path inside the site, e.g. "index.html".
    pub path: String,
    /// BLAKE3 hash of the file bytes.
    pub hash: [u8; 32],
    /// File size in bytes.
    pub size: u64,
    /// Optional (skippable) content, e.g. large media.
    #[serde(default)]
    pub optional: bool,
}

/// The site manifest. This is what gets signed and stored in the DHT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteManifest {
    /// Site address (ed25519 public key, 32 bytes).
    pub site_key: [u8; 32],
    /// BLAKE3 Merkle tree root over all file entries.
    pub tree_hash: [u8; 32],
    /// Total number of files.
    pub file_count: u32,
    /// Total bytes of required content.
    pub total_size: u64,
    /// Unix modification timestamp.
    pub modified: i64,
    /// Ed25519 signature over the 112-byte signable block.
    pub signature: Vec<u8>,
    /// Individual file entries.
    #[serde(default)]
    pub files: Vec<FileEntry>,
}
