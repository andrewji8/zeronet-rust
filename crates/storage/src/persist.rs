//! SQLite persistence for the storage layer: the local `HashField` index and
//! cached `SiteManifest`s.
//!
//! The point is to survive restarts: after a node downloads files, the hash
//! index and any fetched manifests are written here; on next start they are
//! reloaded so we know what is already local.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::hashfield::HashField;
use content::SiteManifest;

/// Errors from the persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("poisoned mutex")]
    Poisoned,
}

/// A SQLite-backed store for the hash index and site manifests.
///
/// Wraps a `rusqlite::Connection` in a `Mutex` so a `&Db` can be shared across
/// tasks (`Send`).
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Open (or create) the database at `path`, ensuring schema exists.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS hashfield (
                hash BLOB NOT NULL PRIMARY KEY
             );
             CREATE TABLE IF NOT EXISTS site_manifest (
                site_key BLOB NOT NULL PRIMARY KEY,
                json     TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, DbError> {
        self.conn.lock().map_err(|_| DbError::Poisoned)
    }

    // ---- HashField ----

    /// Load all known hashes into a fresh `HashField`.
    pub fn load_hashfield(&self) -> Result<HashField, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT hash FROM hashfield")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = HashField::new();
        for r in rows {
            let b = r?;
            if b.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                out.insert(h);
            }
        }
        Ok(out)
    }

    /// Replace the entire hash index with `hashes`.
    pub fn save_hashfield(&self, hashes: &[[u8; 32]]) -> Result<(), DbError> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM hashfield", [])?;
        for h in hashes {
            conn.execute(
                "INSERT OR IGNORE INTO hashfield(hash) VALUES (?1)",
                params![h.as_slice()],
            )?;
        }
        Ok(())
    }

    // ---- SiteManifests ----

    /// Store one site manifest keyed by its 32-byte site key.
    pub fn save_site_manifest(&self, site_key: &[u8; 32], m: &SiteManifest) -> Result<(), DbError> {
        let json = serde_json::to_string(m)?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO site_manifest(site_key, json) VALUES (?1, ?2)
             ON CONFLICT(site_key) DO UPDATE SET json = excluded.json",
            params![site_key.as_slice(), json],
        )?;
        Ok(())
    }

    /// Load all stored manifests.
    pub fn load_site_manifests(&self) -> Result<Vec<([u8; 32], SiteManifest)>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT site_key, json FROM site_manifest")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (b, j) = r?;
            if b.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                let m: SiteManifest = serde_json::from_str(&j)?;
                out.push((k, m));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashfield::HashField;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("zrs_persist_{}_{}", name, std::process::id()))
    }

    #[test]
    fn hashfield_roundtrip() {
        let path = tmp_path("hf");
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();

        let mut hf = HashField::new();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        hf.insert(h1);
        hf.insert(h2);
        db.save_hashfield(&hf.all()).unwrap();

        let reloaded = Db::open(&path).unwrap().load_hashfield().unwrap();
        assert!(reloaded.has(&h1), "h1 must be persisted");
        assert!(reloaded.has(&h2), "h2 must be persisted");
        assert_eq!(reloaded.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn manifest_roundtrip() {
        let path = tmp_path("mf");
        let _ = std::fs::remove_file(&path);

        let identity = content::sign::Identity::generate();
        let data = b"hello";
        let entry = content::FileEntry {
            path: "f".into(),
            hash: content::merkle::file_hash(data),
            size: data.len() as u64,
            optional: false,
        };
        let manifest = content::merkle::build_manifest(
            identity.site_key(),
            vec![entry],
            &identity.signing_key,
            123,
        );
        content::merkle::verify_manifest(&manifest).unwrap();

        let db = Db::open(&path).unwrap();
        db.save_site_manifest(&identity.site_key(), &manifest)
            .unwrap();

        let loaded = db.load_site_manifests().unwrap();
        assert_eq!(loaded.len(), 1);
        let (k, m) = &loaded[0];
        assert_eq!(*k, identity.site_key());
        content::merkle::verify_manifest(m).unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
