//! SQLite persistence for the Kademlia routing table.
//!
//! Lets a restarting node rebuild its routing table from disk instead of
//! re-discovering every peer from scratch.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::rt::{RoutingTable, RtPeer};
use crate::KadConfig;
use crate::PeerId;

/// Errors from the Kademlia persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("poisoned mutex")]
    Poisoned,
}

/// SQLite-backed routing table persistence.
pub struct RtDb {
    conn: Mutex<Connection>,
}

impl RtDb {
    /// Open (or create) the database at `path`, ensuring the schema exists.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rt_peer (
                id      BLOB NOT NULL PRIMARY KEY,
                ip_group INTEGER
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, DbError> {
        self.conn.lock().map_err(|_| DbError::Poisoned)
    }

    /// Persist every peer currently in `table`.
    pub fn save_routing_table(&self, table: &RoutingTable) -> Result<(), DbError> {
        let conn = self.conn()?;
        // We need the full peer set; RoutingTable exposes `nearest_peers(self, ...)`
        // but no drain iterator, so query it with a large n (bucket_size * 256
        // covers the theoretical max peers a table can hold).
        let cap = (table.config.bucket_size as usize) * 256;
        let zeros = PeerId([0u8; 32]);
        let peers = table.nearest_peers(&zeros, cap);

        conn.execute("DELETE FROM rt_peer", [])?;
        for p in &peers {
            conn.execute(
                "INSERT OR IGNORE INTO rt_peer(id, ip_group) VALUES (?1, ?2)",
                params![p.id.0.as_slice(), p.ip_group],
            )?;
        }
        Ok(())
    }

    /// Rebuild a `RoutingTable` from disk.
    pub fn load_routing_table(
        &self,
        self_id: PeerId,
        config: KadConfig,
    ) -> Result<RoutingTable, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, ip_group FROM rt_peer")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?))
        })?;
        let mut table = RoutingTable::new(self_id, config);
        for r in rows {
            let (b, group_i64) = r?;
            if b.len() == 32 {
                let mut raw = [0u8; 32];
                raw.copy_from_slice(&b);
                let ip_group = match group_i64 {
                    Some(v) if (0..=u32::MAX as i64).contains(&v) => Some(v as u32),
                    _ => None,
                };
                table.add_peer(RtPeer {
                    id: PeerId(raw),
                    ip_group,
                });
            }
        }
        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_table_roundtrip() {
        let path = std::env::temp_dir().join(format!("zrs_kad_rt_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let cfg = KadConfig::default();
        let self_id = PeerId([1u8; 32]);
        let mut table = RoutingTable::new(self_id, cfg.clone());
        table.add_peer(RtPeer {
            id: PeerId([2u8; 32]),
            ip_group: Some(7),
        });
        table.add_peer(RtPeer {
            id: PeerId([3u8; 32]),
            ip_group: None,
        });

        let db = RtDb::open(&path).unwrap();
        db.save_routing_table(&table).unwrap();

        let reloaded = RtDb::open(&path)
            .unwrap()
            .load_routing_table(self_id, cfg)
            .unwrap();
        assert!(reloaded.find(&PeerId([2u8; 32])).is_some());
        assert!(reloaded.find(&PeerId([3u8; 32])).is_some());
        assert_eq!(reloaded.find(&PeerId([2u8; 32])).unwrap().ip_group, Some(7));
        let _ = std::fs::remove_file(&path);
    }
}
