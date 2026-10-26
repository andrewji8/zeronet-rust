//! Site path management.

use std::path::PathBuf;
use tokio::fs;

/// Resolve a relative file path to the absolute on-disk path for a site.
pub fn site_file_path(root: &PathBuf, rel: &str) -> PathBuf {
    root.join(rel)
}

/// Ensure the parent directory of `path` exists.
pub async fn ensure_parent(path: &PathBuf) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    Ok(())
}
