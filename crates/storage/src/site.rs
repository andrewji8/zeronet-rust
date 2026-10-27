//! Site path management.

use std::path::{Path, PathBuf};
use tokio::fs;

/// Resolve a relative file path to the absolute on-disk path for a site.
pub fn site_file_path(root: &Path, rel: &str) -> PathBuf {
    root.join(rel)
}

/// Ensure the parent directory of `path` exists.
pub async fn ensure_parent(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    Ok(())
}
