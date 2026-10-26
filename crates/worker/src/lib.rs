//! Download task pool: concurrent file downloads with task scheduling.
//!
//! Replaces ZeroNet's `Worker` + `WorkerManager` with tokio task spawn.
//! No global monkey-patch; each task is an independent tokio::task.

pub mod task;
pub mod download;
pub mod engine;

pub use download::{download_and_store, download_via_dht, fetch_file, DownloadError, stage_of};
pub use engine::{DownloadEngine, DownloadTaskError, TaskOutcome};

use kad::PeerId;
use tokio::sync::mpsc;

/// The task queue shared between the dispatcher and workers.
pub struct TaskQueue {
    tx: mpsc::Sender<Task>,
}

/// A single download task.
pub struct Task {
    pub site: PeerId,
    /// Relative file path to fetch.
    pub path: String,
    pub peer: PeerId,
}

impl TaskQueue {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = mpsc::channel(capacity);
        Self { tx }
    }

    /// Push a task onto the queue.
    pub async fn push(&self, task: Task) {
        let _ = self.tx.send(task).await;
    }
}

/// Task completion statistics.
pub struct Stats {
    pub completed: std::sync::atomic::AtomicU32,
    pub failed: std::sync::atomic::AtomicU32,
}

impl Stats {
    pub fn new() -> Self {
        Self { completed: std::sync::atomic::AtomicU32::new(0), failed: std::sync::atomic::AtomicU32::new(0) }
    }
}






