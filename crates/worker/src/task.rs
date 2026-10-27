//! Task state tracking.

/// The lifecycle state of a download task.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaskState {
    Pending,
    InFlight,
    Done,
    Failed { attempts: u32 },
}
