//! Routing-table refresh: periodically ping stale buckets and top them up.

use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::Kademlia;

/// Spawn a background refresh loop. Cancel it by dropping the returned
/// `JoinHandle` (or by cancelling its parent task).
pub fn spawn_refresh(dht: &Kademlia, period: Duration) -> tokio::task::JoinHandle<()> {
    let dht = dht.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            refresh_once(&dht).await;
        }
    })
}

async fn refresh_once(dht: &Kademlia) {
    let stale = dht.rt.lock().await.stale_bucket_ids();
    // In a full implementation, each stale bucket triggers a Kademlia lookup
    // for a random target within that bucket, then inserts new closest peers.
    // That wire work is owned by the `net` crate; here we just drive the timer.
    let _ = stale;
}



