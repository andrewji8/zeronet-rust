//! Kademlia lookup with follow-up pass.

use std::collections::VecDeque;

use crate::{KadConfig, Kademlia, PeerId};
use super::peerset::{PeerState, QueryPeerset};

/// A pluggable transport that queries one peer and returns the closer peers it knows.
pub trait QueryTransport: Send + Sync {
    fn query_peers(
        &self,
        peer: &PeerId,
        target: &PeerId,
    ) -> impl std::future::Future<Output = Result<Vec<PeerId>, String>> + Send;
}

/// Result of a lookup.
#[derive(Debug, Default)]
pub struct LookupResult {
    /// The top-k closest (reachable) peers, ordered by distance.
    pub closest: Vec<PeerId>,
    /// Whether the lookup ran to normal termination vs. was cancelled/starved.
    pub completed: bool,
}

/// Run a Kademlia lookup for `target`, following the Amino parameters in `dht.config`.
///
/// `transport` is used to issue the per-peer queries. The routing table provides the
/// seed peers; discovered closer peers are tracked in a `QueryPeerset`.
pub async fn run_lookup<T: QueryTransport>(dht: &Kademlia, target: &PeerId, transport: &T) -> LookupResult {
    let config: KadConfig = dht.config.clone();
    let alpha = config.concurrency as usize;
    let beta = config.resiliency as usize;
    let k = config.bucket_size as usize;

    // Seed from routing table.
    let rt = dht.rt.clone();
    let seed = {
        let guard = rt.lock().await;
        guard.nearest_peers(target, k)
    };
    let seeds: Vec<PeerId> = seed.into_iter().map(|p| p.id).collect();
    if seeds.is_empty() {
        return LookupResult::default();
    }

    let mut peerset = QueryPeerset::new();
    for s in &seeds {
        peerset.try_add(*s, dht.self_id);
    }

    let mut result = LookupResult::default();
    loop {
        // Next wave: closest Heard peers, up to alpha.
        let wave: Vec<PeerId> = peerset.peers_in_states(alpha, &[PeerState::Heard]);
        if wave.is_empty() {
            break; // starvation termination
        }

        // Mark waiting, query concurrently.
        for p in &wave {
            peerset.set_state(*p, PeerState::Waiting);
        }

        let results: Vec<Result<Vec<PeerId>, String>> = futures::future::join_all(
            wave.iter().map(|p| transport.query_peers(p, target)),
        )
        .await;

        for (p, res) in wave.iter().zip(results.into_iter()) {
            match res {
                Ok(closer) => {
                    // Anti-spam: cap closer peers returned by one response at 2k.
                    let mut closer: VecDeque<PeerId> = closer.into_iter().collect();
                    let cap = 2 * k;
                    closer.truncate(cap);
                    for c in closer {
                        if c != dht.self_id {
                            peerset.try_add(c, *p);
                        }
                    }
                    peerset.set_state(*p, PeerState::Queried);
                }
                Err(_) => {
                    peerset.set_state(*p, PeerState::Unreachable);
                }
            }
        }

        // Termination: are the beta closest peers all Queried?
        let closest = peerset.get_closest_n_in_states(
            beta,
            &[PeerState::Heard, PeerState::Waiting, PeerState::Queried],
        );
        let all_queried = closest.iter().all(|p| peerset.get_state(p) == Some(PeerState::Queried));
        if all_queried {
            // Follow-up pass: query any Heard/Waiting top-k peers not yet queried.
            let followup: Vec<PeerId> = peerset.peers_in_states(k, &[PeerState::Heard, PeerState::Waiting]);
            if !followup.is_empty() {
                for p in &followup {
                    peerset.set_state(*p, PeerState::Waiting);
                }
                let fu: Vec<Result<Vec<PeerId>, String>> = futures::future::join_all(
                    followup.iter().map(|p| transport.query_peers(p, target)),
                )
                .await;
                for (p, res) in followup.iter().zip(fu.into_iter()) {
                    match res {
                        Ok(closer) => {
                            for c in closer {
                                if c != dht.self_id {
                                    peerset.try_add(c, *p);
                                }
                            }
                            peerset.set_state(*p, PeerState::Queried);
                        }
                        Err(_) => peerset.set_state(*p, PeerState::Unreachable),
                    }
                }
            }
            result.closest = peerset.get_closest_n_in_states(
                k,
                &[PeerState::Heard, PeerState::Waiting, PeerState::Queried],
            );
            result.completed = true;
            return result;
        }
    }

    // Starvation: no Heard peers left.
    result.closest = peerset.get_closest_n_in_states(
        k,
        &[PeerState::Heard, PeerState::Waiting, PeerState::Queried],
    );
    result.completed = false;
    result
}

