//! Per-query peer state machine (PeerHeard -> PeerWaiting -> PeerQueried | PeerUnreachable).

use std::collections::{HashMap, VecDeque};

use crate::PeerId;

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum PeerState {
    Heard,
    Waiting,
    Queried,
    Unreachable,
}

/// The set of peers known to one lookup and their states.
#[derive(Default)]
pub struct QueryPeerset {
    state: HashMap<PeerId, PeerState>,
    /// Ordered by distance to target; closest first.
    order: VecDeque<PeerId>,
    referrer: HashMap<PeerId, PeerId>,
}

impl QueryPeerset {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a peer (idempotent). `by` is the referrer that told us about it.
    pub fn try_add(&mut self, id: PeerId, by: PeerId) -> bool {
        if self.state.contains_key(&id) {
            return false;
        }
        self.state.insert(id, PeerState::Heard);
        self.referrer.insert(id, by);
        self.order.push_back(id);
        true
    }

    pub fn set_state(&mut self, id: PeerId, s: PeerState) {
        if self.state.contains_key(&id) {
            self.state.insert(id, s);
        }
    }

    pub fn get_state(&self, id: &PeerId) -> Option<PeerState> {
        self.state.get(id).copied()
    }

    pub fn referrer(&self, id: &PeerId) -> Option<PeerId> {
        self.referrer.get(id).copied()
    }

    pub fn num_heard(&self) -> usize {
        self.state
            .values()
            .filter(|s| **s == PeerState::Heard)
            .count()
    }

    pub fn num_waiting(&self) -> usize {
        self.state
            .values()
            .filter(|s| **s == PeerState::Waiting)
            .count()
    }

    /// Closest `n` peers in any of the given states.
    pub fn get_closest_n_in_states(&self, n: usize, states: &[PeerState]) -> Vec<PeerId> {
        self.order
            .iter()
            .filter(|id| {
                self.get_state(id)
                    .map(|s| states.contains(&s))
                    .unwrap_or(false)
            })
            .copied()
            .take(n)
            .collect()
    }

    /// All peers currently in `states` (used to pick the next query wave).
    pub fn peers_in_states(&self, n: usize, states: &[PeerState]) -> Vec<PeerId> {
        self.order
            .iter()
            .filter(|id| {
                self.get_state(id)
                    .map(|s| states.contains(&s))
                    .unwrap_or(false)
            })
            .copied()
            .take(n)
            .collect()
    }
}
