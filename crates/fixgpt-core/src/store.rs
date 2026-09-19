use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::policy::StatePolicy;
use crate::token::TurnState;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub token: TurnState,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreStatus {
    pub usable: bool,
    pub version: u64,
    pub remaining_seconds: i64,
    pub ready: bool,
    pub strikes: u32,
    pub observations: u64,
}

#[derive(Default)]
struct Inner {
    policy: StatePolicy,
    active: Option<Snapshot>,
    ready: Option<Snapshot>,
    version: u64,
    strikes: u32,
    candidates: u64,
}

pub struct StateStore {
    inner: Mutex<Inner>,
}

impl StateStore {
    pub fn new(policy: StatePolicy) -> Self {
        Self {
            inner: Mutex::new(Inner {
                policy,
                ..Inner::default()
            }),
        }
    }

    pub fn acquire(&self, now_seconds: i64) -> Option<Snapshot> {
        let mut inner = self.lock();
        promote(&mut inner, now_seconds);
        inner
            .active
            .as_ref()
            .filter(|active| inner.policy.accept(&active.token, now_seconds))
            .cloned()
    }

    pub fn offer(&self, token: TurnState, now_seconds: i64) -> bool {
        let mut inner = self.lock();
        inner.candidates = inner.candidates.saturating_add(1);
        if !inner.policy.accept(&token, now_seconds) {
            return false;
        }

        let active_same = inner
            .active
            .as_ref()
            .is_some_and(|active| active.token.fingerprint == token.fingerprint);
        if active_same {
            return true;
        }

        let active_usable = inner
            .active
            .as_ref()
            .is_some_and(|active| inner.policy.accept(&active.token, now_seconds));

        if !active_usable {
            inner.version = inner.version.saturating_add(1);
            inner.active = Some(Snapshot {
                token,
                version: inner.version,
            });
            inner.ready = None;
            inner.strikes = 0;
            return true;
        }

        let replace_ready = inner
            .ready
            .as_ref()
            .is_none_or(|ready| token.issued_at >= ready.token.issued_at);
        if replace_ready {
            inner.ready = Some(Snapshot { token, version: 0 });
        }
        promote(&mut inner, now_seconds);
        true
    }

    /// Records a response observation without promoting it.
    ///
    /// `used` is the immutable snapshot attached to the request. A late response
    /// for an old snapshot cannot add strikes to a newer active value.
    pub fn observe(&self, value: impl AsRef<str>, used: &Snapshot, now_seconds: i64) -> bool {
        let mut inner = self.lock();
        inner.candidates = inner.candidates.saturating_add(1);

        let token = crate::token::TurnState::parse(value.as_ref());
        let suspect = match token {
            Ok(token) => !inner.policy.accept(&token, now_seconds),
            Err(_) => true,
        };

        let current = inner.active.as_ref().is_some_and(|active| {
            active.version == used.version && active.token.fingerprint == used.token.fingerprint
        });
        if current {
            inner.strikes = if suspect {
                inner.strikes.saturating_add(1)
            } else {
                0
            };
        }
        suspect
    }

    pub fn needs_refresh(&self, now_seconds: i64) -> bool {
        let mut inner = self.lock();
        promote(&mut inner, now_seconds);
        let Some(active) = inner.active.as_ref() else {
            return true;
        };
        !inner.policy.accept(&active.token, now_seconds)
            || inner.strikes >= 2
            || now_seconds.saturating_add(inner.policy.refresh_before_seconds)
                > active
                    .token
                    .issued_at
                    .saturating_add(inner.policy.ttl_seconds)
    }

    pub fn status(&self, now_seconds: i64) -> StoreStatus {
        let inner = self.lock();
        let active = inner.active.as_ref();
        let ready = inner.ready.as_ref();
        StoreStatus {
            usable: active.is_some_and(|value| inner.policy.accept(&value.token, now_seconds)),
            version: active.map_or(0, |value| value.version),
            remaining_seconds: active
                .map(|value| {
                    value
                        .token
                        .issued_at
                        .saturating_add(inner.policy.ttl_seconds)
                        .saturating_sub(now_seconds)
                        .max(0)
                })
                .unwrap_or_default(),
            ready: ready.is_some_and(|value| inner.policy.accept(&value.token, now_seconds)),
            strikes: inner.strikes,
            observations: inner.candidates,
        }
    }

    /// Invalidates only the active snapshot used by the failed request.
    pub fn reject_and_promote(&self, used: &Snapshot, now_seconds: i64) -> bool {
        let mut inner = self.lock();
        let matches = inner.active.as_ref().is_some_and(|active| {
            active.version == used.version && active.token.fingerprint == used.token.fingerprint
        });
        if !matches {
            return false;
        }
        inner.active = None;
        inner.strikes = 0;
        promote(&mut inner, now_seconds);
        inner
            .active
            .as_ref()
            .is_some_and(|active| inner.policy.accept(&active.token, now_seconds))
    }

    pub fn policy(&self) -> StatePolicy {
        self.lock().policy.clone()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn promote(inner: &mut Inner, now_seconds: i64) {
    let Some(ready) = inner.ready.as_ref() else {
        return;
    };

    let ready_usable = inner.policy.accept(&ready.token, now_seconds);
    let active_usable = inner
        .active
        .as_ref()
        .is_some_and(|active| inner.policy.accept(&active.token, now_seconds));
    let active_same = inner
        .active
        .as_ref()
        .is_some_and(|active| active.token.fingerprint == ready.token.fingerprint);
    let refresh_due = inner.active.as_ref().is_some_and(|active| {
        now_seconds.saturating_add(inner.policy.refresh_before_seconds)
            > active
                .token
                .issued_at
                .saturating_add(inner.policy.ttl_seconds)
    });
    let newer_ready = inner
        .active
        .as_ref()
        .is_some_and(|active| ready.token.issued_at > active.token.issued_at);
    let should_promote = ready_usable
        && !active_same
        && (!active_usable || inner.strikes >= 2 || (refresh_due && newer_ready));

    if !should_promote {
        return;
    }

    inner.version = inner.version.saturating_add(1);
    let mut promoted = ready.clone();
    promoted.version = inner.version;
    inner.active = Some(promoted);
    inner.ready = None;
    inner.strikes = 0;
}
impl Default for StatePolicy {
    fn default() -> Self {
        Self::personal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TurnState;

    fn state(seed: &str, issued_at: i64, blocks: usize) -> TurnState {
        TurnState {
            value: format!("value-{seed}"),
            fingerprint: format!("fingerprint-{seed}"),
            issued_at,
            blocks,
        }
    }

    #[test]
    fn first_valid_state_becomes_active() {
        let store = StateStore::new(StatePolicy::personal());
        assert!(store.offer(state("a", 1_800_000_000, 10), 1_800_000_001));
        let active = store.acquire(1_800_000_001).expect("active");
        assert_eq!(active.token.fingerprint, "fingerprint-a");
    }

    #[test]
    fn healthy_active_keeps_new_state_as_ready() {
        let store = StateStore::new(StatePolicy::personal());
        assert!(store.offer(state("a", 1_800_000_000, 10), 1_800_000_001));
        assert!(store.offer(state("b", 1_800_000_010, 10), 1_800_000_011));
        let active = store.acquire(1_800_000_011).expect("active");
        assert_eq!(active.token.fingerprint, "fingerprint-a");
        assert!(store.status(1_800_000_011).ready);
    }

    #[test]
    fn strikes_promote_ready_state() {
        let store = StateStore::new(StatePolicy::personal());
        assert!(store.offer(state("a", 1_800_000_000, 10), 1_800_000_001));
        assert!(store.offer(state("b", 1_800_000_010, 10), 1_800_000_011));
        let active = store.acquire(1_800_000_011).expect("active");
        assert!(store.observe("invalid", &active, 1_800_000_012));
        assert!(store.observe("invalid", &active, 1_800_000_013));
        let promoted = store.acquire(1_800_000_013).expect("promoted");
        assert_eq!(promoted.token.fingerprint, "fingerprint-b");
    }

    #[test]
    fn stale_observation_does_not_affect_newer_active() {
        let store = StateStore::new(StatePolicy::personal());
        assert!(store.offer(state("a", 1_800_000_000, 10), 1_800_000_001));
        let stale = store.acquire(1_800_000_001).expect("active");
        assert!(store.offer(state("b", 1_800_000_010, 10), 1_800_000_011));
        assert!(store.reject_and_promote(&stale, 1_800_000_011));
        assert!(store.observe("invalid", &stale, 1_800_000_012));
        assert_eq!(store.status(1_800_000_012).strikes, 0);
    }

    #[test]
    fn expired_state_is_not_usable() {
        let store = StateStore::new(StatePolicy::personal());
        assert!(store.offer(state("a", 1_800_000_000, 10), 1_800_000_001));
        let status = store.status(1_800_010_000);
        assert!(!status.usable);
        assert!(store.needs_refresh(1_800_010_000));
    }
}
