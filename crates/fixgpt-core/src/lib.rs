//! Core turn-state and account policy primitives for FixGPT.
//!
//! This crate deliberately treats the upstream state envelope as opaque data.
//! It validates only the observed shape and timestamp needed by the local
//! scheduling heuristic.

pub mod credential;
pub mod policy;
pub mod store;
pub mod token;

pub use credential::{CredentialLimit, RejectedStatus};
pub use policy::{AccountKind, InjectionMode, StateFallback, StatePolicy};
pub use store::{Snapshot, StateStore, StoreStatus};
pub use token::{HEADER_NAME, TurnState};
