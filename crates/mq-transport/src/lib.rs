//! spec §4
//!
//! Rules (spec §4.8): methods copy `inner.engine` before calling xquic and hold no `&`/`&mut` into
//! `Inner` across the call; trampolines reach `Inner` only through `clock::current()` in short
//! raw-pointer scopes; `new` enters with `Time(0)` and `release_thread`s on failure; `close(self, now)`
//! destroys under the guard and `Drop` must not destroy twice (an `engine: *mut` nulled after destroy).

// TODO(task 4.6): remove
#![allow(dead_code)]

mod clock;

/// Stub; fleshed out in Tasks 4.5/4.6.
pub(crate) struct Inner;

/// Extended in Task 4.5.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    EngineAlreadyOnThread,
    // more later
}
