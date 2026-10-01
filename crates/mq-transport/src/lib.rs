//! spec §4
//!
//! Rules (spec §4.8): methods copy `inner.engine` before calling xquic and hold no `&`/`&mut` into
//! `Inner` across the call; trampolines reach `Inner` only through `clock::current()` in short
//! raw-pointer scopes; `new` enters with `Time(0)` and `release_thread`s on failure; `close(self, now)`
//! destroys under the guard and `Drop` must not destroy twice (an `engine: *mut` nulled after destroy).

// TODO(task 4.6): remove
#![allow(dead_code)]

mod clock;
mod engine;
mod events;
mod ffi;
mod slots;
mod txq;

use mq_transport_api::{Time, TransportConfig};
use slots::{ConnSlot, Slots, StreamSlot};
use std::ffi::CString;
use std::fs::File;

/// Everything a callback can reach (spec §4.8). Lives in a `Box` owned by `Transport`, so its
/// address is stable for the transport's lifetime.
pub(crate) struct Inner {
    /// Null once destroyed (destroy-once, spec §4.2 `close`).
    engine: *mut xquic_sys::xqc_engine_t,
    /// Role, max_conns, scheduler, cc: read by `connect` / admission (Task 4.6).
    cfg: TransportConfig,
    /// NUL-terminated copy of `cfg.alpn` for `xqc_connect`.
    alpn: CString,
    /// Established connections that passed the second cap check (spec §4.7).
    n_counted: u32,
    /// Accepted, not yet admitted or released (spec §4.7).
    n_provisional: u32,
    conns: Slots<ConnSlot>,
    streams: Slots<StreamSlot>,
    txq: txq::TxQueues,
    events: events::Events,
    /// Recorded by `set_event_timer` (spec §4.3).
    deadline: Option<Time>,
    /// The last `now` a method was given; `Drop` destroys with it (spec §4.2).
    last_now: Time,
    /// qlog sink; written only while open (spec §4.9).
    qlog: Option<File>,
}

/// One xquic engine (spec §4). `!Send + !Sync` through the raw engine pointer in `Inner`.
pub struct Transport {
    inner: Box<Inner>,
}

#[derive(Debug)]
pub enum Error {
    /// spec §4.6
    EngineAlreadyOnThread,
    /// `xqc_engine_create` (e.g. unreadable cert/key) or ALPN registration failed.
    EngineCreate,
    /// Invalid configuration (e.g. a path or ALPN with an interior NUL).
    Config(String),
    Qlog(std::io::Error),
}
