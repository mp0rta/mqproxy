// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP4 spec §2.1: the in-shard pipe and executor shared by the SP3 origin
//! bridge and the MITM front — hyper, h2 and rustls are polled by hand with
//! the `Dirty` waker; no tokio task or channel on the data path.

mod exec;
mod pipe;
mod tls_io;

pub use exec::{Dirty, ShardExec};
#[cfg(any(test, feature = "test-support"))]
pub use pipe::pipe_pair;
pub use pipe::{PipeHandle, PipeIo, pipe};
pub use tls_io::{In, TlsIo};

/// spec §7.1/§9.3: each direction of the pipe.
pub const PIPE_CAP: usize = 64 * 1024;
/// spec §7.3/§7.4: one `tcp_write` slice, one upload frame.
pub const SLICE: usize = 16 * 1024;
