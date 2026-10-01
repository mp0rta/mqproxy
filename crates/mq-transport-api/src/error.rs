//! Error types (spec §4.2). Plain enums; this crate has no dependencies.

/// Stream operation failure (spec §4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StreamError {
    /// Nothing accepted / no data available.
    Blocked,
    /// The peer reset the stream.
    Reset,
    /// The id's object is gone (spec §4.8).
    Stale,
    /// Connection-level failure.
    Conn,
}

/// `add_path` failure (spec §4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathError {
    /// No path id available yet; `MpReady` is raised again once one is.
    NoPathId,
    Stale,
    Other,
}

/// `connect` failure. (`max_conns` is a server-side accept limit, so a
/// client `connect` has no "limit" case.)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConnectError {
    /// The engine refused; carries xquic's return code.
    Other(i32),
}

/// Failure of `open_stream` / `conn_stats` / `stream_info` (spec §4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    Stale,
    /// Operation not allowed for this role (server `open_stream`).
    Role,
    /// 8192 stream-slot ceiling reached (spec §4.2).
    Ceiling,
    Other,
}

macro_rules! debug_display {
    ($($t:ty),*) => {$(
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(self, f)
            }
        }
        impl std::error::Error for $t {}
    )*};
}
debug_display!(StreamError, PathError, ConnectError, Error);
