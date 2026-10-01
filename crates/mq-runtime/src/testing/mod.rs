//! Test harness support (spec §8.1), behind the `test-support` feature.

pub mod log_capture;
mod recording_app;
mod scripted;

pub use recording_app::{RecordHandle, Recorded, RecordingApp};
pub use scripted::{Call, ScriptedHandle, ScriptedTransport};
