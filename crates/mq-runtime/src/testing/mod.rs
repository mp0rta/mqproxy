// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Test harness support (spec §8.1), behind the `test-support` feature.

mod fake_io;
pub mod log_capture;
mod recording_app;
mod scripted;

pub use fake_io::{FakeIo, Op};
pub use recording_app::{RecordHandle, Recorded, RecordingApp};
pub use scripted::{Call, ScriptedHandle, ScriptedTransport};
