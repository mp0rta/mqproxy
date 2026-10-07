// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! A process-global `log::Log`, for shards on other threads (`DriverThread`), where the
//! thread-local `mq_runtime::testing::log_capture` cannot see them. Lines accumulate across
//! the tests of one binary: each test filters by its own markers.

use std::sync::Mutex;

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Tap;

impl log::Log for Tap {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        let line = format!("{} {}", r.level(), r.args());
        LINES.lock().unwrap_or_else(|e| e.into_inner()).push(line);
    }
    fn flush(&self) {}
}

static TAP: Tap = Tap;

/// Installs the tap. Idempotent: a logger already installed (this one, or another) stays.
pub fn install() {
    let _ = log::set_logger(&TAP);
    log::set_max_level(log::LevelFilter::Info);
}

/// Every line logged so far (`"LEVEL message"`).
pub fn lines() -> Vec<String> {
    LINES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}
