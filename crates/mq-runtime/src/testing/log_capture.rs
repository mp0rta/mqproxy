// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! A `log::Log` that appends formatted records to a thread-local buffer, so a
//! test can assert the log lines its own thread produced (spec §8.1).

use std::cell::RefCell;

thread_local! {
    static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        LINES.with(|l| l.borrow_mut().push(format!("{} {}", r.level(), r.args())));
    }
    fn flush(&self) {}
}

static CAPTURE: Capture = Capture;

/// Installs the capture logger. Idempotent; if another logger is already
/// installed it stays, and nothing is captured.
pub fn install() {
    if log::set_logger(&CAPTURE).is_ok() {
        log::set_max_level(log::LevelFilter::Trace);
    }
}

/// Returns and clears this thread's captured lines (`"LEVEL message"`).
pub fn take() -> Vec<String> {
    LINES.with(|l| std::mem::take(&mut *l.borrow_mut()))
}
