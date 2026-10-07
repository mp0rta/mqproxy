//! spec §6.5: C `mq_log` (`src/util/mq_log.c:30`): `[LEVEL] msg\n` on stderr,
//! no timestamp, level fixed at INFO (`main` calls `mq_log_set_level(MQ_LOG_INFO)`).

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write;

static INSTANCE_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Set once at startup, before emitting process logs.
pub fn set_instance_id(id: String) {
    let _ = INSTANCE_ID.set(id);
}

struct Stderr;

impl Log for Stderr {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= Level::Info
    }

    fn log(&self, r: &Record) {
        if self.enabled(r.metadata()) {
            // One write per line, so lines from other threads do not interleave.
            let _ = writeln!(
                std::io::stderr().lock(),
                "{}",
                line(r.level(), r.args(), INSTANCE_ID.get().map(String::as_str))
            );
        }
    }

    fn flush(&self) {}
}

/// C's prefixes: ERROR, WARN, INFO, DEBUG (`Trace` never passes the INFO level).
fn line(level: Level, msg: &std::fmt::Arguments, instance: Option<&str>) -> String {
    let prefix = match level {
        Level::Error => "ERROR",
        Level::Warn => "WARN",
        Level::Info => "INFO",
        Level::Debug | Level::Trace => "DEBUG",
    };
    match instance {
        Some(id) => format!("[{prefix}] {msg} instance_id={id}"),
        None => format!("[{prefix}] {msg}"),
    }
}

/// Installs the logger; the max level is INFO, as C.
pub fn init() {
    if log::set_logger(&Stderr).is_ok() {
        log::set_max_level(LevelFilter::Info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_matches_c() {
        assert_eq!(
            line(Level::Info, &format_args!("message"), Some("edge-1")),
            "[INFO] message instance_id=edge-1"
        );
        assert_eq!(
            line(Level::Info, &format_args!("a {}", 1), None),
            "[INFO] a 1"
        );
        assert_eq!(line(Level::Warn, &format_args!("w"), None), "[WARN] w");
        assert_eq!(line(Level::Error, &format_args!("e"), None), "[ERROR] e");
        assert_eq!(line(Level::Debug, &format_args!("d"), None), "[DEBUG] d");
        assert!(!Stderr.enabled(&Metadata::builder().level(Level::Debug).build()));
    }
}
