//! spec §6.5: C `mq_log` (`src/util/mq_log.c:30`): `[LEVEL] msg\n` on stderr,
//! no timestamp, level fixed at INFO (`main` calls `mq_log_set_level(MQ_LOG_INFO)`).

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write;

struct Stderr;

impl Log for Stderr {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= Level::Info
    }

    fn log(&self, r: &Record) {
        if self.enabled(r.metadata()) {
            // One write per line, so lines from other threads do not interleave.
            let _ = writeln!(std::io::stderr().lock(), "{}", line(r.level(), r.args()));
        }
    }

    fn flush(&self) {}
}

/// C's prefixes: ERROR, WARN, INFO, DEBUG (`Trace` never passes the INFO level).
fn line(level: Level, msg: &std::fmt::Arguments) -> String {
    let prefix = match level {
        Level::Error => "ERROR",
        Level::Warn => "WARN",
        Level::Info => "INFO",
        Level::Debug | Level::Trace => "DEBUG",
    };
    format!("[{prefix}] {msg}")
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
        assert_eq!(line(Level::Info, &format_args!("a {}", 1)), "[INFO] a 1");
        assert_eq!(line(Level::Warn, &format_args!("w")), "[WARN] w");
        assert_eq!(line(Level::Error, &format_args!("e")), "[ERROR] e");
        assert_eq!(line(Level::Debug, &format_args!("d")), "[DEBUG] d");
        assert!(!Stderr.enabled(&Metadata::builder().level(Level::Debug).build()));
    }
}
