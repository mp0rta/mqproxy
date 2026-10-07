//! spec §6.4 `--setup-redirect`: the nft / ip-rule commands, table
//! `mqproxy`. Every invocation goes through `run`: a direct exec with separate
//! argv elements, no shell, and the child's `PATH` pinned to
//! `/usr/sbin:/usr/bin:/sbin:/bin`.

use mq_runtime::ListenKind;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};

/// spec §6.4: the only `PATH` `nft` / `ip` are resolved through.
pub const PINNED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Opts {
    /// `Redirect` or `Tproxy` (`--tproxy-mode`).
    pub mode: ListenKind,
    /// The bound transparent listener's port.
    pub listener_port: u16,
    pub dport: u16,
    pub uid: u32,
    pub fwmark: u32,
    pub table: u32,
}

/// spec §6.4: the one exec path (install, start-up cleanup, shutdown cleanup).
pub fn run(prog: &str, argv: &[String]) -> io::Result<ExitStatus> {
    Command::new(prog)
        .args(argv)
        .env("PATH", PINNED_PATH)
        .status()
}

fn v(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// The redirect or tproxy install commands, in order; element 0 is the program.
pub fn install_cmds(o: &Opts) -> Vec<Vec<String>> {
    let (uid, dport, mark, table) = (
        o.uid.to_string(),
        o.dport.to_string(),
        o.fwmark.to_string(),
        o.table.to_string(),
    );
    let to = format!(":{}", o.listener_port);
    if o.mode == ListenKind::Tproxy {
        vec![
            v(&["ip", "rule", "add", "fwmark", &mark, "lookup", &table]),
            v(&[
                "ip",
                "route",
                "add",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                &table,
            ]),
            v(&["nft", "add", "table", "ip", "mqproxy"]),
            v(&[
                "nft",
                "add",
                "chain",
                "ip",
                "mqproxy",
                "div",
                "{ type filter hook prerouting priority -150 ; }",
            ]),
            v(&[
                "nft", "add", "rule", "ip", "mqproxy", "div", "meta", "l4proto", "tcp", "meta",
                "skuid", &uid, "return",
            ]),
            v(&[
                "nft", "add", "rule", "ip", "mqproxy", "div", "meta", "l4proto", "tcp", "tcp",
                "dport", &dport, "tproxy", "to", &to, "meta", "mark", "set", &mark, "accept",
            ]),
        ]
    } else {
        vec![
            v(&["nft", "add", "table", "ip", "mqproxy"]),
            v(&[
                "nft",
                "add",
                "chain",
                "ip",
                "mqproxy",
                "out",
                "{ type nat hook output priority -100 ; }",
            ]),
            v(&[
                "nft", "add", "rule", "ip", "mqproxy", "out", "meta", "skuid", &uid, "return",
            ]),
            v(&[
                "nft", "add", "rule", "ip", "mqproxy", "out", "meta", "l4proto", "tcp", "tcp",
                "dport", &dport, "redirect", "to", &to,
            ]),
        ]
    }
}

/// The redirect or tproxy uninstall commands, in order.
pub fn uninstall_cmds(o: &Opts) -> Vec<Vec<String>> {
    let mut c = vec![v(&["nft", "delete", "table", "ip", "mqproxy"])];
    if o.mode == ListenKind::Tproxy {
        let (mark, table) = (o.fwmark.to_string(), o.table.to_string());
        c.push(v(&["ip", "rule", "del", "fwmark", &mark, "lookup", &table]));
        c.push(v(&[
            "ip",
            "route",
            "del",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            &table,
        ]));
    }
    c
}

/// Logs the command, runs it, logs a failure; true on exit 0.
fn cmd(argv: &[String], log_failure: bool) -> bool {
    log::info!("mq_tproxy_setup: run: {}", argv.join(" "));
    let prog = &argv[0];
    let err = match run(prog, &argv[1..]) {
        Ok(st) if st.success() => return true,
        Ok(st) => match st.code() {
            Some(c) => format!("'{prog}' exited {c}"),
            None => format!("'{prog}' killed by signal {}", st.signal().unwrap_or(0)),
        },
        Err(e) => format!("'{prog}': {e}"),
    };
    if log_failure {
        log::error!("mq_tproxy_setup: {err}");
    }
    false
}

/// spec §6.4: removes leftovers of a crashed run (failures expected, not
/// logged), then installs. `false` = a failed install, which the caller logs as a
/// warning; every command is tried and a partial install is left for
/// `uninstall`.
pub fn install(o: &Opts) -> bool {
    for c in uninstall_cmds(o) {
        cmd(&c, false);
    }
    let mut ok = true;
    for c in install_cmds(o) {
        ok &= cmd(&c, true);
    }
    let (uid, port, dport, mark, table) = (o.uid, o.listener_port, o.dport, o.fwmark, o.table);
    match (o.mode == ListenKind::Tproxy, ok) {
        (false, true) => log::info!(
            "mq_tproxy_setup: REDIRECT rules installed (uid={uid} exempted, dport={dport} -> :{port})"
        ),
        (false, false) => {
            log::error!("mq_tproxy_setup: REDIRECT install failed for dport={dport} -> :{port}")
        }
        (true, true) => log::info!(
            "mq_tproxy_setup: TPROXY rules installed (uid={uid} exempted, mark={mark}, table={table}, dport={dport} -> :{port})"
        ),
        (true, false) => log::error!(
            "mq_tproxy_setup: TPROXY install failed (mark={mark} table={table} dport={dport} -> :{port})"
        ),
    }
    ok
}

/// spec §6.6: the shutdown hook; each failure is tolerated.
pub fn uninstall(o: &Opts) {
    let tproxy = o.mode == ListenKind::Tproxy;
    let mode = if tproxy { "TPROXY" } else { "REDIRECT" };
    let what = ["nft delete table", "ip rule del", "ip route del"];
    let mut all_ok = true;
    for (c, what) in uninstall_cmds(o).iter().zip(what) {
        if !cmd(c, true) {
            all_ok = false;
            log::warn!("mq_tproxy_setup: {mode} cleanup: {what} failed (tolerated)");
        }
    }
    if tproxy {
        log::info!(
            "mq_tproxy_setup: TPROXY rules cleanup done (mark={} table={})",
            o.fwmark,
            o.table
        );
    } else if all_ok {
        log::info!("mq_tproxy_setup: REDIRECT rules removed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(mode: ListenKind) -> Opts {
        Opts {
            mode,
            listener_port: 12345,
            dport: 443,
            uid: 1000,
            fwmark: 1,
            table: 100,
        }
    }

    fn lit(cmds: &[&[&str]]) -> Vec<Vec<String>> {
        cmds.iter().map(|c| v(c)).collect()
    }

    #[test]
    fn argv_lists_match_c() {
        let r = opts(ListenKind::Redirect);
        assert_eq!(
            install_cmds(&r),
            lit(&[
                &["nft", "add", "table", "ip", "mqproxy"],
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip",
                    "mqproxy",
                    "out",
                    "{ type nat hook output priority -100 ; }"
                ],
                &[
                    "nft", "add", "rule", "ip", "mqproxy", "out", "meta", "skuid", "1000", "return"
                ],
                &[
                    "nft", "add", "rule", "ip", "mqproxy", "out", "meta", "l4proto", "tcp", "tcp",
                    "dport", "443", "redirect", "to", ":12345"
                ],
            ])
        );
        assert_eq!(
            uninstall_cmds(&r),
            lit(&[&["nft", "delete", "table", "ip", "mqproxy"]])
        );

        let t = opts(ListenKind::Tproxy);
        assert_eq!(
            install_cmds(&t),
            lit(&[
                &["ip", "rule", "add", "fwmark", "1", "lookup", "100"],
                &[
                    "ip",
                    "route",
                    "add",
                    "local",
                    "0.0.0.0/0",
                    "dev",
                    "lo",
                    "table",
                    "100"
                ],
                &["nft", "add", "table", "ip", "mqproxy"],
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip",
                    "mqproxy",
                    "div",
                    "{ type filter hook prerouting priority -150 ; }"
                ],
                &[
                    "nft", "add", "rule", "ip", "mqproxy", "div", "meta", "l4proto", "tcp", "meta",
                    "skuid", "1000", "return"
                ],
                &[
                    "nft", "add", "rule", "ip", "mqproxy", "div", "meta", "l4proto", "tcp", "tcp",
                    "dport", "443", "tproxy", "to", ":12345", "meta", "mark", "set", "1", "accept"
                ],
            ])
        );
        assert_eq!(
            uninstall_cmds(&t),
            lit(&[
                &["nft", "delete", "table", "ip", "mqproxy"],
                &["ip", "rule", "del", "fwmark", "1", "lookup", "100"],
                &[
                    "ip",
                    "route",
                    "del",
                    "local",
                    "0.0.0.0/0",
                    "dev",
                    "lo",
                    "table",
                    "100"
                ],
            ])
        );
    }

    #[test]
    fn pinned_path_and_no_shell_for_every_invocation() {
        let dir = std::env::temp_dir().join(format!("mqproxy-fake-nft-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("marker");
        let fake = dir.join("nft");
        std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The fake dir first in the test process's PATH (a polluted service env).
        // `env::set_var` is unsafe in edition 2024 and the crate forbids unsafe,
        // so this test binary re-runs itself with that PATH and calls `run` there.
        let old = std::env::var("PATH").unwrap_or_default();
        let st = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "setup_redirect::tests::run_nft_version_child",
                "--nocapture",
            ])
            .env("PATH", format!("{}:{old}", dir.display()))
            .env("MQPROXY_TEST_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "child test failed");
        assert!(!marker.exists(), "the fake nft ran: PATH was not pinned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Runs only as the child of `pinned_path_and_no_shell_for_every_invocation`,
    /// whose PATH starts with the fake `nft`.
    #[test]
    fn run_nft_version_child() {
        if std::env::var_os("MQPROXY_TEST_CHILD").is_none() {
            return;
        }
        match run("nft", &v(&["--version"])) {
            Ok(_) => {} // the system nft, found through the pinned PATH
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}"),
        }
    }
}
