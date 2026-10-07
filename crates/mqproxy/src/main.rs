// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.4
#![forbid(unsafe_code)]

fn main() {
    mqproxy::logger::init();
    // spec §3.2: the zeroed rings must stay untouched until written, so large
    // allocations must always be fresh mmaps, not recycled (memset) heap.
    if !mq_linux::pin_mmap_threshold() {
        log::warn!("mallopt(M_MMAP_THRESHOLD) failed; rings may become resident");
    }
    let args: Vec<String> = std::env::args().collect();
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    match mqproxy::cli::parse(&argv) {
        Ok(mut resolved) => {
            if let Some(id) = resolved.instance_id.clone() {
                mqproxy::logger::set_instance_id(id);
            }
            // spec §8: the test-only connect timeout knob, read once here.
            if let mqproxy::cli::Mode::Server(s) = &mut resolved.mode
                && let Some(g) = &mut s.config.gateway
            {
                let env = std::env::var("MQ_GW_ORIGIN_CONNECT_TIMEOUT_S").ok();
                g.origin_connect_timeout = mqproxy::cli::origin_connect_timeout(env.as_deref());
            }
            for w in &resolved.warnings {
                log::warn!("{w}");
            }
            std::process::exit(mqproxy::run::run(resolved));
        }
        Err(e) if e.code == 0 => print!("{}", e.message),
        Err(e) => {
            eprint!("{}", e.message);
            std::process::exit(e.code);
        }
    }
}
