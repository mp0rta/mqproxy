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
        Ok(resolved) => {
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
