//! spec §6.4
#![forbid(unsafe_code)]

fn main() {
    mqproxy::logger::init();
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
