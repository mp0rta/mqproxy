//! spec §6.4
#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    match mqproxy::cli::parse(&argv) {
        // Task 9.3 replaces this with run_client / run_server.
        Ok(resolved) => println!("{resolved:?}"),
        Err(e) if e.code == 0 => print!("{}", e.message),
        Err(e) => {
            eprint!("{}", e.message);
            std::process::exit(e.code);
        }
    }
}
