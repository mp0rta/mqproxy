//! UDP echo peer for e2e_udp.sh.
use clap::Parser;
use std::{
    io,
    net::UdpSocket,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Parser)]
struct Args {
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    #[arg(long, default_value = "65535", value_parser = clap::value_parser!(u16).range(1..))]
    max_size: u16,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let socket = UdpSocket::bind(("127.0.0.1", args.port))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(sig, stop.clone())?;
    }
    println!("udp_echo: bound {}", socket.local_addr()?);
    let mut buf = vec![0; usize::from(args.max_size)];
    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if let Err(e) = socket.send_to(&buf[..n], peer) {
                    eprintln!("udp_echo: {e}");
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
