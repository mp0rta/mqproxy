//! SOCKS5 UDP echo client and single-peer benchmark forwarder.
use clap::Parser;
use mq_proxy::udp::socks5udp::{self, Dst};
use mq_wire::frames::AddrType;
use std::{
    error::Error,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    proxy: SocketAddr,
    #[arg(long)]
    target: String,
    #[arg(long)]
    send: Option<String>,
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    count: u32,
    #[arg(long, default_value = "3000", value_parser = clap::value_parser!(u64).range(1..))]
    timeout_ms: u64,
    #[arg(long)]
    verbose: bool,
    #[arg(long, conflicts_with_all = ["send", "count"], value_parser = clap::value_parser!(u16).range(1..))]
    listen: Option<u16>,
}

fn payload(arg: Option<&str>) -> Result<Vec<u8>> {
    if let Some(path) = arg {
        match std::fs::read(path) {
            Ok(raw) => {
                let hex: Vec<_> = raw
                    .into_iter()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect();
                if hex.len() % 2 != 0 || hex.len() > 2 * 65535 {
                    return Err("invalid hex payload length".into());
                }
                return hex
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
                    .collect();
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let n: u16 = arg.unwrap_or("8").parse()?;
    if n == 0 {
        return Err("payload size must be 1-65535".into());
    }
    Ok((0..n).map(|i| i as u8).collect())
}

fn header(target: &str) -> Result<Vec<u8>> {
    let (host, port) = target.rsplit_once(':').ok_or("target must be host:port")?;
    let port: u16 = port.parse()?;
    if host.is_empty() || host.len() > 255 || port == 0 {
        return Err("invalid target".into());
    }
    let ip = host.parse::<Ipv4Addr>().ok().map(|v| v.octets());
    let dst = Dst {
        atype: if ip.is_some() {
            AddrType::Ipv4
        } else {
            AddrType::Domain
        },
        addr: ip.as_ref().map_or(host.as_bytes(), |v| v.as_slice()),
        port,
    };
    let mut out = Vec::new();
    socks5udp::build(&mut out, &dst);
    Ok(out)
}

fn associate(args: &Args) -> Result<(TcpStream, UdpSocket)> {
    let timeout = Duration::from_millis(args.timeout_ms);
    let mut tcp = TcpStream::connect_timeout(&args.proxy, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.write_all(&[5, 1, 0])?;
    let mut method = [0; 2];
    tcp.read_exact(&mut method)?;
    if method != [5, 0] {
        return Err("SOCKS5 method rejected".into());
    }
    tcp.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let mut reply = [0; 10];
    tcp.read_exact(&mut reply[..4])?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err("ASSOCIATE rejected or non-IPv4 relay".into());
    }
    tcp.read_exact(&mut reply[4..])?;
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    if port == 0 {
        return Err("ASSOCIATE returned port zero".into());
    }
    let ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let udp = UdpSocket::bind(("127.0.0.1", 0))?;
    udp.connect((ip, port))?;
    udp.set_read_timeout(Some(timeout))?;
    Ok((tcp, udp))
}

fn forward(args: &Args, tcp: TcpStream, udp: UdpSocket, header: &[u8], port: u16) -> Result<()> {
    use mio::{Events, Interest, Poll, Token};
    tcp.set_nonblocking(true)?;
    udp.set_nonblocking(true)?;
    let local = UdpSocket::bind(("127.0.0.1", port))?;
    local.set_nonblocking(true)?;
    let mut tcp = mio::net::TcpStream::from_std(tcp);
    let mut udp = mio::net::UdpSocket::from_std(udp);
    let mut local = mio::net::UdpSocket::from_std(local);
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut tcp, Token(0), Interest::READABLE)?;
    poll.registry()
        .register(&mut udp, Token(1), Interest::READABLE)?;
    poll.registry()
        .register(&mut local, Token(2), Interest::READABLE)?;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(sig, stop.clone())?;
    }
    let mut events = Events::with_capacity(8);
    let mut rx = vec![0; 65535];
    let mut tx = Vec::with_capacity(65535);
    // ponytail: one sticky peer per benchmark process; use a peer map if multi-client tests need it.
    let mut peer = None;
    let (mut wrap_fail, mut unwrap_fail, mut no_peer_drop) = (0u64, 0u64, 0u64);
    eprintln!("udpsocks: forwarding 127.0.0.1:{port} <-> SOCKS5 UDP relay");
    let result = (|| -> io::Result<()> {
        while !stop.load(Ordering::Relaxed) {
            match poll.poll(&mut events, Some(Duration::from_millis(100))) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => r?,
            }
            for event in &events {
                loop {
                    let result = match event.token() {
                        Token(0) => match tcp.read(&mut rx[..1]) {
                            Ok(0) => return Ok(()),
                            other => other,
                        },
                        Token(1) => udp.recv(&mut rx).inspect(|&n| {
                            if let Some(peer) = peer {
                                if let Some((_, off)) = socks5udp::parse(&rx[..n]) {
                                    if local.send_to(&rx[off..n], peer).is_err() {
                                        unwrap_fail += 1;
                                    }
                                } else {
                                    unwrap_fail += 1;
                                }
                            } else {
                                no_peer_drop += 1;
                            }
                        }),
                        _ => local.recv_from(&mut rx).map(|(n, from)| {
                            if peer.is_none() {
                                peer = Some(from);
                                if args.verbose {
                                    eprintln!("udpsocks: learned peer {from}");
                                }
                            }
                            tx.clear();
                            tx.extend_from_slice(header);
                            tx.extend_from_slice(&rx[..n]);
                            if tx.len() > 65507 || udp.send(&tx).is_err() {
                                wrap_fail += 1;
                            }
                            n
                        }),
                    };
                    match result {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Ok(())
    })();
    eprintln!(
        "udpsocks: forwarder stats wrap_fail={wrap_fail} unwrap_fail={unwrap_fail} no_peer_drop={no_peer_drop}"
    );
    Ok(result?)
}

fn run(args: Args) -> Result<()> {
    let mut packet = header(&args.target)?;
    let data = payload(args.send.as_deref())?;
    let (tcp, udp) = associate(&args)?;
    if let Some(port) = args.listen {
        return forward(&args, tcp, udp, &packet, port);
    }
    packet.extend_from_slice(&data);
    if packet.len() > 65507 {
        return Err("datagram too large".into());
    }
    let mut rx = vec![0; 65535];
    let mut failed = 0;
    for i in 0..args.count {
        let result = (|| -> Result<()> {
            udp.send(&packet)?;
            let n = udp.recv(&mut rx)?;
            let (_, off) = socks5udp::parse(&rx[..n]).ok_or("invalid SOCKS5 UDP header")?;
            let body = &rx[off..n];
            let hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
            println!("{hex}");
            if body != data {
                return Err("MISMATCH".into());
            }
            if args.verbose {
                eprintln!("udpsocks: OK {} bytes (iter {})", body.len(), i + 1);
            } else {
                eprintln!("OK {} bytes", body.len());
            }
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("udpsocks: {e} (iter {})", i + 1);
            failed += 1;
        }
    }
    if failed > 0 {
        return Err(format!("{failed}/{} responses failed", args.count).into());
    }
    Ok(())
}

fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("udpsocks: {e}");
        std::process::exit(1);
    }
}

#[test]
fn headers_and_arguments() {
    assert_eq!(
        header("127.0.0.1:53").unwrap(),
        [0, 0, 0, 1, 127, 0, 0, 1, 0, 53]
    );
    let h = header("example.org:53").unwrap();
    assert_eq!(socks5udp::parse(&h).unwrap().0.addr, b"example.org");
    for target in [":53", "example.org:0", "example.org:65536"] {
        assert!(header(target).is_err());
    }
    assert_eq!(payload(Some("3")).unwrap(), [0, 1, 2]);
    assert!(payload(Some("0")).is_err());
    assert!(
        Args::try_parse_from([
            "udpsocks",
            "--proxy",
            "127.0.0.1:1080",
            "--target",
            "a:53",
            "--listen",
            "1234"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from([
            "udpsocks",
            "--proxy",
            "127.0.0.1:1080",
            "--target",
            "a:53",
            "--listen",
            "1234",
            "--count",
            "1"
        ])
        .is_err()
    );
}
