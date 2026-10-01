//! spec §5.4: a toy `App` builds against the trait, and `Cx` records onto `ShardState`.

use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, Host, IoRequest, ListenerTag, ShardState, SocketOpId,
    StreamPreread, Target, TcpEnd, TcpId, TimerId, UdpSocketId,
};
use mq_transport_api::{
    ConnConfig, ConnId, ConnStats, ConnectError, Error, Event, PathError, PathId, SlotId,
    StreamError, StreamId, StreamInfo, Time, Transmit, TransportOps, TxKey,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Minimal transport: everything is a no-op / failure; `add_path` gives path 7.
struct Null;
impl TransportOps for Null {
    fn recv_datagram(&mut self, _: Time, _: SocketAddr, _: SocketAddr, _: &[u8]) {}
    fn drive(&mut self, _: Time) {}
    fn pending_transmit(&self, _: &mut Vec<TxKey>) {}
    fn peek_transmit(&mut self, _: TxKey) -> Option<Transmit<'_>> {
        None
    }
    fn transmit_done(&mut self, _: TxKey, _: usize) {}
    fn resume_pending(&self) -> bool {
        false
    }
    fn poll_event(&mut self) -> Option<Event> {
        None
    }
    fn next_timeout(&self) -> Option<Time> {
        None
    }
    fn connect(&mut self, _: Time, _: &ConnConfig) -> Result<ConnId, ConnectError> {
        Err(ConnectError::Other(-1))
    }
    fn open_stream(&mut self, _: Time, _: ConnId) -> Result<StreamId, Error> {
        Err(Error::Role)
    }
    fn stream_send(
        &mut self,
        _: Time,
        _: StreamId,
        d: &[u8],
        _: bool,
    ) -> Result<usize, StreamError> {
        Ok(d.len())
    }
    fn stream_recv(
        &mut self,
        _: Time,
        _: StreamId,
        _: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        Err(StreamError::Blocked)
    }
    fn stream_reset(&mut self, _: Time, _: StreamId) {}
    fn add_path(&mut self, _: Time, _: ConnId, _: bool) -> Result<PathId, PathError> {
        Ok(PathId(7))
    }
    fn close_conn(&mut self, _: Time, _: ConnId) {}
    fn conn_stats(&self, _: ConnId) -> Result<ConnStats, Error> {
        Err(Error::Stale)
    }
    fn stream_info(&self, _: StreamId) -> Result<StreamInfo, Error> {
        Err(Error::Stale)
    }
}

/// Toy app implementing every §5.4 callback.
#[derive(Default)]
struct Toy {
    calls: Vec<&'static str>,
}
impl App for Toy {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        self.calls.push("start");
        cx.request_exit(3);
    }
    fn on_transport_event(&mut self, _: &mut Cx<'_>, _: Event) {}
    fn on_accepted(&mut self, _: &mut Cx<'_>, _: ListenerTag, _: TcpId, _: AcceptMeta) {}
    fn on_tcp_data(&mut self, _: &mut Cx<'_>, _: TcpId) {}
    fn on_tcp_end(&mut self, _: &mut Cx<'_>, _: TcpId, _: TcpEnd) {}
    fn on_dial_result(&mut self, _: &mut Cx<'_>, _: DialOpId, _: Result<TcpId, DialError>) {}
    fn on_udp_socket(
        &mut self,
        _: &mut Cx<'_>,
        _: SocketOpId,
        _: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
    }
    fn on_timer(&mut self, _: &mut Cx<'_>, _: TimerId) {}
    fn on_shutdown(&mut self, _: &mut Cx<'_>) {}
}

fn primary() -> SocketAddr {
    "127.0.0.1:4433".parse().unwrap()
}

#[test]
fn toy_app_runs_through_dyn_transport_and_request_exit_records() {
    let mut t = Null;
    let mut st = ShardState::new(primary(), 1);
    let mut app = Toy::default();
    let mut cx = Cx::new(&mut t, Time(5), &mut st);
    assert_eq!(cx.now(), Time(5));
    assert_eq!(cx.primary_local(), primary());
    app.on_start(&mut cx);
    assert_eq!(app.calls, ["start"]);
    assert_eq!(st.exit_status(), Some(3));
}

#[test]
fn timers_are_recorded_and_cancelled() {
    let mut t = Null;
    let mut st = ShardState::new(primary(), 1);
    let mut cx = Cx::new(&mut t, Time(1_000), &mut st);
    let a = cx.set_timer(Duration::from_millis(5));
    let b = cx.set_timer(Duration::from_millis(1));
    assert_ne!(a, b);
    cx.cancel_timer(b);
    assert_eq!(st.timer_deadline(a), Some(Time(6_000)));
    assert_eq!(st.timer_deadline(b), None);
    assert_eq!(st.next_timer(), Some(Time(6_000)));
}

#[test]
fn dial_and_socket_ops_become_io_requests_in_order() {
    let mut t = Null;
    let mut st = ShardState::new(primary(), 1);
    let mut cx = Cx::new(&mut t, Time(0), &mut st);
    let target = Target {
        host: Host::Domain("example.com".into()),
        port: 443,
    };
    let d = cx.dial(target.clone(), Duration::from_secs(15));
    cx.cancel_dial(d);
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let o = cx.open_udp_socket(ip);
    cx.cancel_udp_socket(o);
    assert_eq!(
        st.poll_io_request(),
        Some(IoRequest::Dial {
            op: d,
            target,
            deadline: Duration::from_secs(15)
        })
    );
    assert_eq!(st.poll_io_request(), Some(IoRequest::CancelDial { op: d }));
    assert_eq!(
        st.poll_io_request(),
        Some(IoRequest::OpenUdpSocket {
            op: o,
            local_ip: ip
        })
    );
    assert_eq!(
        st.poll_io_request(),
        Some(IoRequest::CancelUdpSocket { op: o })
    );
    assert_eq!(st.poll_io_request(), None);
}

#[test]
fn accepting_and_rng_are_on_the_state() {
    let mut t = Null;
    let mut a = ShardState::new(primary(), 42);
    let mut b = ShardState::new(primary(), 42);
    assert!(a.accepting());
    let mut cx = Cx::new(&mut t, Time(0), &mut a);
    cx.set_accepting(false);
    let x = cx.rng().next_u64();
    assert!(!a.accepting());
    assert_eq!(x, b.rng().next_u64(), "same seed, same sequence");
}

#[test]
fn add_path_records_socket_mapping() {
    let mut t = Null;
    let mut st = ShardState::new(primary(), 1);
    let conn = ConnId::from_slot(SlotId::new(0, 1)).unwrap();
    let sock = st.primary_udp();
    let mut cx = Cx::new(&mut t, Time(0), &mut st);
    assert_eq!(cx.add_path(conn, sock, false), Ok(PathId(7)));
    assert_eq!(st.path_socket(conn, PathId(7)), Some(sock));
}

#[test]
fn tcp_write_bounded_by_send_buffer_and_preread_checked() {
    let mut t = Null;
    let mut st = ShardState::new(primary(), 1);
    let tcp = st.insert_tcp();
    let s = StreamId::from_slot(SlotId::new(0, 1)).unwrap();
    let mut cx = Cx::new(&mut t, Time(0), &mut st);
    assert!(cx.tcp_write(tcp, &[0; 60 * 1024]).is_ok());
    assert!(
        cx.tcp_write(tcp, &[0; 8 * 1024]).is_err(),
        "64 KiB send buffer"
    );
    let big = StreamPreread {
        bytes: &[0; 8 * 1024],
        fin: false,
    };
    assert!(
        cx.start_relay(tcp, s, big).is_err(),
        "does not fit behind reply"
    );
    let ok = StreamPreread {
        bytes: b"hi",
        fin: true,
    };
    assert!(cx.start_relay(tcp, s, ok).is_ok());
}
