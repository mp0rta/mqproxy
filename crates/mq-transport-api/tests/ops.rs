use mq_transport_api::{
    CloseReason, ConnId, ErrType, Event, PathId, SlotId, StreamInfo, StreamKind, TransportOps,
    TxKey,
};

fn assert_dyn(_: &mut dyn TransportOps) {}

#[test]
fn transport_ops_is_object_safe() {
    // Compiles only if TransportOps is dyn-compatible.
    let _f: fn(&mut dyn TransportOps) = assert_dyn;

    // Shapes downstream relies on.
    let k: TxKey = (None, PathId(0));
    assert!(k.0.is_none());
    let c = ConnId::from_slot(SlotId::new(1, 1)).unwrap();
    let info = StreamInfo {
        conn: c,
        quic_id: 0,
        kind: StreamKind::Bidi,
    };
    assert_eq!(info, info.clone());
    let e = Event::ConnClosed(
        c,
        CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        },
    );
    assert_eq!(e.clone(), e);
}
