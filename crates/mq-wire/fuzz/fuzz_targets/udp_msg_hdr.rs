#![no_main]
use libfuzzer_sys::fuzz_target;
use mq_wire::udp_msg::{UDP_MSG_HDR, UdpMsgHdr};

fuzz_target!(|data: &[u8]| {
    let Some(h) = UdpMsgHdr::decode(data) else {
        return;
    };
    let mut a = [0u8; UDP_MSG_HDR];
    h.encode(&mut a);
    assert_eq!(a[..], data[..UDP_MSG_HDR]);
    assert_eq!(UdpMsgHdr::decode(&a), Some(h));
});
