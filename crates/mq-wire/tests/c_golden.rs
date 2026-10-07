//! Frozen at SP5 from C/Rust differential comparisons on cd41d699.
//! Every full row passed field, consumed-length and re-encode parity against C.
//! Outside C's representable domain only acceptance is frozen (as in the old test).
use mq_wire::{
    frames::*,
    udp_msg::{UDP_MSG_HDR, UdpMsgHdr},
    varint,
};

#[test]
fn c_codec_vectors() {
    for (i, row) in include_str!("data/c-codec-vectors.txt").lines().enumerate() {
        let mut fields = row.splitn(3, '\t');
        let kind = fields.next().unwrap();
        let hex = fields.next().unwrap();
        let want = fields.next().unwrap();
        let input: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        if want == "accept" {
            let accepted = match kind {
                "auth_req" => AuthReq::decode(&input).is_ok(),
                "auth_resp" => AuthResp::decode(&input).is_ok(),
                "tcp_resp" => ConnectTcpResp::decode(&input).is_ok(),
                _ => panic!("unexpected limited-domain kind {kind}"),
            };
            assert!(accepted, "vector {} {kind}", i + 1);
        } else {
            assert_eq!(snapshot(kind, &input), want, "vector {} {kind}", i + 1);
        }
    }
}

fn snapshot(kind: &str, input: &[u8]) -> String {
    macro_rules! frame {
        ($ty:ty) => {
            match <$ty>::decode(input) {
                Ok((f, n)) => {
                    let mut out = [0; MAX_FRAME];
                    let encoded = f.encode(&mut out).unwrap();
                    format!("{f:?};{n};{:02x?}", &out[..encoded])
                }
                Err(_) => "reject".to_string(),
            }
        };
    }
    match kind {
        "auth_req" => frame!(AuthReq),
        "auth_resp" => frame!(AuthResp),
        "tcp_req" => frame!(ConnectTcpReq),
        "tcp_resp" => frame!(ConnectTcpResp),
        "udp_open" => frame!(UdpSessionOpen),
        "udp_resp" => frame!(UdpSessionResp),
        "udp_hdr" => match UdpMsgHdr::decode(input) {
            Some(h) => {
                let mut b = [0; UDP_MSG_HDR];
                h.encode(&mut b);
                format!("{h:?};{b:02x?}")
            }
            None => "reject".to_string(),
        },
        "varint" => format!("{:?}", varint::decode(input).ok()),
        _ => panic!("unknown vector kind {kind}"),
    }
}
