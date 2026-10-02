#![no_main]
//! spec §6.1: the SOCKS5 parser driven as the app would, whole and in data-sized chunks.
use libfuzzer_sys::fuzz_target;
use mq_proxy::ingress::{Progress, Socks5Parser};

fn drive(data: &[u8], chunk: impl Fn(usize) -> usize) {
    let mut p = Socks5Parser::default();
    let (mut buf, mut pos, mut greetings) = (Vec::new(), 0, 0);
    loop {
        let n = chunk(pos).min(data.len() - pos);
        buf.extend_from_slice(&data[pos..pos + n]);
        pos += n;
        match p.feed(&buf) {
            Progress::Need if pos == data.len() => return,
            Progress::Need => {}
            Progress::Done { consumed, .. } | Progress::Associate { consumed } => {
                return assert!(consumed <= buf.len());
            }
            Progress::Reply {
                consumed,
                bytes,
                close,
            } => {
                assert!(consumed <= buf.len() && !bytes.is_empty());
                if close {
                    return;
                }
                greetings += 1;
                assert!(
                    greetings == 1 && consumed > 0,
                    "one method reply, then progress"
                );
                buf.drain(..consumed);
            }
            Progress::Close => return,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    drive(data, |_| data.len());
    drive(data, |pos| {
        1 + data.get(pos).map_or(0, |&b| b as usize % 16)
    });
});
