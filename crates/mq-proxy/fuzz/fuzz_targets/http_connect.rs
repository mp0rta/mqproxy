// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#![no_main]
//! spec §6.1: the HTTP CONNECT parser driven as the app would, whole and in data-sized chunks.
use libfuzzer_sys::fuzz_target;
use mq_proxy::ingress::{HttpConnectParser, Progress};

fn drive(data: &[u8], chunk: impl Fn(usize) -> usize) {
    let mut p = HttpConnectParser;
    let (mut buf, mut pos) = (Vec::new(), 0);
    loop {
        let n = chunk(pos).min(data.len() - pos);
        buf.extend_from_slice(&data[pos..pos + n]);
        pos += n;
        match p.feed(&buf) {
            Progress::Need if pos == data.len() => return,
            Progress::Need => {}
            Progress::Done { consumed, .. } => return assert!(consumed <= buf.len()),
            Progress::Reply {
                consumed,
                bytes,
                close,
            } => {
                return assert!(consumed <= buf.len() && !bytes.is_empty() && close);
            }
            Progress::Associate { .. } => unreachable!("HTTP CONNECT has no ASSOCIATE"),
            Progress::Close => return,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    drive(data, |_| data.len());
    drive(data, |pos| {
        1 + data.get(pos).map_or(0, |&b| b as usize % 64)
    });
});
