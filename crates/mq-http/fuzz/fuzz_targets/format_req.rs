// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#![no_main]
use libfuzzer_sys::fuzz_target;
use mq_http::metrics::{ReqLine, format_req};

/// Takes `n` bytes off the front of `d`; a short input yields what is left (zero-padded by the callers).
fn take<'a>(d: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (h, t) = d.split_at(n.min(d.len()));
    *d = t;
    h
}

fn num<const N: usize>(d: &mut &[u8]) -> [u8; N] {
    let mut b = [0u8; N];
    let h = take(d, N);
    b[..h.len()].copy_from_slice(h);
    b
}

fuzz_target!(|data: &[u8]| {
    let mut d = data;
    let sid = u64::from_le_bytes(num(&mut d));
    let req_bytes = u64::from_le_bytes(num(&mut d));
    let resp_bytes = u64::from_le_bytes(num(&mut d));
    let begin_us = u64::from_le_bytes(num(&mut d));
    let header_send_us = u64::from_le_bytes(num(&mut d));
    let fin_send_us = u64::from_le_bytes(num(&mut d));
    let fin_ack_us = u64::from_le_bytes(num(&mut d));
    let status = i32::from_le_bytes(num(&mut d));
    let mp_state = i32::from_le_bytes(num(&mut d));
    let origin_connect_ms = i64::from_le_bytes(num(&mut d));
    let [reuse, proto, tls, ..] = num::<4>(&mut d);
    // Remaining bytes: five string fields, each cut at a fixed offset (up to 300 bytes) so long values hit the caps.
    let method = take(&mut d, 300);
    let authority = take(&mut d, 300);
    let path = take(&mut d, 300);
    let content_encoding = take(&mut d, 300);
    let reset = take(&mut d, 300);
    let line = ReqLine {
        sid,
        method,
        status,
        authority,
        path,
        req_bytes,
        resp_bytes,
        begin_us,
        header_send_us,
        fin_send_us,
        fin_ack_us,
        origin_protocol: ["h1", "h2", "h3", "none"][proto as usize % 4],
        origin_tls: ["ok", "fail", "na"][tls as usize % 3],
        content_encoding,
        origin_reuse: reuse,
        origin_connect_ms,
        mp_state,
        reset,
    };
    if let Some(out) = format_req(&line) {
        assert!(out.len() < mq_http::metrics::LINE_MAX);
    }
});
