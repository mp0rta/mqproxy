// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Spec §8.3, §4.9: a handshake plus an unblocked download;
//! `<dir>/client.qlog` holds frame events and no DATA_BLOCKED / STREAM_DATA_BLOCKED frames.
mod common;

use common::pair::{MS, Opts, Pair, new_streams, read_all, send};
use common::xfer::pattern;
use std::path::PathBuf;

#[test]
fn qlog_has_frames_and_no_blocked_frames() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fabric_qlog");
    std::fs::create_dir_all(&dir).unwrap();
    let mut p = Pair::with(Opts {
        qlog: Some(dir.clone()),
        ..Opts::default()
    });

    // A multi-hundred-KB download (the client's qlog records the frames it receives); the
    // 16 MiB windows dwarf it, so the server is never window-limited.
    let data = pattern(512 * 1024);
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, b"GET".to_vec(), true), Ok(3));
    p.exchange();
    let ss = new_streams(&p.sev)[0].0;
    let (mut off, mut got, mut fin) = (0, Vec::new(), false);
    assert!(p.pump_until(MS, 10_000, |p| {
        if off < data.len() {
            let chunk = data[off..].to_vec();
            off += send(&p.server, p.now, ss, chunk, true).unwrap_or(0);
        }
        let (b, f) = read_all(&p.client, p.now, cs).unwrap();
        got.extend(b);
        fin = f;
        fin
    }));
    assert!(got == data);
    drop(p); // the sink writes synchronously; dropping closes the engines

    let raw = std::fs::read(dir.join("client.qlog")).expect("client.qlog");
    let qlog = String::from_utf8_lossy(&raw); // CIDs are logged as raw bytes
    let count = |tok: &str| qlog.matches(tok).count();
    assert!(
        count("frames_processed") > 0,
        "EXTRA-importance events missing"
    );
    assert!(
        count("xqc_parse_stream_frame") > 0,
        "the download's STREAM frames"
    );
    assert_eq!(count("xqc_parse_data_blocked_frame"), 0);
    assert_eq!(count("xqc_parse_stream_data_blocked_frame"), 0);
}
