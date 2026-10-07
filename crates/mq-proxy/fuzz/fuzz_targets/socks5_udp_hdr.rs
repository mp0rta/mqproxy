// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#![no_main]
//! spec §5: any accepted header rebuilds byte for byte and parses back to itself.
use libfuzzer_sys::fuzz_target;
use mq_proxy::udp::socks5udp::{build, parse, target_of};

fuzz_target!(|data: &[u8]| {
    let Some((dst, off)) = parse(data) else {
        return;
    };
    assert!(off <= data.len());
    let mut out = Vec::new();
    assert_eq!(build(&mut out, &dst), off);
    assert_eq!(out[..], data[..off]);
    assert_eq!(parse(&out), Some((dst, off)));
    let _ = target_of(&dst);
});
