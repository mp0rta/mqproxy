// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#![no_main]
use libfuzzer_sys::fuzz_target;
use mq_wire::varint;

fuzz_target!(|data: &[u8]| {
    let Ok((v, _)) = varint::decode(data) else {
        return;
    };
    let mut b = [0u8; 8];
    let n = varint::encode(&mut b, v).expect("re-encode");
    assert_eq!(n, varint::len(v));
    assert_eq!(varint::decode(&b[..n]), Ok((v, n)));
});
