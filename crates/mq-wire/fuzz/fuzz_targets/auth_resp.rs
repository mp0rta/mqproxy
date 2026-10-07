// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#![no_main]
use libfuzzer_sys::fuzz_target;
use mq_wire::frames::AuthResp;

fuzz_target!(|data: &[u8]| {
    let Ok((v, _)) = AuthResp::decode(data) else {
        return;
    };
    let mut a = [0u8; 512];
    let na = v.encode(&mut a).expect("re-encode of decoded frame");
    let (v2, n2) = AuthResp::decode(&a[..na]).expect("re-decode");
    assert_eq!(v, v2);
    assert_eq!(n2, na);
    let mut b = [0u8; 512];
    let nb = v2.encode(&mut b).unwrap();
    assert_eq!(a[..na], b[..nb]);
});
