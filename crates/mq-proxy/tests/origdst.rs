// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.1: transparent capture target.
//! `unsupported_family` is covered by mq-linux's `sockaddr_conversion_rejects_unix_family`;
//! `short_buffer` has no equivalent (owned `SocketAddr`, no caller buffer).

use mq_proxy::ingress::target_from_original_dst;
use mq_runtime::{AcceptMeta, Host, Target};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn meta(original_dst: Option<SocketAddr>) -> AcceptMeta {
    AcceptMeta {
        peer: "10.0.0.2:5555".parse().unwrap(),
        local: "10.0.0.1:1080".parse().unwrap(),
        original_dst,
    }
}

#[test]
fn ipv4() {
    assert_eq!(
        target_from_original_dst(&meta(Some("93.184.216.34:443".parse().unwrap()))),
        Some(Target {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            port: 443
        })
    );
}

#[test]
fn ipv6() {
    // IPv4-only in SP1.
    assert_eq!(
        target_from_original_dst(&meta(Some("[2001:db8::1]:8080".parse().unwrap()))),
        None
    );
}

#[test]
fn no_original_dst() {
    assert_eq!(target_from_original_dst(&meta(None)), None);
}
