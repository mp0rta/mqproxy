// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.1: transparent capture takes its target from `AcceptMeta.original_dst`.

use mq_runtime::{AcceptMeta, Host, Target};
use std::net::{IpAddr, SocketAddr};

/// spec §6.1: IPv4 only.
pub fn target_from_original_dst(meta: &AcceptMeta) -> Option<Target> {
    match meta.original_dst? {
        SocketAddr::V4(a) => Some(Target {
            host: Host::Ip(IpAddr::V4(*a.ip())),
            port: a.port(),
        }),
        SocketAddr::V6(_) => None,
    }
}
