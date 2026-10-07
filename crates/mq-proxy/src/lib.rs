// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6
#![forbid(unsafe_code)]

pub(crate) mod app_stream;
pub mod client;
pub mod config;
pub mod ingress;
pub mod metrics;
pub mod server;
pub mod tls_pipe;
pub mod udp;
