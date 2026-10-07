// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §6.4/§7.5: what the bridge reports to the gateway. Every entry
//! point that can complete an exchange takes the sink as a parameter, so
//! `Gateway { origin, core }` calls `self.origin.pump(cx, &mut self.core)`
//! without a double borrow.

use super::{Completion, OriginFailure, RelayHead};
use mq_runtime::Cx;
use mq_transport_api::H3ReqId;

pub trait BridgeEvents {
    /// The origin's response head, relayed by the gateway; may call `h3_send_headers`.
    fn on_response(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, head: RelayHead);
    /// One body frame. `Partial(n)`: the gateway keeps the rest in its own
    /// `pending` (§6.4); the bridge marks the record `held` and polls no
    /// further frame until `Origin::resume(h3)`.
    fn on_body_frame(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, data: &[u8]) -> Accepted;
    /// The body is complete as hyper knows it; the gateway applies the §6.4 body check.
    fn on_body_end(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, done: Completion);
    fn on_failure(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, f: OriginFailure, after_head: bool);
    /// Refill the request's `UploadBuf` from `h3_recv_body` (§6.3).
    fn want_h3(&mut self, cx: &mut Cx<'_>, h3: H3ReqId);
}

/// How much of a body frame the gateway took.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Accepted {
    All,
    Partial(usize),
}
