//! `OriginLoop`: the origin bridge (`OriginHost`) on the production loop core
//! over real sockets, on the **test thread** — a `DriverThread` can neither be
//! commanded nor inspected, and `StartReq` holds `!Send` state (spec §10.3).

use crate::driver_harness::{ResolverControl, chan_resolver};
use mq_proxy::server::origin::OriginCfg;
use mq_proxy::server::origin::host::{OriginHost, StartSpec};
use mq_runtime::driver::{Io, LoopConfig, LoopCore, MioIo};
use mq_runtime::testing::ScriptedTransport;
use mq_runtime::{Cx, Shard};
use mq_transport_api::H3ReqId;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct OriginLoop {
    pub core: LoopCore<MioIo, ScriptedTransport, OriginHost>,
    /// Kept: dropping it fails every domain resolve at once.
    resolver: ResolverControl,
}

impl OriginLoop {
    /// Built as `DriverThread::spawn_on` builds its driver; started.
    pub fn new(cfg: OriginCfg, tls: Arc<rustls::ClientConfig>) -> OriginLoop {
        let (r, resolver) = chan_resolver();
        let mut io = MioIo::new(r, false).expect("MioIo");
        let (udp, local) = io
            .bind_udp(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind_udp");
        let (t, _) = ScriptedTransport::new();
        let shard = Shard::new(t, OriginHost::new(cfg, tls), local, 7);
        let primary = shard.primary_udp();
        let mut core = LoopCore::new(io, shard, LoopConfig::default());
        core.attach_primary_udp(udp, primary);
        core.start();
        OriginLoop { core, resolver }
    }

    /// `OriginHost::start` (start + pump).
    pub fn start(&mut self, spec: StartSpec) -> H3ReqId {
        self.with_host(|h, cx| h.start(cx, spec))
    }

    /// `OriginHost::cancel` (`H3Closed` + pump).
    pub fn cancel(&mut self, h3: H3ReqId) {
        self.with_host(|h, cx| h.cancel(cx, h3))
    }

    /// Runs `f` on the host between iterations; the next iteration does not
    /// sleep on the wait computed before `f` changed the shard.
    pub fn with_host<R>(&mut self, f: impl FnOnce(&mut OriginHost, &mut Cx<'_>) -> R) -> R {
        let now = self.core.io().now();
        let r = self.core.shard_mut().with_app(now, f);
        self.core.reset_wait();
        r
    }

    /// Iterates until `pred` holds (`true`) or `limit` passed (`false`). A
    /// timer at `limit` keeps the loop from sleeping past it; the host
    /// ignores it (the bridge declines foreign timers).
    pub fn run_until(&mut self, limit: Duration, pred: impl Fn(&OriginHost) -> bool) -> bool {
        let end = Instant::now() + limit;
        let timer = self.with_host(|_, cx| cx.set_timer(limit));
        let held = loop {
            if pred(self.host()) {
                break true;
            }
            if Instant::now() >= end {
                break false;
            }
            self.core.iteration();
        };
        // Generational ids: cancelling a timer that already fired is a no-op.
        self.with_host(|_, cx| cx.cancel_timer(timer));
        held
    }

    pub fn host(&self) -> &OriginHost {
        self.core.shard().app()
    }

    pub fn resolver(&self) -> &ResolverControl {
        &self.resolver
    }
}
