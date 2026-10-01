# mq-runtime

The shard runtime (spec §5): `Shard`, the `App` interface, `LoopCore`, and the
production driver (`Driver` over `MioIo`).

## Verification: `mio::Poll` under tokio (spec §11)

Spec §11 lists "`mio::Poll` nested under tokio's reactor delivers edge
notifications as expected" as an SP0 verification item, with the fallback "run
the `mio::Poll` loop on a plain thread and hand off-path completions to it
through an eventfd". **Result: verified; the fallback is not needed.**

### Design under test

- The loop core (`LoopCore`) runs outside tokio. Tokio is only a
  `current_thread` runtime owned by `MioIo` (`src/driver/mio_io.rs`).
- Sockets are registered edge-triggered with a `mio::Poll`. The `Poll`'s epoll
  fd is wrapped in an `AsyncFd` on the tokio reactor.
- `MioIo::wait` (blocking case, `wait_blocking`) is one `block_on(select!)` per
  call over two arms: `AsyncFd::readable()` on the `Poll` fd and the completion
  channel (resolver answers from the blocking pool, signals, shutdown).
- Clear, then drain. The readiness is cleared (`clear_ready`) before the `Poll`
  is drained, so an edge that arrives between the two re-arms the `AsyncFd`
  and is not lost.
- The drain is bounded. At most `DRAIN_BOUND` = 8 non-blocking `Poll::poll`
  passes per wait. If the bound is hit, `pending` is set and the next
  iteration yields instead of blocking, so other work is not starved.
- `Stats` exposes `iterations` and `max_consecutive_empty_drains` (wakeups
  that produced no event) for the spin check.

### Evidence

Command (HEAD `d5495b6` plus the Task 7.3 working tree, 32-core host, load
average about 8-10 from concurrent builds and a benchmark):

```
cargo test -p mq-integration --test driver_loopback -- --exact \
  driver_echo_loopback driver_stress_many_short_transfers_with_idle_gaps --nocapture
```

Output:

```
spin check: transfer iterations=129 idle(300ms) iterations=0 max_consecutive_empty_drains=0
test driver_echo_loopback ... ok
test driver_stress_many_short_transfers_with_idle_gaps ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.50s
```

- **`driver_echo_loopback` spin check** (scripted polling off, no periodic
  timer). The test echoes 128 × 8 KiB, then idles 300 ms.
  - The idle driver iterated **0** times in 300 ms. The limit is ≤ 3; a
    spinning loop would add thousands.
  - `max_consecutive_empty_drains` was **0** here and ≤ 1 in the Task 7.2
    runs. The limit is ≤ 2.
  - So the `AsyncFd` wakes only on real readiness, and every wakeup finds the
    edge.
- **`driver_stress_many_short_transfers_with_idle_gaps`**: 300 short TCP
  transfers with idle gaps. Every one completes, which means no edge was lost
  across a block/wake cycle. It passed in the run above, ×28 during Task 7.2,
  and in every `driver_*` suite run since.
- **`loop_engine_boot`** (Task 7.3) adds the real xquic transport under the
  same driver: two drivers on loopback complete a QUIC handshake and stop with
  exit status 0. It passed 20/20 consecutive runs.

### Conclusion

Edge notifications from the nested `mio::Poll` arrive as expected. Neither a
dedicated poll thread nor an eventfd hand-off is needed.

### Fallback, if this ever regresses

If either test fails because of the `AsyncFd` protocol itself, switch
`MioIo::wait` to the spec §11 fallback. The fallback is to run `mio::Poll::poll`
blocking on a plain thread (the driver thread), with no `AsyncFd`. Tokio keeps
only the resolver's blocking pool. Off-path completions (resolver answers,
signals, shutdown) are handed to the loop through an `eventfd` registered with
the same `Poll`, which the loop drains with the channel. Example symptoms: idle
iterations growing without bound, `max_consecutive_empty_drains` > 2, or a
stalled transfer in the stress test.
