# mq-linux

The single home for Linux syscalls that need `unsafe` or raw fds (spec §2.2).

## GSO/GRO: hand-written `libc`, not `quinn-udp` (Task 5.1)

I evaluated `quinn-udp` 0.5.16 (`UdpSocketState` over a `std::net::UdpSocket`)
in a throwaway spike on Linux 7.0 loopback. Functionally it works: a GSO send
of 60 × 1000 bytes arrives as one GRO read (`len=60000 stride=1000
dst_ip=127.0.0.1`). It fails the spec §5.3 error policy, though. The driver
has to see `EIO`, `EINVAL` and `EMSGSIZE`, and it alone decides when to turn
GSO off.

- `UdpSocketState::send` (`src/unix.rs:207-220`) maps `EMSGSIZE` to `Ok(())`
  and logs every other error except `WouldBlock`, then returns `Ok(())`.
- `try_send` returns errors, but the shared inner `send` (`src/unix.rs:345-378`)
  still acts on its own:
  - On `EIO` or `EINVAL` it stores `max_gso_segments = 1`, so the library turns
    GSO off by itself.
  - On the first `EINVAL` it sets `sendmsg_einval`, rebuilds the cmsgs without
    `IP_TOS` and retries silently, so the caller never sees that error.
- It also has no 64-segment / 65507-byte guard of its own. On this kernel a
  65 × 100 GSO send succeeds, because `UDP_MAX_SEGMENTS` is now larger than 64.

Decision: write the path by hand in `src/udp.rs`. It uses one `sendmsg` with a
`UDP_SEGMENT` cmsg and one `recvmmsg` with the `UDP_GRO` and `IP_PKTINFO` cmsgs.
Every OS error goes to the caller unchanged, and the limits are checked in
userspace. `quinn-udp` is not a dependency.
