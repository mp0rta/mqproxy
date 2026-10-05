# xquic pin

`third_party/xquic` is pinned to **`f88832d02fd8677b4708d5f4f36f580251fb4bc9`**,
the head of the fork branch `feat/h3wire-raw-streams` (mp0rta/xquic), based on
`4aa5b1fe993e1f5dc7e3e24c8e9d8585752cb14b`, the head of
`feat/max-implicit-streams` (which is based on `a5fbdc3`, `mqvpn-main`).
`mqvpn-dev` does not contain `a5fbdc3`, so the branches start from `a5fbdc3`
rather than from `mqvpn-dev`. The `max_implicit_streams` commit is still in the
series; the four h3wire commits sit on top of it.

## Why a branch head, not a merged revision

**Decision (2026-10-01):** the branch is kept as an mqproxy-only branch for
now. mqvpn shares this fork and has not validated the patch; merging into
`mqvpn-dev` / `mqvpn-main` is deferred until mqvpn has run with it. Until the
merge, mqproxy pins the branch head directly.

The branch must still be pushed to the fork remote: until it is, the pin is a
commit that exists only in a local clone, and a fresh `git submodule update`
(and CI) cannot fetch it. The fork owner must push the branch first:

```
git -C third_party/xquic push origin feat/h3wire-raw-streams
```

Effect on mqvpn: none until mqvpn bumps its own pin. The cap only triggers for
a peer that leaves more than 16384 stream ids unopened at once; sequential
stream use never accumulates gap entries (fork CUnit: 16400 out-of-order
creations, no error, count back to 0). If mqvpn wants the old behaviour even
after bumping, the default can be changed to "0 = disabled" with mqproxy
setting 16384 explicitly (mq-transport already does).

## What the patch does

### Raw streams for h3wire (adoption spec §2)

All opt-in: with no new callback registered and the setter not called, xquic
behaves as at `4aa5b1f`.

1. `xqc_stream_reset(stream, code)` sends RESET_STREAM only, with a 62-bit code.
   It drops queued stream frames and resets at the current send offset; a no-op
   once RESET_SENT or when the conn is closing.
2. `xqc_stream_stop_sending(stream, code)` sends STOP_SENDING only, while the
   receive side is in Recv or Size Known. What arrives afterwards is still read.
3. `stream_peer_abort_notify(stream, kind, code, user_data)`, a new optional
   member of `xqc_stream_callbacks_t` (`kind` is RESET_STREAM or STOP_SENDING).
   Both frame handlers call it with the full code, including on the passive
   stream-creation path.
4. `xqc_conn_set_no_reset_echo(conn, on)` (default off) stops a received
   RESET_STREAM from being echoed; the application resets its own send side via
   item 1. The automatic RESET_STREAM in reply to STOP_SENDING is unchanged
   (RFC 9000 section 3.5).
5. `xqc_stream_get_close_stats(stream, out)` fills `xqc_stream_close_stats_t`
   `{fin_send_time, fin_ack_time, mp_state, err, close_msg}` the way
   `xqc_h3_request_get_stats` does, with connection-error precedence for `err`.
   Callable from `stream_close_notify`.

### Implicit streams (spec §7)

- `xqc_conn_settings_t.max_implicit_streams` (0 = default 16384): a peer stream
  id inserts a `passive_streams_hash` entry for every skipped id; the
  connection now counts the entries held for ids no stream was created for and
  closes with `TRA_STREAM_LIMIT_ERROR` before an insertion would exceed the cap.
  The count drops when a skipped id is later opened, so dense ids never hit it.
- On refusal `xqc_passive_create_stream` returns NULL before
  `max_stream_id_*_remote` advances or a stream is created.
- `xqc_server_set_conn_settings` copies the field.
- `-DXQC_ENABLE_TEST_HOOKS=ON` (default OFF) adds `xqc_stream_create_with_id()`
  and `xqc_conn_implicit_stream_count()`; `xquic-sys`'s `test-hooks` feature
  turns it on.

## Bumping once merged (after mqvpn validation)

1. Open the fork PR and merge it per the fork's process: the branch is based on
   `mqvpn-main` (`a5fbdc3`), so land it with a 3-way merge into `mqvpn-dev`,
   not a rebase (a rebase onto `mqvpn-dev` conflicts across a5fbdc3's commits),
   then `mqvpn-main`.
2. `git -C third_party/xquic fetch origin && git -C third_party/xquic checkout <merged sha>`.
3. `scripts/update-xquic-bindings.sh`; `cargo test -p xquic-sys` (layout);
   commit the gitlink and `bindings.rs` if it changed.
4. Replace the SHA and branch above with the merged revision (or delete this
   file once the pin is an ordinary merged revision).
