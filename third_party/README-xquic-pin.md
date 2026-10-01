# xquic pin

`third_party/xquic` is pinned to **`4aa5b1fe993e1f5dc7e3e24c8e9d8585752cb14b`**,
the head of the fork branch `feat/max-implicit-streams` (mp0rta/xquic), based on
`a5fbdc3` (`mqvpn-main`). `mqvpn-dev` does not contain `a5fbdc3`, so the branch
starts from `a5fbdc3` rather than from `mqvpn-dev`.

## Why a branch head, not a merged revision

The branch has not been pushed or merged yet. Until it is, the pin is a commit
that exists only in a local clone: a fresh `git submodule update` (and CI)
cannot fetch it. The fork owner must push the branch first.

## What the patch does (spec §7, implicit streams)

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

## Bumping once merged

1. Push `feat/max-implicit-streams`, open the fork PR, merge it per the fork's
   process (`mqvpn-dev`, then `mqvpn-main`).
2. `git -C third_party/xquic fetch origin && git -C third_party/xquic checkout <merged sha>`.
3. `scripts/update-xquic-bindings.sh`; `cargo test -p xquic-sys` (layout);
   commit the gitlink and `bindings.rs` if it changed.
4. Replace the SHA and branch above with the merged revision (or delete this
   file once the pin is an ordinary merged revision).
