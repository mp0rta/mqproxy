# Parser corpus replay

`fuzz/corpus` preserves the legacy C seeds. The maintained harnesses are the
Cargo fuzz workspaces under `crates/mq-wire/fuzz`, `crates/mq-proxy/fuzz` and
`crates/mq-http/fuzz`. The Rust workflow replays these seeds and explores each
target. For example:

```sh
cargo +nightly fuzz run --fuzz-dir crates/mq-wire/fuzz varint fuzz/corpus/varint -- -runs=0
```

C codec compatibility is frozen in `crates/mq-wire/tests/data/c-codec-vectors.txt`.
The 1,892 rows were checked against the C decoder/encoder at `cd41d699` before
removal: committed corpora, deterministic generated inputs (seed
`0x5BE0_CD19_137E_2179`), truncations, and varint boundaries. Each full row
checks fields, bytes consumed and canonical encoding. Outside C's representable
string/error-code domain, rows check acceptance only, matching the old differential
contract. Replay with `cargo test -p mq-wire --test c_golden`.
