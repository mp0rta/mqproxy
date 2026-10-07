# オブザーバビリティ

どちらの側にも `--qlog <dir>` を渡すと xquic qlog を出力します。パス単位のバイト数は、ストリーム内マルチパスが実際にフローを複数パスへ分割していることを確認できます — アグリゲーションが機能している鍵となる指標です。

## メトリクス

- `--metrics-interval <sec>` は、パス単位の統計を `mq.conn` / `mq.path` の logfmt 行として定期的にログ出力します。サーバーでは直近に受け付けた TCP とゲートウェイのコネクションを、クライアントではプロキシコネクション (および `--gateway` 設定時はゲートウェイコネクション) をログ出力します。
- `--mitm` 指定時、クライアントは各ティックとシャットダウン時に `mq.mitm` 行も出力します: 現在の MITM コネクション数とストリーム数、終端したコネクションと (理由別の) 不透明リレーしたコネクションの数、TLS/h2 の失敗、リーフ証明書キャッシュのヒットとミス、リクエスト数。全フィールドは [TLS MITM ガイド](/ja/guide/tls-mitm#オブザーバビリティ) を参照してください。
- `--request-metrics` (サーバー、ゲートウェイ) は、ゲートウェイリクエストごとに 1 行の `mq.req` logfmt 行を出力します (method/status/target/ttfb/origin_protocol/cache/…)。オプトインで、`--metrics-interval` とは独立です。

## テスト

リポジトリのルートでテストスイートを実行します。

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked -p mqproxy --bins --examples
bash tests/test_cli_help.sh target/release/mqproxy
bash tests/integration/e2e_udp.sh     # 他に e2e_{gateway,multipath,tproxy,mitm_h2,...}.sh
```

cargo のテストはワイヤフレーミング、リレー／フロー状態機械、イングレスパース、ゲートウェイのリクエスト経路、TLS MITM をカバーします。`tests/integration/e2e_*.sh` のスクリプトは、マルチパスアグリゲーション・完全なゲートウェイチェーン・UDP リレー・透過キャプチャ・MITM をエンドツーエンドで実行します。root または `NET_ADMIN` を必要とするスクリプトは、非特権で実行すると自動的にスキップされます。
