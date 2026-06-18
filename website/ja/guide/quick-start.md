# クイックスタート

サーバーとクライアントをローカルで動かし、クライアントの SOCKS5 イングレス経由で TCP トラフィックを流します。

```bash
# サーバー — UDP :4433 で MPQUIC を待ち受け。デフォルトで同梱のテスト証明書を使用。
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# クライアント — サーバーへ接続し、ローカルの SOCKS5 リスナーを :1080 で公開。
./build/mqproxy client \
  --server 127.0.0.1:4433 \
  --token  secret123 \
  --socks5 127.0.0.1:1080
```

```bash
# プロキシ経由でトラフィックを送信
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

::: warning
同梱のテスト証明書はローカルテスト専用です。実運用では独自の `--cert`/`--key` と強力な `--token` を渡してください。
:::

## マルチパスアグリゲーション

`--path` を繰り返すことで、追加のローカル IP を MPQUIC パスとしてバインドできます（例: WiFi + LTE）。するとストリームがそれらにわたってアグリゲーションされます。

```bash
./build/mqproxy client \
  --server <server-ip>:4433 --token secret123 \
  --socks5 127.0.0.1:1080 \
  --path 192.168.1.50 \
  --path 10.20.0.30
```

`--http-connect <ip:port>` で HTTP CONNECT イングレスを公開することもできます（`curl --proxy http://127.0.0.1:<port> https://...` で使用）。

## 次のステップ

- [HTTP ゲートウェイ](./http-gateway) — HTTP リクエストの実行をサーバーへ委譲します。
- [UDP リレー](./udp-relay) — DNS/ゲーム/VoIP の UDP を MPQUIC DATAGRAM で運びます。
- [透過キャプチャ](./transparent-capture) — アプリ設定不要で TCP をカーネルレベルでキャプチャします。
- [TLS MITM](./tls-mitm) — TLS を HTTP/2 として終端・検査します。
- [オプションリファレンス](/ja/reference/options) — モードごとの全フラグ。
