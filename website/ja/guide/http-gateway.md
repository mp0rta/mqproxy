# HTTP リクエスト実行ゲートウェイ

```text
アプリケーション (curl / SDK)
  │  POST /_mqproxy/fetch  (X-Mq-Auth / X-Mq-Target / X-Mq-Method + 生ボディ)
  ▼
mqproxy-client ──────── MPQUIC 上の HTTP/3 (ALPN h3) ────────► mqproxy-server
     1 HTTP リクエスト = 1 H3 リクエストストリーム = 1 MPQUIC ストリーム   │  hyper + rustls
     パスにわたって分散                                                  │  (h2 または HTTP/1.1,
                                                                        │   TLS 検証 ON)
                                                                        ▼
                                                                    オリジンサーバー
```

不透明なバイトをトンネリングする代わりに、ゲートウェイは **委譲された HTTP リクエストを実行** します。クライアントは `X-Mq-*` ヘッダを検証し、リクエストを標準的な H3 リクエストストリームへマッピングし（QPACK・トレーラ・ストリーム管理は H3 スタック由来 — ワイヤ上に独自の HTTP フレーミングはありません）、サーバーは各リクエストを認証し（`X-Mq-Auth`、リクエストごと）、`X-Mq-*` 制御ヘッダを除去し、完全な TLS 検証付きでオリジンに対してリクエストを実行します。エラーは HTTP ステータスにマッピングされ（DNS 失敗 → 502、接続タイムアウト → 504、不正なトークン → 403 など）、レスポンスには `X-Mq-Origin-Protocol` という診断ヘッダが付きます。各リクエストが 1 本の MPQUIC ストリームであるため、大きなダウンロード *とアップロード* がストリーム内マルチパスアグリゲーションを得られます。

## リクエストごとの制御

リクエストごとの `X-Mq-*` 制御により、API を変更せずにゲートウェイ機能をオプトインできます。

- `X-Mq-Origin-Protocol`: `h1` は HTTP/1.1 を強制します。`h2`・`h3`・ヘッダなしの場合は、サーバーが ALPN で h2 か HTTP/1.1 をネゴシエートします（HTTP/3 のオリジンクライアントはありません）。それ以外の値は `400`（`x-mq-error: bad-origin-protocol`）になります。
- `X-Mq-Accept-Encoding` はダウンロードの圧縮を要求します。
- `X-Mq-Forward-Cookie` は `Cookie` ヘッダを上流へ転送します（指定しなければ送られません）。
- `X-Mq-Cache` は引き続き検証されます（不正な値は `400`、`x-mq-error: bad-cache-ttl`）が、正しい値を指定しても効果はありません。オリジンのレスポンスキャッシュは削除されました。

サーバーはまた、リクエストをまたいでオリジンコネクションをプールして再利用します。

## クイックスタート

ゲートウェイはサーバー側でデフォルト有効です。クライアント側では `--gateway` を追加します（`--socks5` の有無を問わず動作）。

```bash
./target/release/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --gateway 127.0.0.1:8080

# ダウンロードを委譲 (X-Mq-Method で任意の HTTP メソッド。デフォルト GET)
curl -X POST http://127.0.0.1:8080/_mqproxy/fetch \
  -H "X-Mq-Auth: Bearer secret123" \
  -H "X-Mq-Target: https://example.com/large.bin" \
  -o large.bin

# アップロードを委譲
curl -X POST http://127.0.0.1:8080/_mqproxy/fetch \
  -H "X-Mq-Auth: Bearer secret123" \
  -H "X-Mq-Target: https://example.com/upload" \
  -H "X-Mq-Method: PUT" \
  --data-binary @large.bin
```

`--path` はここでも同様に機能します。ゲートウェイの MPQUIC コネクションは、各リクエストをバインドされた全パスにわたってアグリゲーションします。

サーバー側のフラグ（`--no-gateway`、`--origin-ca`、`--request-metrics`、`--masquerade`）は [オプションリファレンス](/ja/reference/options#http-ゲートウェイモード) を参照してください。
