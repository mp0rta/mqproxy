# TCP プロキシ

デフォルトのモードです。クライアントに到着した TCP フローは、新しい MPQUIC **双方向ストリーム** を開きます。1 つの TCP フローが 1 本の MPQUIC ストリームになり、バインドされた全パスにわたって分散されます。このモードでは mqproxy は TLS を **終端しません** — HTTPS では TLS はアプリケーションとオリジンの間でエンドツーエンドのまま保たれ、mqproxy-client と mqproxy-server の間の WAN 区間のみが MPQUIC で運ばれます。

```text
アプリケーション (curl / SDK / app)
  │  SOCKS5 / HTTP CONNECT 経由の TCP
  ▼
mqproxy-client ──────────────── MPQUIC (マルチパス) ──────────────► mqproxy-server
  │  CONNECT_TCP(host:port)        1 TCP フロー = 1 双方向ストリーム      │  host:port へダイヤル
  │                                パスにわたって分散                    ▼
  └─ 双方向バイトリレー ◄─────────────────────────────────────────► オリジンサーバー
```

このストリームは `CONNECT_TCP_REQUEST`（SOCKS5 スタイルのアドレスタイプ）で始まり、サーバーがターゲットへダイヤルして `CONNECT_TCP_RESPONSE` を返し、その後は同じストリームが双方向に生バイトをリレーします。コネクションレベルの認証は、フローが開かれる前に制御ストリーム上で一度だけ行われます。

## 2 つのローカルイングレス

クライアントは TCP プロキシを次のいずれか（または両方）で公開します。

- **SOCKS5**（`--socks5 <ip:port>`）— TCP `CONNECT`。同じリスナーは SOCKS5 UDP `ASSOCIATE` も提供します（[UDP リレー](./udp-relay) を参照）。
- **HTTP CONNECT**（`--http-connect <ip:port>`）— `curl --proxy http://<ip:port> …` で使用します。

## クイックスタート

```bash
# サーバー — UDP :4433 で MPQUIC を待ち受け。デフォルトで同梱のテスト証明書を使用。
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# クライアント — サーバーへ接続し、ローカルの SOCKS5 リスナーを :1080 で公開。
./build/mqproxy client \
  --server 127.0.0.1:4433 \
  --token  secret123 \
  --socks5 127.0.0.1:1080
```

SOCKS5 イングレス経由でトラフィックを送信します。

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

あるいは HTTP CONNECT イングレスを公開してプロキシとして使います。

```bash
./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --http-connect 127.0.0.1:3128

curl --proxy http://127.0.0.1:3128 https://example.com/
```

## マルチパスアグリゲーション

`--path` を繰り返して追加のローカル IP を MPQUIC パスとしてバインドすると、各 TCP フローのストリームがそれらにわたってアグリゲーションされます。

```bash
./build/mqproxy client \
  --server <server-ip>:4433 --token secret123 \
  --socks5 127.0.0.1:1080 \
  --path 192.168.1.50 \
  --path 10.20.0.30
```

全フラグの一覧は [オプションリファレンス](/ja/reference/options#tcp-プロキシモード) を参照してください。このモードでは TLS はエンドツーエンドのままです — 代わりに終端・検査するには [TLS MITM](./tls-mitm) を参照してください。
