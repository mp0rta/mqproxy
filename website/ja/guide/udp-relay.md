# UDP リレー

```text
UDP アプリ (DNS / ゲーム / VoIP / …)
  │  SOCKS5 UDP ASSOCIATE
  ▼
mqproxy-client ──────── MPQUIC DATAGRAM (マルチパス) ────────► mqproxy-server
     1 UDP セッション = 双方向シグナリングストリーム + DATAGRAM    │  接続済みの
     (session_id タグ付きパケットを運ぶ)                          │  UDP ソケット
                                                                 ▼
                                                             UDP ターゲット
```

UDP リレーは、非 QUIC の UDP トラフィック（DNS、NTP、ゲーム、VoIP、アプリ固有の UDP）を MPQUIC DATAGRAM 上で運びます。イングレスは TCP と同じ `--socks5` リスナー上の **SOCKS5 UDP ASSOCIATE**（RFC 1928 §7）です。各ターゲットに対してクライアントは小さな双方向シグナリングストリーム（`UDP_SESSION_OPEN`/`RESP`、1 本の `mqproxy-tcp/1` コネクション上で TCP と多重化）を開き、その後 session id でタグ付けしたパケットを DATAGRAM として送信します。サーバーはセッションごとに接続済み UDP ソケットを保持し、双方向にリレーします。

パス MTU より大きいパケットはフラグメント化・再構成されます（4 スロット LRU、再送なし — UDP はロスありのまま）。セッションは、アイドルタイムアウト（サーバー駆動、`--udp-idle-timeout`）、ストリームのクローズ、または SOCKS5 制御コネクションの切断で破棄されます。サーバーは認証時にこの機能をアドバタイズし、`--no-udp` ですべての UDP を拒否できます。

::: tip
UDP リレーは `mqproxy-tcp/1` コネクションに相乗りするため、`--gateway` のみで動作するクライアント（H3 コネクション）はこれを利用できません。
:::

## クイックスタート

UDP リレーは **同じ `--socks5` リスナー** 上で公開されます — UDP ASSOCIATE を話す任意の SOCKS5 クライアントが利用できます。サーバーは認証時に機能をアドバタイズします。`--udp-idle-timeout <sec>` でセッション寿命を調整するか、`--no-udp` で UDP を完全に拒否します。

```bash
# サーバー (UDP リレーはデフォルト ON。30 秒アイドルタイムアウトを表示)
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123 \
  --udp-idle-timeout 30

# クライアント — SOCKS5 リスナーが TCP と UDP の両方を処理
./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --socks5 127.0.0.1:1080
```

`curl` は SOCKS5 UDP ASSOCIATE を話さないため、UDP 対応の SOCKS5 クライアントを使ってください。リポジトリには最小限のテストクライアント `udpsocks`（テストスイートでビルドされます）が同梱されており、手軽な確認に便利です。

```bash
# クライアントの SOCKS5 リスナー経由で UDP パケットをターゲットへリレー
./build/udpsocks --proxy 127.0.0.1:1080 --target 8.8.8.8:53 --send 32 --count 1
```
