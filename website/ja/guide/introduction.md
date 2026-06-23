# 概要

**mqproxy** は、[Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) 上に構築された **マルチパス・アプリケーションプロキシ／アクセラレータ** で、[XQUIC のフォーク](https://github.com/mp0rta/xquic) を使用しています。mqproxy はアプリケーションのフローを MPQUIC のプリミティブへ直接マッピングします — 1 つの TCP フローは 1 本の MPQUIC ストリームに、1 つの HTTP リクエストは MPQUIC 上の 1 本の H3 ストリームに、1 つの UDP セッションは MPQUIC DATAGRAM になります。これにより、アプリケーション自身が MPQUIC を実装することなく、経路の多重化・シームレスなフェイルオーバー・**帯域アグリゲーション** を得られます。

mqproxy は **クライアント／サーバーのペア** として動作します。クライアントは 1 つ以上のローカルイングレスを公開し、トラフィックを単一のマルチパス QUIC トンネル経由でサーバーへ運び、サーバーがオリジンへ到達します。4 つのイングレスモードが利用できます — **TCP プロキシ**（SOCKS5 / HTTP CONNECT）、**HTTP リクエストゲートウェイ**（`POST /_mqproxy/fetch`、TLS 検証を常時有効にしてオリジンに対して実行）、**UDP リレー**（MPQUIC DATAGRAM 上の SOCKS5 UDP ASSOCIATE）、そしてオプションの TLS 終端 MITM モードを伴う **カーネルリダイレクト TCP の透過キャプチャ** です。すべてのモードで、束ねた各パスにわたる経路多重化・シームレスフェイルオーバー・ストリーム内帯域アグリゲーションが得られます。

加えて、自動再接続／キープアライブ、パス単位・リクエスト単位のメトリクス、輻輳制御とマルチパススケジューラの選択、認証前コネクション上限、マスカレードモード、INI 設定ファイル、systemd サービスパッケージングも備えています。

## mqvpn との関係

mqproxy は [mqvpn](https://github.com/mp0rta/mqvpn) の L4/L7 兄弟です。mqvpn が QUIC DATAGRAM（MASQUE CONNECT-IP）で IP パケットを運ぶ標準ベースの L3 VPN であるのに対し、mqproxy はアプリケーションフロー層で動作し、**MPQUIC ネイティブ** です。

| | mqvpn | mqproxy |
|---|---|---|
| レイヤ | L3 | L4 / L7 |
| データプレーン | QUIC DATAGRAM | QUIC STREAM + DATAGRAM |
| モデル | IP パケットトンネル | アプリケーションフロープロキシ |
| 強み | IP 透過性、標準志向 | MPQUIC ネイティブなフローマッピング |

両者は補完的で共存できます。デバイス全体の透過性には mqvpn を動かしつつ、特定の優先度の高い転送は mqproxy に委譲する、といった使い方が可能です。

## なぜ MPQUIC ネイティブなのか？

QUIC の **ストリーム** はオフセットで再構成されるため、1 本のストリームの STREAM フレームを複数パスに分散しても正しさが保たれます。したがって、1 本の MPQUIC ストリームとして運ばれる単一の大きなダウンロード／アップロードは、*ストリーム内* マルチパスアグリゲーションを得られます。これは、内側のトラフィックを DATAGRAM で運ぶ方式（mqvpn/MASQUE の経路）に対する構造的な優位性です。DATAGRAM 方式では、フローピンニングが単一パスを強制し、ピンしなければ内側 QUIC の並べ替えのリスクが生じます。

**実測:** 2 パス・100 Mbit/s のテストベッドでは、TCP プロキシは *単一* の TCP ストリームでもアグリゲーションします — **`-P 1` で単一パスの 1.81 倍**、`-P 16` で 1.93 倍。一方、フローピンする L3 DATAGRAM トンネルは、2 本目のパスが使われるまでに複数の並列フローを必要とします。完全なマトリクス（`-P 1〜16`、対称・非対称、mqvpn の `wlb`/`minrtt` との比較）は [TCP アグリゲーション ベンチマーク](https://github.com/mp0rta/mqproxy/blob/main/docs/report/2026-06-23-single-tcp-aggregation-mqvpn-vs-mqproxy.md) を参照してください。

## 動作モード

| モード | マッピング | |
|---|---|---|
| **TCP プロキシ** | 1 TCP フロー → 1 MPQUIC 双方向ストリーム | ✅ |
| **HTTP リクエスト実行ゲートウェイ** | 1 HTTP リクエスト → MPQUIC 上の 1 H3 ストリーム | ✅ |
| **UDP リレー** | 1 UDP セッション → MPQUIC DATAGRAM | ✅ |
| **透過 TCP キャプチャ** | カーネルリダイレクト TCP → 不透明な MPQUIC ストリーム | ✅ |
| **TLS MITM イングレス** | ブラウザの TLS を終端（偽造リーフ） → H2 → ゲートウェイトンネル | ✅ オプション |

TCP プロキシモードは TLS を **終端しません**。HTTPS では TLS はアプリケーションとオリジンの間でエンドツーエンドのままです。mqproxy-client と mqproxy-server の間の WAN 区間のみが MPQUIC で運ばれます。

## 仕組み

```text
アプリケーション (curl / SDK / app)
  │  SOCKS5 / HTTP CONNECT 経由の TCP
  ▼
mqproxy-client ──────────────── MPQUIC (マルチパス) ──────────────► mqproxy-server
  │  CONNECT_TCP(host:port)        1 TCP フロー = 1 双方向ストリーム      │  host:port へダイヤル
  │                                パスにわたって分散                    ▼
  └─ 双方向バイトリレー ◄─────────────────────────────────────────► オリジンサーバー
```

クライアントに（SOCKS5 または HTTP CONNECT 経由で）到着した TCP フローは、新しい MPQUIC 双方向ストリームを開きます。このストリームは `CONNECT_TCP_REQUEST`（SOCKS5 スタイルのアドレスタイプ）で始まり、サーバーがターゲットへダイヤルして `CONNECT_TCP_RESPONSE` を返し、その後は同じストリームが双方向に生バイトをリレーします。コネクションレベルの認証は、フローが開かれる前に制御ストリーム上で一度だけ行われます。

[ソースからのビルド](./building) と [クイックスタート](./quick-start) へ進むか、特定のモードへジャンプしてください: [TCP プロキシ](./tcp-proxy)、[HTTP ゲートウェイ](./http-gateway)、[UDP リレー](./udp-relay)、[透過キャプチャ](./transparent-capture)、[TLS MITM](./tls-mitm)。
