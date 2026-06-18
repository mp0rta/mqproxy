---
layout: home

hero:
  name: mqproxy
  text: MPQUIC ネイティブなマルチパス・アプリケーションプロキシ
  tagline: TCP・HTTP・UDP のフローを Multipath QUIC のプリミティブへ直接マッピングし、アプリ自身が MPQUIC を実装することなく、経路の多重化・シームレスなフェイルオーバー・帯域アグリゲーションを実現します。
  actions:
    - theme: brand
      text: はじめる
      link: /ja/guide/introduction
    - theme: alt
      text: クイックスタート
      link: /ja/guide/quick-start
    - theme: alt
      text: GitHub で見る
      link: https://github.com/mp0rta/mqproxy

features:
  - icon: 🧬
    title: MPQUIC ネイティブなフローマッピング
    details: 1 つの TCP フローは 1 本の MPQUIC ストリームに、1 つの HTTP リクエストは 1 本の H3 ストリームに、1 つの UDP セッションは MPQUIC DATAGRAM になります。単一の転送がストリーム内で全パスにわたってアグリゲーションされます。
  - icon: 🛣️
    title: 帯域アグリゲーションとフェイルオーバー
    details: QUIC ストリームはオフセットで再構成されるため、そのフレームを複数パス（WiFi + LTE など）に分散しても正しさが保たれます。--path を繰り返してパスを追加します。
  - icon: 🧰
    title: 5 つのイングレスモード
    details: TCP プロキシ（SOCKS5 / HTTP CONNECT）、HTTP リクエストゲートウェイ、UDP リレー、透過キャプチャ、そしてオプトインの TLS 終端 MITM L7 プロキシ。
  - icon: 🛡️
    title: プロダクション対応
    details: 自動再接続／キープアライブ、パス単位・リクエスト単位のメトリクス、CC／スケジューラ選択、認証前コネクション上限、マスカレードモード、INI 設定ファイル、systemd パッケージング。
---
