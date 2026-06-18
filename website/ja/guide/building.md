# ソースからのビルド

**必要なもの:** `cmake`、`make`、C11 コンパイラ、`git`、`openssl` CLI（同梱のテスト証明書を configure 時に生成するために使用）、`libevent`、`libcurl` の開発ヘッダ（例: `libcurl4-openssl-dev` — ゲートウェイのオリジンクライアント）、`libnghttp2` の開発ヘッダ（`libnghttp2-dev` — TLS MITM L7 経路の HTTP/2 終端用。静的バイナリにはさらに同梱の `libnghttp2.a` が必要）、そして `golang`（BoringSSL のビルドに Go が必要）。初回ビルド時はネットワークアクセスが必要です（BoringSSL がクローンされます）。

Debian/Ubuntu の場合:

```bash
sudo apt-get install -y build-essential cmake git openssl \
  libevent-dev libcurl4-openssl-dev libnghttp2-dev golang-go
```

::: tip ランタイムのパッケージ依存
動的リンクされたバイナリは nghttp2 共有ライブラリ（Debian/Ubuntu パッケージ `libnghttp2-14`）に依存します。`-DMQPROXY_STATIC_XQUIC=ON` のパッケージングバイナリは代わりに `libnghttp2.a` を静的リンクするため、nghttp2 のランタイム依存を持ちません。
:::

## ビルド手順

```bash
# 1. xquic サブモジュールごとクローン
git clone --recursive https://github.com/mp0rta/mqproxy.git
cd mqproxy
# (--recursive なしでクローンした場合: git submodule update --init --recursive)

# 2. ツリー内の xquic をビルド (BoringSSL + xquic、qlog 有効)
#    third_party/xquic/build/libxquic.so を生成。BoringSSL を既知のコミットに固定。
./scripts/build-xquic.sh

# 3. その xquic に対して mqproxy を configure + ビルド
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DXQUIC_BUILD_DIR="$PWD/third_party/xquic/build"
cmake --build build -j"$(nproc)"

# バイナリは build/mqproxy にあります
./build/mqproxy --help
```

ビルドが完了したら、[クイックスタート](./quick-start) でサーバー／クライアントのペアをローカルで動かしてください。mqproxy をマネージドサービスとして動かすには [インストール](./installation) を参照してください。
