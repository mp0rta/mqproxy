# インストール

mqproxy は systemd のテンプレートユニットを同梱しており、各インスタンスをハードニングされた非特権サービスとして実行できます。ビルド済みの `.deb` からインストールするか、自己完結バイナリをビルドしてインストールできます。

## `.deb` からインストール

ビルド済みの `amd64` および `arm64` パッケージが各 [GitHub Release](https://github.com/mp0rta/mqproxy/releases) に添付されています。Rust バイナリは xquic・BoringSSL・Rust 依存ライブラリを静的リンクします。システム側の実行時依存はパッケージのメタデータに記録されます。

```bash
# 最新リリースから自分のアーキテクチャの .deb を選ぶ
sudo apt install ./mqproxy_<version>_amd64.deb     # または _arm64.deb
```

パッケージは `/usr/bin/mqproxy`、`mqproxy-server@` / `mqproxy-client@` の systemd テンプレートユニットをインストールし、非特権の `mqproxy` ユーザーと `/etc/mqproxy` を作成します（同梱の `sysusers.d`/`tmpfiles.d` 経由、パッケージの `postinst` で適用）。以下のインスタンスごとの設定手順から続けてください — configure/enable の手順は同一で、ソースからのビルド手順だけが省略されます。

## systemd サービスとしてインストール（ソースから）

自己完結バイナリ（xquic + BoringSSL を静的リンク、インストール後のバイナリは非標準のランタイム依存を持たない）をビルドしてインストールします。

```bash
sudo apt-get install -y dpkg-dev python3
python3 packaging/build.py
sudo apt install ./target/dist/mqproxy_*.deb
```

`mqproxy` システムユーザーとそのディレクトリを作成します（同梱の `sysusers.d`/`tmpfiles.d` で宣言）。

```bash
sudo systemd-sysusers
sudo systemd-tmpfiles --create          # /etc/mqproxy を作成 (0750 mqproxy:mqproxy)
```

## インスタンスの設定と有効化

インスタンスごとの設定を配置してロックダウンします（サービスはこれをユーザー `mqproxy` として読み込みます）。

```bash
sudoedit /etc/mqproxy/edge1.conf        # 設定ファイルのページを参照
sudo chown mqproxy:mqproxy /etc/mqproxy/edge1.conf
sudo chmod 0600 /etc/mqproxy/edge1.conf # 0600 でトークン権限の警告を抑止
```

インスタンスを有効化して起動します — `@` の後ろの部分が設定ファイルのベース名です。

```bash
sudo systemctl enable --now mqproxy-server@edge1     # → /etc/mqproxy/edge1.conf
journalctl -u mqproxy-server@edge1 -f                # ログ
```

クライアント側は同じ要領で `mqproxy-client@<name>` を使います（`/etc/mqproxy/<name>.conf`）。

## 注意点

- **qlog:** xquic の qlog を取得するには、設定で `[Log] QLog = /var/log/mqproxy` を設定します。ユニットの `LogsDirectory=` が `/var/log/mqproxy` を作成し、`ProtectSystem=strict` が（`PrivateTmp` を除き）それ以外の場所への qlog 書き込みをブロックします。qlog は `QLog` が設定されない限り OFF のままです。
- **特権ポート:** デフォルトの `4433` は capability を必要としません。1024 未満のポートで待ち受けるには、`sudo systemctl edit mqproxy-server@edge1` で `AmbientCapabilities=CAP_NET_BIND_SERVICE` を追加します。
- **TLS 証明書:** `[TLS] Cert`/`Key` を、サービスが読めるパス（例: `/etc/mqproxy` 配下）に設定します。組み込みのテスト証明書はパッケージインストールには含まれません。

完全な INI リファレンスは [設定ファイル](./configuration) を参照してください。
