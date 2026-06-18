# TLS MITM モード

`--mitm` は、透過キャプチャ経路を **TLS 終端の L7 プロキシ** に変えます。キャプチャされた各コネクションについて、クライアントは TLS ClientHello の SNI を覗き見し、オペレータの CA（`--ca-cert`/`--ca-key`）で署名したホストごとのリーフ証明書を偽造し、**HTTP/2** で TLS を終端し、各 H2 リクエストストリームを既存の MPQUIC ゲートウェイトンネル（`X-Mq-Auth` 制御プレーン）にマッピングしてサーバーへ送り、サーバーがオリジンを取得します。ブラウザ↔クライアント側はプレーンな h2 を話し、クライアント↔サーバートンネルは変わらず MPQUIC なので、各リクエストは引き続きストリーム内マルチパスアグリゲーションを得られます。

::: danger 信頼モデル
これは **オペレータ管理／同意済みエンドポイント** の MITM（企業プロキシや個人 VPN の姿勢）であり、攻撃ツールではありません。これが機能するのは、オペレータがデバイスに自分の CA をインストールし、ブラウザが偽造リーフを信頼するからに他なりません。CA 秘密鍵は信頼の起点です — 保護してください。mqproxy はこれを `O_NOFOLLOW`/`O_CLOEXEC` で開き、暗号化された鍵やグループ／全体読み取り可能な鍵を拒否します。
:::

## クイックスタート

```bash
# サーバー — 変更なし。ゲートウェイのオリジンブリッジがオリジン取得を行う。
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# クライアント — 透過キャプチャ + MITM。--tproxy と署名 CA が必要。
sudo ./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --tproxy 127.0.0.1:12443 --setup-redirect \
  --mitm \
  --ca-cert /etc/mqproxy/mitm-ca.crt \
  --ca-key  /etc/mqproxy/mitm-ca.key \
  --ignore-host signal.org \
  --ignore-hosts .apple.com,.icloud.com

# CA がデバイスに信頼された状態で、TCP :443 のブラウジングは終端され、
# H2 として検査され、リクエストごとに MPQUIC トンネルで運ばれます。
curl https://example.com/
```

## 必要条件（フェイルクローズ）

`--mitm` には `--tproxy`（v1 では透過キャプチャが唯一の MITM イングレス）**および** `--ca-cert <pem>` + `--ca-key <pem>` が必要です。いずれかが欠けている場合 — または BoringSSL アーカイブなしでビルドされたバイナリの場合（先に `scripts/build-xquic.sh` を実行）— は、非ゼロ終了の起動エラーになります。mqproxy が暗黙のうちに不透明パススルーへフォールバックすることはありません。`--mitm` はクライアント専用です（server サブコマンドは拒否します）。

## ignore-hosts（不透明スプライスによるバイパス）

`--ignore-host <host>`（繰り返し可）と `--ignore-hosts <a,b,c>`（カンマ区切り）は、**不透明にスプライス** するホストを列挙します — 生の TLS が手を加えられずにリレーされ、オリジンの本物の証明書がクライアントに届きます（偽造リーフを拒否する証明書ピンニングアプリに使用）。マッチングは正規化された（小文字化・末尾ドット除去された）SNI に対して行われ、**完全一致**（`signal.org` は `signal.org` のみにマッチ）または **先頭ドットのサフィックス**（`.apple.com` は `x.apple.com` や `a.b.apple.com` にマッチするが `apple.com` 自体には **マッチしない**）のいずれかです。CLI と設定のエントリは累積されます（和集合）。

## 設定（`[Mitm]`、クライアント専用）

INI 形式の全体は [設定ファイル](./configuration) のページを参照してください。

```ini
[Mitm]
Enabled  = true
CACert   = /etc/mqproxy/mitm-ca.crt
CAKey    = /etc/mqproxy/mitm-ca.key
IgnoreHosts = .apple.com
IgnoreHosts = signal.org
```

`IgnoreHosts` は繰り返し可能です — `[Multipath] Path` と同様に 1 行 1 ホストです。CLI の `--ignore-host(s)` とこれらのエントリは和集合になります。

## セキュリティ姿勢

- **信頼できないブラウザヘッダ。** ブラウザが提供する `X-Mq-*` ヘッダはすべて除去されます — プロキシ制御として解釈されることは決してありません。クライアントは自身の `x-mq-auth` / `x-mq-forward-cookie` を注入します。通常のブラウジングが機能するよう `Cookie` と `Authorization` は転送されます。
- **デュアル ABI のシンボル分離。** MITM 暗号コアはベンダリングされた BoringSSL をリンクし、そのシンボルは実行ファイルの動的テーブルから隠されます（`-Wl,--exclude-libs`）。これにより libcurl のシステム OpenSSL に割り込めません。
- **フェイルクローズかつ有界。** 設定不備／利用不可の MITM は起動エラーであり、暗黙のパススルーには決してなりません。ClientHello のドレインは有界（8 KiB 上限 + デッドライン）で、HTTP/2 のリソース制限（同時ストリーム数・フレームサイズ・ヘッダリストサイズ）が新しいイングレスを制限します。
- **HTTP/2 のみ。** ブラウザは ALPN `h2` を提示しなければなりません。MITM が ON のとき、非 h2・非 TLS・SNI なしのコネクションはハードフェイルします。
