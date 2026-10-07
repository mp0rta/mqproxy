# TLS MITM モード

`--mitm` は、透過キャプチャ経路を **TLS 終端の L7 プロキシ** に変えます。キャプチャされた各コネクションについて、クライアントは TLS ClientHello の SNI を覗き見し、オペレータの CA（`--ca-cert`/`--ca-key`）で署名したホストごとのリーフ証明書を偽造し、**HTTP/2** で TLS を終端し、各 H2 リクエストを MPQUIC トンネル上のそれぞれ独立した H3 リクエストにマッピングします。オリジンの取得はサーバーのゲートウェイが行います。ブラウザ↔クライアント側はプレーンな h2、クライアント↔サーバー間は MPQUIC なので、リクエストごとに専用のストリーム（リクエスト間のヘッドオブラインブロッキングなし）と専用のマルチパススケジューリングが得られます。

::: danger 信頼モデル
これは **オペレータ管理／同意済みエンドポイント** の MITM（企業プロキシや個人 VPN の姿勢）であり、攻撃ツールではありません。これが機能するのは、オペレータがデバイスに自分の CA をインストールし、ブラウザが偽造リーフを信頼するからに他なりません。CA 秘密鍵は信頼の起点です — 保護してください。mqproxy は、シンボリックリンクである鍵ファイル、mqproxy を実行しているユーザーが所有していない鍵ファイル、グループまたは他ユーザーが読み取れる鍵ファイル（`chmod 600` にしてください）を拒否します。
:::

## CA の作成

mqproxy には CA 証明書と、その **暗号化されていない PKCS#8** 形式の秘密鍵（`-----BEGIN PRIVATE KEY-----` の PEM）が必要です。次のコマンドで作成できます。

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout mitm-ca.key -out mitm-ca.crt -days 825 -subj "/CN=mqproxy MITM CA" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign
chmod 600 mitm-ca.key
```

その後、トラフィックをキャプチャするすべてのデバイスの信頼ストアに `mitm-ca.crt` をインストールします（Debian/Ubuntu なら `/usr/local/share/ca-certificates/` にコピーして `update-ca-certificates` を実行）。

EC（P-256、P-384）、Ed25519、RSA の CA が使えます。証明書は X.509 v3 で `CA:TRUE` を持ち、`keyUsage` 拡張がある場合は `keyCertSign` を含む必要があります。期限切れは不可で、鍵と証明書が対応している必要があります。

**PKCS#8 のみ。** PKCS#1（`BEGIN RSA PRIVATE KEY`）または SEC1（`BEGIN EC PRIVATE KEY`）形式の鍵は起動エラーになり、変換方法がメッセージで示されます。

```bash
openssl pkcs8 -topk8 -nocrypt -in old.key -out mitm-ca.key
```

暗号化された鍵（`BEGIN ENCRYPTED PRIVATE KEY`）も拒否されます。

### CA を自分のドメインに限定する（任意）

あらゆる名前について全デバイスが信頼する CA は大きなリスクです。X.509 の `nameConstraints` 拡張を付けると、CA を検査したいドメインだけに限定できます。ブラウザがこれを強制し、mqproxy はそれ以外のホストについて、ブラウザに拒否される証明書を偽造する代わりに [不透明に](#不透明リレーになるもの) リレーします。

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout mitm-ca.key -out mitm-ca.crt -days 825 -subj "/CN=mqproxy MITM CA" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign \
  -addext "nameConstraints=critical,permitted;DNS:example.com,permitted;DNS:example.org"
```

`DNS:example.com` は `example.com` とそのすべてのサブドメインを許可し、`DNS:.example.com` はサブドメインのみを許可します。`excluded;DNS:…` も同様に使えます。`IP` の制約は無視されます。それ以外の種類の名前制約、またはホスト名ではない `DNS` 制約を持つ CA は起動エラーになります。

## クイックスタート

```bash
# サーバー — 変更なし。ゲートウェイのオリジンブリッジがオリジン取得を行う。
./target/release/mqproxy server --listen 0.0.0.0:4433 --token secret123 \
  --cert /etc/mqproxy/tls/server.pem --key /etc/mqproxy/tls/server.key

# クライアント — 透過キャプチャ + MITM。--tproxy と署名 CA が必要。
sudo ./target/release/mqproxy client \
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

`--mitm` には `--tproxy`（透過キャプチャが唯一の MITM イングレス）**および** `--ca-cert <pem>` + `--ca-key <pem>` が必要です。いずれかの欠落、読み込めない CA（上記参照）、無効な ignore エントリは、終了コード 2 の起動エラーとなり、原因を示すメッセージが出ます。設定ミスが原因で暗黙のうちに不透明パススルーへフォールバックすることはありません。`--mitm` はクライアント専用です。`server` サブコマンドは拒否し、サーバーの設定ファイルにある `[Mitm]` セクションは警告を出してスキップされます。

`--mitm` を付けない場合、CA と ignore のオプションは受け付けられますが効果はありません。

## 不透明リレーになるもの

MITM は、すべてが肯定的に確認できたときだけ適用されます。それ以外のキャプチャされたコネクションは、通常の TCP プロキシ経路でバイト単位に **不透明リレー** されます。クライアントにはオリジンの本物の証明書が見え、コネクションは切断されずに動き続けます。

- クライアントが TLS の ALPN で `h2` を提示しない（`curl --http1.1`、多くの非ブラウザクライアント、HTTP/1.1 で届く **WebSocket** を含む）
- TLS ではないトラフィック
- SNI がない、SNI が不正、または SNI が IP アドレス
- ホストが ignore リストにある
- ホストが `nameConstraints` を持つ CA の範囲外にある
- クライアントの TLS 設定が偽造証明書と両立しない（たとえば、その署名アルゴリズムをどれも受け入れない）
- ClientHello が 5 秒以内に届かない、または 8 KiB を超える
- ClientHello が完了する前にクライアントがコネクションを閉じた
- すでに 256 コネクションが MITM 中である（超過分は拒否されず不透明リレーに切り替わる）

## ignore-hosts

`--ignore-host <host>`（繰り返し可）と `--ignore-hosts <a,b,c>`（カンマ区切り、スペースなし）は、不透明にリレーするホストを列挙します。オリジンの本物の証明書がクライアントに届くため、偽造リーフを拒否する証明書ピンニングアプリに使用してください。

マッチングは、小文字化し末尾のドットを除去した SNI に対して行われ、次のいずれかです。

- **完全一致** — `example.com` は `example.com` **のみ** にマッチ
- **サブドメインのみ** — `.example.com` は `www.example.com` や `a.b.example.com` にマッチしますが、`example.com` 自体には **マッチしません**

サイトとそのサブドメインの両方を除外するには、両方を列挙します。CLI と設定ファイルのエントリは合算されます。

有効なホスト名ではないエントリ（IP アドレス、ワイルドカード、英数字・`-`・`.` 以外の文字を含むもの、空の `--ignore-host ""` など）は **起動エラー**（終了コード 2）となり、問題のエントリが示されます。黙ってスキップされることはありません。（カンマ区切りの `--ignore-hosts a,,b` の空の項目はスキップされます。）

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

`IgnoreHosts` は繰り返し可能なキーで、`[Multipath] Path` と同様に **1 行 1 ホスト** です（カンマ区切りのリストではありません）。CLI の `--ignore-host(s)` とこれらのエントリは合算されます。

## UDP/443 のブロック

mqproxy が MITM するのは TCP のみです。`Alt-Svc` ヘッダやキャッシュされた HTTPS DNS レコードを見たブラウザは、サイトを UDP/443 の QUIC/HTTP/3 に切り替えることがあり、その場合プロキシは完全にバイパスされます。mqproxy はリレーするレスポンスから `alt-svc` を除去しますが、キャプチャ経路で UDP/443 もブロックして、ブラウザが TCP と TLS にフォールバックするようにしてください。ルーターでは次のようにします。

```bash
nft add table inet mqproxy_block
nft add chain inet mqproxy_block forward '{ type filter hook forward priority 0; }'
nft add rule  inet mqproxy_block forward udp dport 443 reject
```

そのマシン自身のブラウザには、`forward` の代わりに `output` にフックしてください。

## リクエスト処理と制限

- **1 コネクション 1 ホスト。** 各 TLS コネクションは、開かれたときの SNI に紐づきます。`:authority` が別のホストを指すリクエストには `421 Misdirected Request` が返り、ブラウザは専用のコネクションで再試行します。
- **ヘッダ制限**（ゲートウェイトンネルの両端で共通）: ヘッダフィールド（名前 + 値）は 8 KiB、ヘッダセクション全体は 32 KiB、フィールド数は 256、リクエストパス（クエリ込み）は約 8 KiB まで。制限を超えるブラウザのリクエストヘッドには、h2 層が `431`（またはストリームのリセット）を返します。この範囲内であれば、大きな Cookie、長い URL、大きな CSP ヘッダも通ります。
- **HTTP/2 の制限:** コネクションあたり同時 128 ストリーム、受信ウィンドウはストリームあたり 256 KiB、コネクション全体で 512 KiB。
- **コネクション:** クライアントあたり MITM は最大 256 コネクション。開いているストリームのないコネクションはアイドル 60 秒で閉じられます。ストリームが開いている間に 60 秒無通信のピアには PING が送られ、90 秒無通信で閉じられます。Server-Sent Events のような長寿命のレスポンスは問題ありません。
- **メソッド** は大文字小文字を保持し、32 バイトまで。`CONNECT` とアスタリスク形式（`OPTIONS *`）のリクエストは `400` で拒否されます。
- **Cookie:** ブラウザが分割した `cookie` フィールドは 1 つに結合され、`Cookie` と `Authorization` はオリジンへ転送されます。
- **`alt-svc` はレスポンスから除去されます**（[UDP/443 のブロック](#udp-443-のブロック) を参照）。

## オブザーバビリティ

`--metrics-interval` を指定すると、クライアントは各ティックとシャットダウン時に `mq.mitm` 行も出力します（すべてのカウンターが 0 の間は出力されません）。

```
mq.mitm conns=<live> streams=<open> mitm=<n> opaque_not_tls=<n> opaque_no_sni=<n> opaque_bad_sni=<n> opaque_no_h2=<n> opaque_ignored=<n> opaque_ca_scope=<n> opaque_tls_incompat=<n> opaque_timeout=<n> opaque_too_large=<n> opaque_eof=<n> opaque_capacity=<n> tls_fail=<n> h2_fail=<n> dead=<n> leaf_hit=<n> leaf_miss=<n> reqs=<n> rejects=<n>
```

`conns` と `streams` は現在開いている MITM コネクションと h2 ストリームの数で、それ以外は累積値です。`mitm` は終端したコネクション数、各 `opaque_*` は [上記](#不透明リレーになるもの) の理由ごとに不透明リレーしたコネクション数です。`tls_fail`、`h2_fail`、`dead` は、TLS エラー、h2 エラー、ピア消失で終了したコネクション数を数えます。`leaf_hit`/`leaf_miss` は偽造証明書キャッシュのヒットとミス、`reqs` は受信したすべての h2 リクエストの数、`rejects` はそのうちトンネルリクエストを開く前に拒否したものの数です（リクエストマッピングによる `x-mq-error` または 421 の応答、トンネルが使えないか開けなかった場合、不正なリクエストへの `RST_STREAM`、コネクションあたりのストリーム上限を超えたときの `REFUSED_STREAM`）。debug ログレベルでは、ルーティングの判断ごとに `mq_mitm: <sni|-> → mitm|opaque(<why>)` が出力されます。ヘッダやボディの値がログに出ることはありません。

## セキュリティ姿勢

- **信頼できないブラウザヘッダ。** ブラウザが提供する `X-Mq-*` ヘッダはすべて除去されます — プロキシ制御として解釈されることは決してありません。クライアントは自身の `x-mq-auth` / `x-mq-forward-cookie` を注入します。通常のブラウジングが機能するよう `Cookie` と `Authorization` は転送されます。
- **フェイルクローズかつ有界。** 設定不備の MITM は起動エラーであり、暗黙のパススルーには決してなりません。ClientHello はサイズ上限とデッドライン付きで読み込まれ、上記の制限が新しいイングレスを制限します。
- **リーフ証明書** は SNI ごとに偽造され、有効期間は短く（24 時間）、CA で署名され、小さなメモリ内キャッシュに保持されます。mqproxy の実行中、CA 鍵はメモリ上に残ります。
- **HTTP/2 のみ。** それ以外のプロトコルは検査されず、不透明にリレーされます。

## 既知の制限: 低速なデバイスへの大きなダウンロード

クライアントの HTTP/3 受信側には、まだエンドツーエンドのバックプレッシャーがありません。xquic は受信したレスポンスデータをすぐにクライアントのメモリへコピーし、フロー制御のクレジットもすぐにサーバーへ返します。ブラウザ（またはそれが動くデバイス）が大きなダウンロードをトンネルの配信速度より遅く消費すると、その差分をクライアントがメモリに溜め込みます。ゲートウェイの `POST /_mqproxy/fetch` イングレスも同様です。修正は xquic 上流で追跡されており（[alibaba/xquic#959](https://github.com/alibaba/xquic/issues/959) と [PR #960](https://github.com/alibaba/xquic/pull/960)）、取り込み可能になり次第反映します。それまでメモリに余裕のないルーターでは、低速なクライアント向けの大きなダウンロード中のクライアントのメモリ使用量を監視するか、該当ホストを [ignore リスト](#ignore-hosts) に追加して、上限のある不透明経路を通してください。
