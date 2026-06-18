# 設定ファイル

長いコマンドラインの代わりに、どちらのサブコマンドも `--config <path>` で WireGuard スタイルの INI ファイルから設定を読み込めます。これは mqproxy をマネージドサービスとして動かす（インスタンスごとに 1 つの設定ファイル）ための想定された方法であり、共有トークンを `ps` / `/proc/<pid>/cmdline` から隠します。

```ini
# /etc/mqproxy/edge1.conf   (chmod 0600 — トークンを非公開に保つ)
[Interface]
Listen   = 0.0.0.0:4433
MaxConns = 64

[TLS]
Cert = /etc/mqproxy/tls/edge1.pem
Key  = /etc/mqproxy/tls/edge1.key

[Auth]
Key = your-shared-token

[Multipath]
CC        = bbr
Scheduler = minrtt
```

```bash
mqproxy server --config /etc/mqproxy/edge1.conf
```

- **優先順位:** 組み込みのデフォルト < 設定ファイル < CLI フラグ。`--config` と並べて渡したフラグはファイルを上書きするため、定常状態をファイルに固定しつつ、コマンドラインで一時的に上書きできます（例: あるデバッグ実行のために `--qlog /tmp/dbg` を追加）。
- **形式:** セクション化された INI、CamelCase のキー（大文字小文字を区別しない）、`#` と `;` のコメントは **独立した行** に（値の後のインライン `# …` は値の一部として読まれ、除去されません）、ブール値は `true`/`yes`/`1`。`Path` はマルチパスのために繰り返し可能。未知のキーや不正な値は警告してスキップされます（デフォルトが有効のまま）。`--config` ファイルが存在しない場合は致命的エラーです。
- **シークレット:** トークンは `[Auth] Key` にあります。ファイルがグループ／全体読み取り可能な場合、mqproxy は起動時に警告します — `chmod 0600` してください。

## キーリファレンス

設定キーは [オプションリファレンス](/ja/reference/options) の CLI フラグに対応します。

| セクション | サーバーキー | クライアントキー |
|---|---|---|
| `[Interface]` | `Listen`, `MaxConns` | `Reconnect`, `KeepaliveIdle`, `ReconnectMaxBackoff` |
| `[Server]` | — | `Address`, `ClientId` |
| `[TLS]` | `Cert`, `Key` | — |
| `[Auth]` | `Key` (トークン) | `Key` (トークン) |
| `[Multipath]` | `CC`, `Scheduler` | `CC`, `Scheduler`, `Path` (繰り返し可) |
| `[Ingress]` | — | `Socks5`, `HttpConnect`, `Gateway`, `TProxy`, `Mode`, `Fwmark`, `Table`, `Dport`, `SetupRedirect`, `SkipUid` |
| `[Gateway]` | `Enabled`, `Masquerade`, `OriginCA`, `CacheMaxBytes` | — |
| `[Mitm]` | — | `Enabled`, `CACert`, `CAKey`, `IgnoreHosts` (繰り返し可) |
| `[UDP]` | `Enabled`, `IdleTimeout` | — |
| `[Metrics]` | `Interval`, `PerRequest` | `Interval` |
| `[Log]` | `QLog` | `QLog` |

完全な出発点として [`server.conf.example`](https://github.com/mp0rta/mqproxy/blob/main/server.conf.example) と [`client.conf.example`](https://github.com/mp0rta/mqproxy/blob/main/client.conf.example) を参照してください。
