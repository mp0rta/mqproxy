# Configuration File

Instead of a long command line, either subcommand can read its settings from a WireGuard-style INI file with `--config <path>`. This is the intended way to run mqproxy as a managed service (one config file per instance) and keeps the shared token out of `ps` / `/proc/<pid>/cmdline`.

```ini
# /etc/mqproxy/edge1.conf   (chmod 0600 — keeps the token private)
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

- **Precedence:** built-in defaults < config file < CLI flags. A flag passed alongside `--config` overrides the file, so you can pin steady state in the file and override transiently on the command line (e.g. add `--qlog /tmp/dbg` for one debug run).
- **Format:** sectioned INI, CamelCase keys (case-insensitive), `#` and `;` comments **on their own line** (an inline `# …` after a value is read as part of the value, not stripped), booleans are `true`/`yes`/`1`. `Path` may be repeated for multipath. Unknown keys and bad values warn and are skipped (the default stands); a missing `--config` file is a fatal error.
- **Secrets:** the token lives in `[Auth] Key`. mqproxy warns at startup if the file is group/world-readable — `chmod 0600` it.

## Key reference

Config keys map to the CLI flags in the [Options Reference](/reference/options):

| Section | Server keys | Client keys |
|---|---|---|
| `[Interface]` | `Listen`, `MaxConns` | `Reconnect`, `KeepaliveIdle`, `ReconnectMaxBackoff` |
| `[Server]` | — | `Address`, `ClientId` |
| `[TLS]` | `Cert`, `Key` | — |
| `[Auth]` | `Key` (token) | `Key` (token) |
| `[Multipath]` | `CC`, `Scheduler` | `CC`, `Scheduler`, `Path` (repeatable) |
| `[Ingress]` | — | `Socks5`, `HttpConnect`, `Gateway`, `TProxy`, `Mode`, `Fwmark`, `Table`, `Dport`, `SetupRedirect`, `SkipUid` |
| `[Gateway]` | `Enabled`, `Masquerade`, `OriginCA`, `CacheMaxBytes` | — |
| `[Mitm]` | — | `Enabled`, `CACert`, `CAKey`, `IgnoreHosts` (repeatable) |
| `[UDP]` | `Enabled`, `IdleTimeout` | — |
| `[Metrics]` | `Interval`, `PerRequest` | `Interval` |
| `[Log]` | `QLog` | `QLog` |

See [`server.conf.example`](https://github.com/mp0rta/mqproxy/blob/main/server.conf.example) and [`client.conf.example`](https://github.com/mp0rta/mqproxy/blob/main/client.conf.example) for complete starting points.
