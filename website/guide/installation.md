# Installation

mqproxy ships systemd template units so each instance runs as a hardened, unprivileged service. You can install from a prebuilt `.deb` or build a self-contained binary and install it.

## Install from a `.deb`

Prebuilt `amd64` and `arm64` packages are attached to each [GitHub Release](https://github.com/mp0rta/mqproxy/releases). The binary is self-contained (xquic + BoringSSL + nghttp2 statically linked), so it depends only on the system libevent/libcurl.

```bash
# pick the .deb for your architecture from the latest release
sudo dpkg -i mqproxy_<version>_amd64.deb     # or _arm64.deb
```

The package installs `/usr/bin/mqproxy`, the `mqproxy-server@` / `mqproxy-client@` systemd template units, and creates the unprivileged `mqproxy` user plus `/etc/mqproxy` (via the bundled `sysusers.d`/`tmpfiles.d`, applied in the package's `postinst`). Continue from the per-instance config steps below — the configure/enable steps are identical; only the build-from-source steps are skipped.

## Install as a systemd service (from source)

Build a self-contained binary (xquic + BoringSSL statically linked, so the installed binary has no non-standard runtime deps) and install it:

```bash
# -DMQPROXY_STATIC_XQUIC statically links xquic+BoringSSL; the install prefix is
# baked into the unit ExecStart at *configure* time, so set it now (not at --install).
cmake -S . -B build \
      -DXQUIC_BUILD_DIR="$PWD/third_party/xquic/build" \
      -DMQPROXY_STATIC_XQUIC=ON -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build --target mqproxy_cli -j
sudo cmake --install build              # → /usr/bin/mqproxy, units, sysusers.d, tmpfiles.d
```

Create the `mqproxy` system user and its directories (declared by the bundled `sysusers.d`/`tmpfiles.d`):

```bash
sudo systemd-sysusers
sudo systemd-tmpfiles --create          # creates /etc/mqproxy (0750 mqproxy:mqproxy)
```

## Configure and enable an instance

Drop a per-instance config and lock it down (the service reads it as user `mqproxy`):

```bash
sudoedit /etc/mqproxy/edge1.conf        # see the Configuration File page
sudo chown mqproxy:mqproxy /etc/mqproxy/edge1.conf
sudo chmod 0600 /etc/mqproxy/edge1.conf # 0600 keeps the token-permission warning quiet
```

Enable and start the instance — the part after `@` is the config basename:

```bash
sudo systemctl enable --now mqproxy-server@edge1     # → /etc/mqproxy/edge1.conf
journalctl -u mqproxy-server@edge1 -f                # logs
```

The client side uses `mqproxy-client@<name>` the same way (`/etc/mqproxy/<name>.conf`).

## Notes

- **qlog:** to capture xquic qlog, set `[Log] QLog = /var/log/mqproxy` in the config. The unit's `LogsDirectory=` creates `/var/log/mqproxy`; `ProtectSystem=strict` blocks writing qlog anywhere else (except `PrivateTmp`). qlog stays off unless `QLog` is set.
- **Privileged ports:** the default `4433` needs no capabilities. To listen on a port below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE` via `sudo systemctl edit mqproxy-server@edge1`.
- **TLS cert:** set `[TLS] Cert`/`Key` to paths the service can read (e.g. under `/etc/mqproxy`); the built-in test cert is not present in a packaged install.

See [Configuration File](./configuration) for the full INI reference.
