# ソースからのビルド

Rust は rustup で導入してください。`rust-toolchain.toml` でバージョンを固定しています。
xquic と BoringSSL のために C/C++ コンパイラ、CMake、Go が必要です。
Cargo が両ライブラリをビルドして静的リンクします。

```bash
sudo apt-get install -y build-essential cmake git golang-go
git clone --recursive https://github.com/mp0rta/mqproxy.git
cd mqproxy
git submodule update --init --recursive
cargo build --release --locked -p mqproxy
./target/release/mqproxy --help
```

アプリケーションは Rust 製です。HTTP/3 は h3wire、オリジンの HTTP/1.1・HTTP/2 は
hyper と rustls を使います。xquic とその配下の BoringSSL は固定した submodule として保持します。
