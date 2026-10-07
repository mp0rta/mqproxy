# Building from source

Install Rust with rustup; `rust-toolchain.toml` pins the supported toolchain.
Native dependencies are a C/C++ toolchain, CMake, Go and Git for the vendored
xquic/BoringSSL build. Cargo builds and statically links them automatically.

```bash
sudo apt-get install -y build-essential cmake git golang-go
git clone --recursive https://github.com/mp0rta/mqproxy.git
cd mqproxy
git submodule update --init --recursive
cargo build --release --locked -p mqproxy
./target/release/mqproxy --help
```

The application is Rust. HTTP/3 uses h3wire; origin HTTP/1.1 and HTTP/2 use
hyper and rustls. xquic and its nested BoringSSL remain pinned submodules.
