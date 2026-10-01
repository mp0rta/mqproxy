// build.rs — spec §2.1: static build of xquic and its nested BoringSSL.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// e.g. "HEAD" → the file git rewrites on checkout. None when git cannot answer (a linked worktree's
/// submodule gitdir lives under the main repo, which `cross` does not mount): then warn and skip the trigger.
fn git_path(repo: &Path, what: &str) -> Option<PathBuf> {
    let out = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap(),
            "rev-parse",
            "--git-path",
            what,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        println!(
            "cargo:warning=no rerun trigger for {} (git unavailable)",
            repo.display()
        );
        return None;
    }
    let p = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    Some(if p.is_absolute() { p } else { repo.join(p) })
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let root = manifest.join("../..").canonicalize().unwrap();
    let xquic = root.join("third_party/xquic");
    let bssl = xquic.join("third_party/boringssl");
    assert!(
        bssl.join("CMakeLists.txt").exists(),
        "run: git submodule update --init --recursive"
    );
    let asan = env::var_os("MQ_XQUIC_ASAN").is_some();

    // 1. BoringSSL — its own out dir (cmake-rs wipes a build dir configured for another source tree).
    let mut b = cmake::Config::new(&bssl);
    b.out_dir(out.join("boringssl"))
        .profile("Release")
        .define("BUILD_SHARED_LIBS", "0")
        .cflag("-fPIC")
        .cxxflag("-fPIC")
        .build_target("ssl");
    if asan {
        b.cflag("-fsanitize=address").cxxflag("-fsanitize=address");
    }
    let bssl_build = b.build().join("build"); // libssl.a, libcrypto.a at the build root
    let (ssl_a, crypto_a) = (bssl_build.join("libssl.a"), bssl_build.join("libcrypto.a"));
    assert!(ssl_a.exists() && crypto_a.exists());

    // 2. xquic — options from the shared file; SSL_INC_PATH + SSL_LIB_PATH must be given together.
    let mut x = cmake::Config::new(&xquic);
    x.out_dir(out.join("xquic"))
        .profile("Release")
        .build_target("xquic-static");
    for line in fs::read_to_string(manifest.join("xquic-build-options.txt"))
        .unwrap()
        .lines()
    {
        if let Some((k, v)) = line.split_once('=') {
            x.define(k, v);
        }
    }
    x.define("SSL_INC_PATH", bssl.join("include"))
        .define(
            "SSL_LIB_PATH",
            format!("{};{}", ssl_a.display(), crypto_a.display()),
        )
        .cflag("-Wno-dangling-pointer");
    if asan {
        x.define("ASAN", "ON"); // xquic's own option (CMakeLists.txt:116)
    }
    if env::var_os("CARGO_FEATURE_TEST_HOOKS").is_some() {
        x.define("XQC_ENABLE_TEST_HOOKS", "ON"); // spec §7: xqc_stream_create_with_id & co.
    }
    let xq_build = x.build().join("build");

    // 3. sizes.c for the layout test
    cc::Build::new()
        .file(manifest.join("csrc/sizes.c"))
        .include(xquic.join("include"))
        .compile("xqc_sys_sizes");

    println!("cargo:rustc-link-search=native={}", xq_build.display());
    println!("cargo:rustc-link-search=native={}", bssl_build.display());
    println!("cargo:rustc-link-lib=static=xquic-static");
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=stdc++");
    // Rebuild when either submodule moves: watch the files git rewrites on checkout, not `.git` (a gitdir file).
    for p in [git_path(&xquic, "HEAD"), git_path(&bssl, "HEAD")]
        .into_iter()
        .flatten()
    {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("xquic-build-options.txt").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("csrc/sizes.c").display()
    );
    println!("cargo:rerun-if-env-changed=MQ_XQUIC_ASAN");
}
