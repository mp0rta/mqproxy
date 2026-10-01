fn main() {
    println!("cargo:rerun-if-changed=csrc/sizes.c");
    cc::Build::new()
        .file("csrc/sizes.c")
        .include("../../third_party/xquic/include")
        .compile("xqc_sys_sizes");
}
