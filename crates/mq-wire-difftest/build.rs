// spec §8.2: build the C codec the differential test compares against.
fn main() {
    let srcs = [
        "../../src/wire/mq_wire.c",
        "../../src/wire/mq_varint.c",
        "layout.c",
    ];
    let headers = ["../../src/wire/mq_wire.h", "../../src/wire/mq_varint.h"];
    for f in srcs.iter().chain(&headers) {
        println!("cargo:rerun-if-changed={f}");
    }
    cc::Build::new()
        .files(srcs)
        .include("../../src")
        .compile("mq_wire_c");
}
