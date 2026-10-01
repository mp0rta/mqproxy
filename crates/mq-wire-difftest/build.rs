// spec §8.2: build the C codec the differential test compares against.
fn main() {
    let files = [
        "../../src/wire/mq_wire.c",
        "../../src/wire/mq_varint.c",
        "../../src/wire/mq_wire.h",
        "../../src/wire/mq_varint.h",
        "layout.c",
    ];
    for f in files {
        println!("cargo:rerun-if-changed={f}");
    }
    cc::Build::new()
        .file(files[0])
        .file(files[1])
        .file(files[4])
        .include("../../src")
        .compile("mq_wire_c");
}
