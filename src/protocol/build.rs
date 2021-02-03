use std::fs;

extern crate env_logger;
extern crate log;

extern crate protoc_bin_vendored;
extern crate protoc_rust;

fn codegen() -> protoc_rust::Codegen {
    let mut codegen = protoc_rust::Codegen::new();
    codegen
        .protoc_path(protoc_bin_vendored::protoc_bin_path().unwrap())
        .out_dir("src/proto")
        .inputs(&[
            "proto/libatbus_options.proto",
            "proto/libatbus_protocol.proto",
        ])
        .include("proto");

    codegen
}

fn main() {
    env_logger::init();

    codegen().run().expect("protoc");
    fs::write(
        "src/proto/mod.rs",
        "
pub mod libatbus_options;
pub mod libatbus_protocol;
",
    )
    .unwrap();

    println!("cargo:rerun-if-changed=proto/libatbus_options.proto");
    println!("cargo:rerun-if-changed=proto/libatbus_protocol.proto");
}
