use std::env;
use libatbus_protoc_bin;

fn main() {
    let (mut codegen, protobuf_include_dir) = libatbus_protoc_bin::codegen();

    let output_dir = env::current_dir().unwrap().join("src").join("proto");
    let _ = codegen
        // .btree_map([".atbus.protocol"])
        .out_dir(output_dir)
        .compile_protos(
            &[
                "proto/libatbus_options.proto",
                "proto/libatbus_protocol.proto",
            ],
            &["proto", &protobuf_include_dir]).unwrap();

    println!("cargo:rerun-if-changed=proto/libatbus_options.proto");
    println!("cargo:rerun-if-changed=proto/libatbus_protocol.proto");
    println!("cargo:rerun-if-changed=proto/build.rs");
}
