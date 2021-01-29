  
extern crate env_logger;
extern crate log;

extern crate protoc_rust;

use protoc_rust::Customize;

fn codegen() -> protoc_rust::Codegen {
    let mut codegen = protoc_rust::Codegen::new();
    codegen.out_dir("src/proto")
        .inputs(&["proto/libatbus_protocol.proto"])
        .include("proto")
        .run()
}

fn main() {
    env_logger::init();

    codegen().expect("protoc");
}
