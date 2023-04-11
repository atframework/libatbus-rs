// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::env;
use std::fs::create_dir_all;
use std::path::Path;

extern crate cbindgen;

fn generate_ffi_cpp() {
    let output_name = "c";
    let output_dir = env::current_dir()
        .unwrap()
        .join(output_name)
        .join("include")
        .join("libatbus");

    let _ = create_dir_all(&output_dir).unwrap();
    let dst = Path::new(&output_dir).join("libatbus_rs.h");
    let manifest_dir = env::current_dir().unwrap();

    let configure_file = env::current_dir()
        .unwrap()
        .join(output_name)
        .join("cbindgen.toml");
    cbindgen::Builder::new()
        .with_crate(&manifest_dir)
        .with_config(cbindgen::Config::from_file(configure_file).unwrap())
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(dst);

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir
            .join(output_name)
            .join("cbindgen.toml")
            .display()
    );
}

fn main() {
    generate_ffi_cpp();
}
