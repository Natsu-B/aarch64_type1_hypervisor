use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=aarch64.lds");
    println!("cargo:rerun-if-env-changed=XTASK_BUILD");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    println!("cargo:rustc-link-search={}", crate_dir);

    let rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    let encoded_rustflags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let has_test_lds = rustflags.contains("test.lds") || encoded_rustflags.contains("test.lds");
    if !has_test_lds {
        println!("cargo:rustc-link-arg=-Taarch64.lds");
    }
}
