use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

fn main() {
    // Directory with DTS fixtures
    let dts_dir = PathBuf::from("test/dts");
    println!("cargo:rerun-if-changed=test/dts");
    // check the environment
    println!("cargo:rerun-if-changed=build.rs");
    println!("--- check the environment");
    if !command_installed("git") {
        panic!("this test requires git");
    }
    if !command_installed("dtc") {
        panic!("this test requires the device tree compiler(dtc)");
    }
    println!("Creating test folder...");
    let _ = fs::create_dir("test");
    println!("Checking file...");
    let dtb_path = Path::new("test/test.dtb");
    if !dtb_path.is_file() {
        let dts_path = Path::new("test/test.dts");
        if !dts_path.is_file() {
            println!(
                "Downloading test.dts from https://gist.github.com/072176edd54cd207c1d800c25d384cd2.git"
            );

            let download_dir = Path::new("test/.download");
            if download_dir.exists() {
                if let Err(err) = fs::remove_dir_all(download_dir) {
                    panic!("failed to clear temporary download dir: {}", err);
                }
            }

            let status = Command::new("git")
                .arg("clone")
                .arg("https://gist.github.com/072176edd54cd207c1d800c25d384cd2.git")
                .arg(download_dir)
                .stdout(Stdio::null())
                .stdin(Stdio::null())
                .status();

            match status {
                Ok(s) if s.success() => {
                    let downloaded_dts = download_dir.join("test.dts");
                    if !downloaded_dts.is_file() {
                        panic!("downloaded repository did not contain test.dts");
                    }
                    if let Err(err) = fs::copy(&downloaded_dts, dts_path) {
                        panic!("failed to copy downloaded test.dts: {}", err);
                    }
                }
                Ok(s) => {
                    panic!(
                        "git clone exited with status {}, failed to fetch test.dts",
                        s
                    );
                }
                Err(err) => {
                    panic!("failed to run git clone: {}", err);
                }
            }

            if let Err(err) = fs::remove_dir_all(download_dir) {
                println!("warning: failed to remove temporary download dir: {}", err);
            }
        }

        println!("Compiling test.dts file to test.dtb...");
        let status = Command::new("dtc")
            .arg("-I")
            .arg("dts")
            .arg("-O")
            .arg("dtb")
            .arg("-o")
            .arg("test/test.dtb")
            .arg(dts_path)
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(s) => panic!("dtc failed with status {} while compiling test/test.dts", s),
            Err(err) => panic!("failed to run dtc: {}", err),
        }
    }

    // OUT_DIR is provided by Cargo
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Find all .dts files
    let entries = fs::read_dir(&dts_dir).unwrap();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("dts") {
            continue;
        }
        let file_name = path.file_stem().unwrap().to_string_lossy().to_string();
        let out_path = out_dir.join(format!("{}.dtb", file_name));

        // Invalidate when source changes
        println!("cargo:rerun-if-changed={}", path.display());

        // Try to run dtc to build the dtb
        let status = Command::new("dtc")
            .args(["-O", "dtb", "-o"])
            .arg(&out_path)
            .arg(&path)
            .status();

        match status {
            Ok(s) if s.success() => {
                // Success
            }
            Ok(s) => {
                // dtc returned error; fail the build so tests don't silently skip
                panic!(
                    "dtc failed (exit: {}), cannot build {}",
                    s,
                    out_path.display()
                );
            }
            Err(e) => {
                // dtc not present or failed to spawn; fail the build as requested
                panic!(
                    "failed to run dtc: {}. Required to build {}",
                    e,
                    out_path.display()
                );
            }
        }
    }
}

fn command_installed(command_name: &str) -> bool {
    Command::new(command_name)
        .arg("--version")
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}
