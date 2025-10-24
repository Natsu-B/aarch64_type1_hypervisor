#![crate_type = "bin"]
// xtask/src/main.rs

use core::panic;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

fn main() {
    // Skip the executable name (xtask)
    let mut args = std::env::args().skip(1);

    let command = args.next();

    let remaining_args: Vec<String> = args.collect();

    match command.as_deref() {
        Some("build") => {
            let _ = build(&remaining_args).unwrap();
        }
        Some("run") => {
            run(&remaining_args).unwrap();
        }
        Some("test") => test(&remaining_args),
        Some(cmd) => {
            eprintln!("Error: Unknown command '{}'", cmd);
            eprintln!("Usage: cargo xtask [build|run|test] [args...]");
            std::process::exit(1);
        }
        None => {
            eprintln!("Error: No command provided.");
            eprintln!("Usage: cargo xtask [build|run|test] [args...]");
            std::process::exit(1);
        }
    }
}

fn build(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("rpi5") => build_rpi5(&args[1..]),
        _ => build_bootloader(args),
    }
}

fn build_bootloader(args: &[String]) -> Result<String, String> {
    let pkg = "elf-hypervisor";
    eprintln!("\n--- Building bootloader package: {} ---", pkg);
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-Z")
        .arg("build-std=core,alloc,compiler_builtins")
        .arg("-Z")
        .arg("build-std-features=compiler-builtins-mem")
        .arg("-p")
        .arg(pkg)
        .arg("--target")
        .arg("aarch64-unknown-none-softfloat")
        .args(args)
        .env("XTASK_BUILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    eprintln!("Running: {:?}", cmd);
    let status = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to spawn cargo build for {}: {}", pkg, e))
        .wait()
        .unwrap_or_else(|e| panic!("Failed to wait for cargo build for {}: {}", pkg, e));
    if !status.success() {
        eprintln!(
            "Error: cargo build failed for package '{}' with status: {:?}",
            pkg, status
        );
        std::process::exit(status.code().unwrap_or(1));
    }

    eprintln!("\n--- Bootloader built successfully ---");
    let profile = resolve_profile(args);
    copy_artifact_to_bin("elf-hypervisor", "elf-hypervisor.elf", &profile)
}

fn build_rpi5(args: &[String]) -> Result<String, String> {
    let pkg = "rpi_boot";
    eprintln!("\n--- Building rpi5 package: {} ---", pkg);
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-Z")
        .arg("build-std=core,alloc,compiler_builtins")
        .arg("-Z")
        .arg("build-std-features=compiler-builtins-mem")
        .arg("-p")
        .arg(pkg)
        .arg("--target")
        .arg("aarch64-unknown-none-softfloat")
        .args(args)
        .env("XTASK_BUILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    eprintln!("Running: {:?}", cmd);
    let status = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to spawn cargo build for {}: {}", pkg, e))
        .wait()
        .unwrap_or_else(|e| panic!("Failed to wait for cargo build for {}: {}", pkg, e));
    if !status.success() {
        eprintln!(
            "Error: cargo build failed for package '{}' with status: {:?}",
            pkg, status
        );
        std::process::exit(status.code().unwrap_or(1));
    }

    eprintln!("\n--- rpi_boot built successfully ---");
    let profile = resolve_profile(args);
    copy_artifact_to_bin("rpi_boot", "rpi_boot.elf", &profile)
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("rpi5") => run_rpi5(&args[1..]),
        _ => {
            run_default(args);
        }
    }
}

fn run_default(args: &[String]) -> ! {
    let binary_path = build_bootloader(args).unwrap_or_else(|err| {
        panic!("Failed to build bootloader: {}", err);
    });

    eprintln!("\n--- Running ./run.sh ---");
    use std::os::unix::process::CommandExt;
    let err = Command::new("./run.sh").arg(&binary_path).args(args).exec();
    panic!("Failed to exec ./run.sh: {}", err);
}

fn run_rpi5(args: &[String]) -> Result<(), String> {
    let elf_path = PathBuf::from(build_rpi5(args)?);
    let img_path = elf_path.with_extension("img");

    eprintln!(
        "\n--- Converting {} to raw image: {} ---",
        elf_path.display(),
        img_path.display()
    );

    let status = Command::new("rust-objcopy")
        .arg("-O")
        .arg("binary")
        .arg(&elf_path)
        .arg(&img_path)
        .status()
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => "rust-objcopy is required but not available in PATH. \
                 Enter the nix develop shell or install rust-objcopy."
                .to_string(),
            _ => format!("Failed to launch rust-objcopy: {}", err),
        })?;

    if status.success() {
        eprintln!("Image generated at {}", img_path.display());
        Ok(())
    } else {
        Err(format!("rust-objcopy exited with status {}", status))
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    std::env::current_dir().map_err(|e| format!("Failed to determine workspace root: {}", e))
}

fn copy_artifact_to_bin(
    binary_name: &str,
    destination_name: &str,
    profile: &str,
) -> Result<String, String> {
    let workspace = workspace_root()?;
    let artifact_path = workspace
        .join("target")
        .join("aarch64-unknown-none-softfloat")
        .join(profile)
        .join(binary_name);

    let bin_dir = workspace.join("bin");
    fs::create_dir_all(&bin_dir).map_err(|e| format!("Failed to create bin directory: {}", e))?;

    let destination = bin_dir.join(destination_name);
    fs::copy(&artifact_path, &destination).map_err(|e| {
        format!(
            "Failed to copy {} to {}: {}",
            artifact_path.display(),
            destination.display(),
            e
        )
    })?;

    Ok(destination.to_string_lossy().into_owned())
}

fn resolve_profile(args: &[String]) -> String {
    for arg in args {
        if let Some(value) = arg.strip_prefix("--profile=") {
            return value.to_owned();
        }
    }

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--profile" {
            if let Some(value) = iter.next() {
                return value.clone();
            }
        }
    }

    if args.iter().any(|arg| arg == "--release") {
        return "release".to_owned();
    }

    "debug".to_owned()
}

fn test(args: &[String]) {
    // Detect host triple
    let host_output = Command::new("rustc")
        .arg("--print")
        .arg("host-tuple")
        .output()
        .expect("Failed to run rustc --print host-tuple");
    let host_tuple = String::from_utf8(host_output.stdout)
        .expect("Invalid UTF-8 from rustc --print host-tuple")
        .trim()
        .to_string();

    eprintln!("Detected host target: {}", host_tuple);

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../");
    let plan_path = repo_root.join("xtest.txt");
    let plan = std::fs::read_to_string(&plan_path).ok();

    let mut std_crates: Vec<(String, Vec<String>)> = Vec::new();
    let mut uefi_tests: Vec<(String, String, String, Vec<String>)> = Vec::new();

    let plan_text = plan.expect("require xtest.txt");
    for (lineno, line) in plan_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("std") => {
                if let Some(pkg) = parts.next() {
                    std_crates.push((pkg.to_string(), Vec::new()));
                } else {
                    eprintln!("xtest.txt:{}: missing package after 'std'", lineno + 1);
                }
            }
            Some("uefi") => {
                let (pkg, testname, testscript) = (parts.next(), parts.next(), parts.next());
                match (pkg, testname, testscript) {
                    (Some(p), Some(t), Some(s)) => {
                        uefi_tests.push((p.to_string(), t.to_string(), s.to_string(), Vec::new()))
                    }
                    _ => eprintln!(
                        "xtest.txt:{}: expected: uefi <package> <testname> <testscript>",
                        lineno + 1
                    ),
                }
            }
            Some(other) => {
                eprintln!(
                    "xtest.txt:{}: unknown kind '{}'; expected 'std' or 'uefi'",
                    lineno + 1,
                    other
                );
            }
            None => {}
        }
    }

    // Helper: build 'timeout' wrapper if available
    fn timeout_prefix(secs: u64) -> Option<Vec<String>> {
        // Detect availability
        let out = Command::new("timeout").arg("--help").output();
        if let Ok(o) = out {
            let help = String::from_utf8_lossy(&o.stdout);
            if help.contains("--foreground") {
                return Some(vec![
                    "timeout".into(),
                    "--foreground".into(),
                    "-k".into(),
                    "5s".into(),
                    format!("{}s", secs),
                ]);
            } else {
                return Some(vec!["timeout".into(), format!("{}", secs)]);
            }
        }
        None
    }

    // Accumulate results across all tests
    let mut passed: Vec<String> = Vec::new();
    let mut failed: Vec<(String, i32)> = Vec::new();

    // Run std tests (each with 30s timeout if available)
    for (pkg, extra) in std_crates {
        eprintln!("\n--- Running host tests for: {} ---", pkg);
        let mut cmd = if let Some(mut prefix) = timeout_prefix(30) {
            let mut c = Command::new(prefix.remove(0));
            for p in prefix {
                c.arg(p);
            }
            c.arg("cargo");
            c.arg("test");
            c
        } else {
            let mut c = Command::new("cargo");
            c.arg("test");
            c
        };

        cmd.arg("--target")
            .arg(&host_tuple)
            .arg("-p")
            .arg(&pkg)
            .args(&extra)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        eprintln!("Running: {:?}", cmd);
        let status = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn cargo test for {}: {}", pkg, e))
            .wait()
            .unwrap_or_else(|e| panic!("Failed to wait for cargo test for {}: {}", pkg, e));
        if status.success() {
            passed.push(format!("std:{}", pkg));
        } else {
            let code = status.code().unwrap_or(1);
            eprintln!("Error: Tests failed for package: {} (code {})", pkg, code);
            failed.push((format!("std:{}", pkg), code));
        }
    }

    // Run UEFI tests (rely on runner's internal timeout)
    for (pkg, testname, testscript, extra) in uefi_tests {
        let runner_path = repo_root.join(testscript);
        let runner = runner_path
            .to_str()
            .expect("runner path contains invalid UTF-8");
        eprintln!(
            "\n--- Running UEFI test for: {}::{}, runner: {} ---",
            pkg, testname, runner
        );
        let mut cmd = if let Some(mut prefix) = timeout_prefix(30) {
            let mut c = Command::new(prefix.remove(0));
            for p in prefix {
                c.arg(p);
            }
            c.arg("cargo");
            c.arg("test");
            c
        } else {
            let mut c = Command::new("cargo");
            c.arg("test");
            c
        };
        cmd.arg("--target")
            .arg("aarch64-unknown-uefi")
            .arg("-p")
            .arg(&pkg)
            .arg("--test")
            .arg(&testname)
            .args(&extra)
            .args(args)
            .env("CARGO_TARGET_AARCH64_UNKNOWN_UEFI_RUNNER", runner)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        eprintln!("Running: {:?}", cmd);
        let status = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn cargo test (UEFI) for {}: {}", pkg, e))
            .wait()
            .unwrap_or_else(|e| panic!("Failed to wait for cargo test (UEFI) for {}: {}", pkg, e));
        let label = format!("uefi:{}::{}", pkg, testname);
        if status.success() {
            passed.push(label);
        } else {
            let code = status.code().unwrap_or(1);
            eprintln!("Error: UEFI test failed for {} with code {}", pkg, code);
            failed.push((label, code));
        }
    }

    // Summary
    eprintln!("\n===== Test Summary =====");
    if !passed.is_empty() {
        eprintln!("Passed ({}):", passed.len());
        for p in &passed {
            eprintln!("  - {}", p);
        }
    } else {
        eprintln!("Passed: 0");
    }
    if !failed.is_empty() {
        eprintln!("Failed ({}):", failed.len());
        for (f, code) in &failed {
            eprintln!("  - {} (code {})", f, code);
        }
        std::process::exit(1);
    } else {
        eprintln!("All tests passed (host + UEFI)");
    }
}
