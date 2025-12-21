#![crate_type = "bin"]
// xtask/src/main.rs

use core::panic;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

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
    let mut img_path = elf_path.clone();
    img_path.set_file_name("kernel_2712.img");

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
        if arg == "--profile"
            && let Some(value) = iter.next()
        {
            return value.clone();
        }
    }

    if args.iter().any(|arg| arg == "--release") {
        return "release".to_owned();
    }

    "debug".to_owned()
}

fn resolve_gdb_executable() -> Option<String> {
    // Prefer gdb-multiarch if available, fall back to gdb.
    for candidate in &["gdb-multiarch", "gdb"] {
        let status = Command::new(candidate)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Ok(status) = status
            && status.success()
        {
            return Some((*candidate).to_string());
        }
    }
    None
}

#[cfg(unix)]
fn spawn_in_own_pgrp(cmd: &mut Command) -> io::Result<Child> {
    use core::ffi::c_int;
    use std::os::unix::process::CommandExt;

    // SAFETY: This runs in the child just before exec; setpgid is async-signal-safe and
    // we only touch state local to the child process to move it into a new process group.
    unsafe {
        cmd.pre_exec(|| {
            unsafe extern "C" {
                fn setpgid(pid: c_int, pgid: c_int) -> c_int;
            }

            if setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    cmd.spawn()
}

#[cfg(not(unix))]
fn spawn_in_own_pgrp(cmd: &mut Command) -> io::Result<Child> {
    cmd.spawn()
}

#[cfg(unix)]
fn kill_process_tree_best_effort(label: &str, child: &mut Child) {
    use core::ffi::c_int;

    const SIGTERM: c_int = 15;
    const SIGKILL: c_int = 9;

    unsafe extern "C" {
        fn kill(pid: c_int, sig: c_int) -> c_int;
    }

    let pgid = match i32::try_from(child.id()) {
        Ok(pid) => pid,
        Err(_) => {
            eprintln!(
                "Warning: PID {} for {} does not fit into i32; falling back to child.kill()",
                child.id(),
                label
            );
            if let Err(e) = child.kill() {
                eprintln!("Warning: failed to kill {}: {}", label, e);
            }
            let _ = child.wait();
            return;
        }
    };

    let mut wait_for_exit = |deadline: Instant| -> bool {
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to poll {} while terminating process group: {}",
                        label, e
                    );
                    return false;
                }
            }
        }
    };

    let send_signal = |sig: c_int| {
        let res = unsafe { kill(-(pgid as c_int), sig) };
        if res != 0 {
            let e = io::Error::last_os_error();
            eprintln!(
                "Warning: failed to send signal {} to process group {} for {}: {}",
                sig, pgid, label, e
            );
        }
    };

    send_signal(SIGTERM);
    let mut exited = wait_for_exit(Instant::now() + Duration::from_secs(2));

    if !exited {
        send_signal(SIGKILL);
        exited = wait_for_exit(Instant::now() + Duration::from_secs(2));
    }

    if !exited {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
        }
    }

    if !exited {
        eprintln!(
            "Warning: process group {} for {} may still be running after SIGKILL",
            pgid, label
        );
    }
}

#[cfg(not(unix))]
fn kill_process_tree_best_effort(label: &str, child: &mut Child) {
    if let Err(e) = child.kill() {
        eprintln!("Warning: failed to kill {}: {}", label, e);
    }
    let _ = child.wait();
}

#[derive(Debug, Clone, Copy)]
enum FilterState {
    Normal,
    AfterEsc,
    Csi,
}

#[derive(Debug)]
struct AnsiQueryFilter {
    state: FilterState,
    pending: Vec<u8>,
}

impl AnsiQueryFilter {
    const MAX_PENDING: usize = 4096;

    fn new() -> Self {
        Self {
            state: FilterState::Normal,
            pending: Vec::new(),
        }
    }

    fn push_filtered(&mut self, input: &[u8], output: &mut Vec<u8>) {
        for &b in input {
            match self.state {
                FilterState::Normal => {
                    if b == 0x1b {
                        self.pending.clear();
                        self.pending.push(b);
                        self.state = FilterState::AfterEsc;
                    } else {
                        output.push(b);
                    }
                }
                FilterState::AfterEsc => {
                    self.pending.push(b);
                    match b {
                        b'[' => {
                            self.state = FilterState::Csi;
                        }
                        b'Z' => {
                            self.pending.clear();
                            self.state = FilterState::Normal;
                        }
                        _ => {
                            self.flush_pending(output);
                            self.state = FilterState::Normal;
                        }
                    }
                }
                FilterState::Csi => {
                    self.pending.push(b);
                    if Self::is_csi_final(b) {
                        if Self::should_drop_csi(&self.pending, b) {
                            self.pending.clear();
                        } else {
                            self.flush_pending(output);
                        }
                        self.state = FilterState::Normal;
                    } else if Self::is_csi_param_or_intermediate(b) {
                        // Keep buffering until we see a final byte.
                    } else {
                        // Not a valid CSI continuation; flush what we saw.
                        self.flush_pending(output);
                        self.state = FilterState::Normal;
                    }
                }
            }

            if self.pending.len() > Self::MAX_PENDING {
                self.flush_pending(output);
                self.state = FilterState::Normal;
            }
        }
    }

    fn finish_into(&mut self, output: &mut Vec<u8>) {
        if !self.pending.is_empty() {
            output.extend_from_slice(&self.pending);
            self.pending.clear();
        }
        self.state = FilterState::Normal;
    }

    fn flush_pending(&mut self, output: &mut Vec<u8>) {
        if !self.pending.is_empty() {
            output.extend_from_slice(&self.pending);
            self.pending.clear();
        }
        self.state = FilterState::Normal;
    }

    fn should_drop_csi(pending: &[u8], final_byte: u8) -> bool {
        match final_byte {
            b'c' => true,
            b'n' => Self::is_dsr_or_cpr_query(pending),
            _ => false,
        }
    }

    fn is_dsr_or_cpr_query(pending: &[u8]) -> bool {
        // Drop CSI Ps n where the last numeric parameter is 5 (status) or 6 (cursor position),
        // with an optional private marker ('?') after CSI.
        if pending.len() < 3 || pending[0] != 0x1b || pending[1] != b'[' {
            return false;
        }
        if *pending.last().unwrap_or(&0) != b'n' {
            return false;
        }

        let mut params = &pending[2..pending.len() - 1];
        if let Some(b'?') = params.first() {
            params = &params[1..];
        }

        if params.is_empty() {
            return false;
        }

        let mut last_param: Option<u32> = None;
        let mut current: u32 = 0;
        let mut has_digits = false;

        for &b in params {
            match b {
                b'0'..=b'9' => {
                    current = current
                        .saturating_mul(10)
                        .saturating_add(u32::from(b - b'0'));
                    has_digits = true;
                }
                b';' => {
                    if has_digits {
                        last_param = Some(current);
                    } else {
                        last_param = None;
                    }
                    current = 0;
                    has_digits = false;
                }
                _ => return false,
            }
        }

        if has_digits {
            last_param = Some(current);
        }

        matches!(last_param, Some(5) | Some(6))
    }

    fn is_csi_final(b: u8) -> bool {
        (0x40..=0x7e).contains(&b)
    }

    fn is_csi_param_or_intermediate(b: u8) -> bool {
        (0x30..=0x3f).contains(&b) || (0x20..=0x2f).contains(&b)
    }
}

fn pump_filtered_output<R, W>(mut reader: R, mut writer: W)
where
    R: Read,
    W: Write,
{
    let mut buf = [0u8; 4096];
    let mut filtered = Vec::with_capacity(buf.len());
    let mut filter = AnsiQueryFilter::new();

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                filtered.clear();
                filter.push_filtered(&buf[..n], &mut filtered);
                if !filtered.is_empty() {
                    if let Err(e) = writer.write_all(&filtered) {
                        eprintln!("Warning: failed to write child output: {}", e);
                        break;
                    }
                }
                let _ = writer.flush();
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("Warning: failed to read child output: {}", e);
                break;
            }
        }
    }

    filtered.clear();
    filter.finish_into(&mut filtered);
    if !filtered.is_empty() {
        let _ = writer.write_all(&filtered);
    }
    let _ = writer.flush();
}

fn spawn_output_pumps(child: &mut Child) -> (thread::JoinHandle<()>, thread::JoinHandle<()>) {
    let stdout = child
        .stdout
        .take()
        .expect("child stdout should be piped for output forwarding");
    let stderr = child
        .stderr
        .take()
        .expect("child stderr should be piped for output forwarding");

    let stdout_handle = thread::spawn(move || {
        let stdout_handle = io::stdout();
        let mut stdout_lock = stdout_handle.lock();
        pump_filtered_output(stdout, &mut stdout_lock);
    });

    let stderr_handle = thread::spawn(move || {
        let stderr_handle = io::stderr();
        let mut stderr_lock = stderr_handle.lock();
        pump_filtered_output(stderr, &mut stderr_lock);
    });

    (stdout_handle, stderr_handle)
}

fn run_uefi_test_with_backtrace(
    mut cmd: Command,
    label: &str,
    gdb_socket: &str,
    timeout_secs: u64,
) -> i32 {
    eprintln!("Running (UEFI, with gdb-on-timeout): {:?}", cmd);

    let mut child = spawn_in_own_pgrp(&mut cmd)
        .unwrap_or_else(|e| panic!("Failed to spawn cargo test (UEFI) for {}: {}", label, e));
    let (stdout_pump, stderr_pump) = spawn_output_pumps(&mut child);

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    // Poll for completion with timeout.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    break Err(());
                }
                thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                eprintln!(
                    "Error: failed to poll UEFI test process for {}: {}",
                    label, e
                );
                break Err(());
            }
        }
    };

    let exit_code = match status {
        Ok(status) => {
            if status.success() {
                0
            } else {
                status.code().unwrap_or(1)
            }
        }
        Err(()) => {
            eprintln!(
                "Error: UEFI test '{}' did not finish within {}s; assuming hang.",
                label, timeout_secs
            );
            eprintln!(
                "Attempting to capture guest state via gdb (socket: {})...",
                gdb_socket
            );

            if let Some(gdb) = resolve_gdb_executable() {
                let mut gdb_cmd = Command::new(&gdb);
                gdb_cmd
                    .arg("-q")
                    .arg("-ex")
                    .arg("set pagination off")
                    .arg("-ex")
                    .arg(format!("target remote {}", gdb_socket))
                    .arg("-ex")
                    .arg("set confirm off")
                    .arg("-ex")
                    .arg("interrupt")
                    .arg("-ex")
                    .arg("info registers")
                    .arg("-ex")
                    .arg("bt")
                    .arg("-ex")
                    .arg("x/16i $pc")
                    .arg("-ex")
                    .arg("quit")
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
                eprintln!("Running gdb: {:?}", gdb_cmd);
                match gdb_cmd.status() {
                    Ok(s) => {
                        eprintln!("gdb finished with status: {:?}", s);
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to execute gdb for {}: {}", label, e);
                    }
                }
            } else {
                eprintln!(
                    "Warning: no suitable gdb executable found in PATH; skip backtrace dump."
                );
            }

            eprintln!("Killing hung UEFI test process for '{}'", label);
            kill_process_tree_best_effort(label, &mut child);

            // 124 = timeout and consistent with `timeout` command conventions.
            124
        }
    };
    let _ = stdout_pump.join();
    let _ = stderr_pump.join();

    exit_code
}

fn run_guest_test_with_timeout(
    mut cmd: Command,
    label: &str,
    timeout_secs: u64,
    kind: &str,
) -> i32 {
    eprintln!("Running ({} with internal timeout): {:?}", kind, cmd);

    let mut child = spawn_in_own_pgrp(&mut cmd)
        .unwrap_or_else(|e| panic!("Failed to spawn cargo test ({}) for {}: {}", kind, label, e));
    let (stdout_pump, stderr_pump) = spawn_output_pumps(&mut child);

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    break Err(());
                }
                thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                eprintln!(
                    "Error: failed to poll {} process for {}: {}",
                    kind, label, e
                );
                break Err(());
            }
        }
    };

    let exit_code = match status {
        Ok(status) => {
            if status.success() {
                0
            } else {
                status.code().unwrap_or(1)
            }
        }
        Err(()) => {
            eprintln!(
                "Error: {} '{}' did not finish within {}s; assuming hang.",
                kind, label, timeout_secs
            );
            eprintln!("Killing hung {} process for '{}'", kind, label);
            kill_process_tree_best_effort(label, &mut child);
            124
        }
    };
    let _ = stdout_pump.join();
    let _ = stderr_pump.join();

    exit_code
}

fn run_uefi_test_with_timeout(cmd: Command, label: &str, timeout_secs: u64) -> i32 {
    run_guest_test_with_timeout(cmd, label, timeout_secs, "UEFI test")
}

fn run_uboot_test_with_timeout(cmd: Command, label: &str, timeout_secs: u64) -> i32 {
    run_guest_test_with_timeout(cmd, label, timeout_secs, "U-Boot test")
}

fn test(args: &[String]) {
    fn parse_test_args(args: &[String]) -> (Vec<String>, Vec<String>) {
        let mut forward_args = Vec::new();
        let mut package_filters = Vec::new();
        let mut i = 0;

        while i < args.len() {
            let arg = &args[i];
            if arg == "--" {
                forward_args.extend(args[i..].iter().cloned());
                break;
            } else if let Some(pkg) = arg.strip_prefix("--package=") {
                package_filters.push(pkg.to_string());
                i += 1;
                continue;
            } else if arg == "-p" || arg == "--package" {
                if let Some(pkg) = args.get(i + 1) {
                    package_filters.push(pkg.clone());
                    i += 2;
                    continue;
                }
            } else if arg.starts_with("-p") && arg.len() > 2 {
                package_filters.push(arg[2..].to_string());
                i += 1;
                continue;
            }

            forward_args.push(arg.clone());
            i += 1;
        }

        (forward_args, package_filters)
    }

    let (test_args, package_filters) = parse_test_args(args);

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
    let mut uboot_tests: Vec<(String, String, String, Vec<String>)> = Vec::new();

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
            Some("uboot") | Some("u-boot") => {
                let (pkg, testname, testscript) = (parts.next(), parts.next(), parts.next());
                match (pkg, testname, testscript) {
                    (Some(p), Some(t), Some(s)) => {
                        uboot_tests.push((p.to_string(), t.to_string(), s.to_string(), Vec::new()))
                    }
                    _ => eprintln!(
                        "xtest.txt:{}: expected: uboot <package> <testname> <testscript>",
                        lineno + 1
                    ),
                }
            }
            Some(other) => {
                eprintln!(
                    "xtest.txt:{}: unknown kind '{}'; expected 'std', 'uefi', or 'uboot'",
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

    fn scripts_need_sudo(
        tests: &[(String, String, String, Vec<String>)],
        repo_root: &PathBuf,
        kind: &str,
    ) -> bool {
        for (_, _, testscript, _) in tests {
            let runner_path = repo_root.join(testscript);
            match fs::read_to_string(&runner_path) {
                Ok(content) => {
                    if content.contains("sudo") {
                        eprintln!(
                            "Detected use of sudo in {} runner script: {}",
                            kind,
                            runner_path.display()
                        );
                        return true;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to read {} runner script {}: {}",
                        kind,
                        runner_path.display(),
                        e
                    );
                }
            }
        }
        false
    }

    fn sudo_warmup() {
        let sudo_check = Command::new("sudo")
            .arg("-V")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match sudo_check {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("Warning: 'sudo' not found; tests that require sudo may fail.");
                return;
            }
            Err(e) => {
                eprintln!("Warning: failed to check availability of 'sudo': {}", e);
                return;
            }
            Ok(_) => {}
        }

        match Command::new("sudo")
            .arg("-n")
            .arg("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => {
                eprintln!("Reusing existing sudo credential cache.");
                return;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Warning: failed to check sudo credential cache: {}", e);
            }
        }

        eprintln!(
            "Running 'sudo -v' to warm up credentials (you may be prompted for your password)..."
        );
        let status = Command::new("sudo")
            .arg("-v")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .unwrap_or_else(|e| panic!("Failed to execute 'sudo -v': {}", e));

        if !status.success() {
            let code = status.code().unwrap_or(1);
            eprintln!(
                "Error: 'sudo -v' failed (code {}); tests that require sudo cannot be run.",
                code
            );
            std::process::exit(code);
        }
    }

    if !package_filters.is_empty() {
        std_crates.retain(|(pkg, _)| package_filters.contains(pkg));
        uefi_tests.retain(|(pkg, _, _, _)| package_filters.contains(pkg));
        uboot_tests.retain(|(pkg, _, _, _)| package_filters.contains(pkg));

        if std_crates.is_empty() && uefi_tests.is_empty() && uboot_tests.is_empty() {
            eprintln!(
                "No entries in xtest.txt match specified packages: {:?}",
                package_filters
            );
            std::process::exit(1);
        }

        eprintln!(
            "Filtered test plan to packages: {:?} ({} std, {} uefi, {} uboot)",
            package_filters,
            std_crates.len(),
            uefi_tests.len(),
            uboot_tests.len()
        );
    }

    // Accumulate results across all tests
    let mut passed: Vec<String> = Vec::new();
    let mut failed: Vec<(String, i32)> = Vec::new();

    if scripts_need_sudo(&uefi_tests, &repo_root, "UEFI")
        || scripts_need_sudo(&uboot_tests, &repo_root, "U-Boot")
    {
        sudo_warmup();
    }

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
            .args(&test_args)
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

    // Decide whether to enable gdb-on-timeout for UEFI tests.
    let enable_uefi_backtrace = std::env::var("XTASK_UEFI_GDB_DUMP_ON_TIMEOUT")
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or_else(|_| std::env::var("CI").is_ok());

    // Run UEFI tests
    for (pkg, testname, testscript, extra) in uefi_tests {
        let runner_path = repo_root.join(testscript);
        let runner = runner_path
            .to_str()
            .expect("runner path contains invalid UTF-8");

        let label = format!("uefi:{}::{}", pkg, testname);
        eprintln!(
            "\n--- Running UEFI test for: {}::{}, runner: {} ---",
            pkg, testname, runner
        );

        // Prepare gdbstub socket path when backtrace dump is enabled.
        let gdb_socket = if enable_uefi_backtrace {
            Some(format!(
                "/tmp/aarch64_hv_qemu_gdb_{}_{}.sock",
                pkg.replace('/', "_"),
                testname.replace('/', "_")
            ))
        } else {
            None
        };

        let mut cmd = {
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
            .args(&test_args)
            .env("CARGO_TARGET_AARCH64_UNKNOWN_UEFI_RUNNER", runner)
            .env("CARGO_TERM_COLOR", "always")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref socket) = gdb_socket {
            cmd.env("XTASK_QEMU_GDB_SOCKET", socket);
        }

        let code = if let Some(ref socket) = gdb_socket {
            run_uefi_test_with_backtrace(cmd, &label, socket, 60)
        } else {
            run_uefi_test_with_timeout(cmd, &label, 30)
        };

        if code == 0 {
            passed.push(label);
        } else {
            eprintln!("Error: UEFI test failed for {} with code {}", pkg, code);
            failed.push((label, code));
        }
    }

    // Run U-Boot tests
    for (pkg, testname, testscript, extra) in uboot_tests {
        let runner_path = repo_root.join(testscript);
        let runner = runner_path
            .to_str()
            .expect("runner path contains invalid UTF-8");

        let test_lds_path = repo_root.join("test.lds");
        let test_lds = test_lds_path
            .to_str()
            .expect("test linker path contains invalid UTF-8")
            .to_string();

        let label = format!("uboot:{}::{}", pkg, testname);
        eprintln!(
            "\n--- Running U-Boot test for: {}::{}, runner: {} ---",
            pkg, testname, runner
        );

        let mut cmd = Command::new("cargo");

        // Give each U-Boot test its own fresh target dir to avoid mixing build-std
        // artifacts (duplicate core lang items).
        let sanitized_label = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>();
        let target_dir = std::env::temp_dir()
            .join("aarch64_hv_uboot_tests")
            .join(format!("{}_{}", sanitized_label, std::process::id()));
        let _ = fs::remove_dir_all(&target_dir);

        let rustflags = {
            let mut parts = Vec::new();
            if let Ok(existing) = std::env::var("RUSTFLAGS") {
                parts.push(existing);
            }
            parts.push("-C panic=abort -Zpanic_abort_tests".to_string());
            parts.push("-C relocation-model=static".to_string());
            parts.push(format!("-C link-arg=-T{}", test_lds));
            parts.join(" ")
        };

        cmd.arg("test")
            .arg("--target")
            .arg("aarch64-unknown-none-softfloat")
            .arg("-p")
            .arg(&pkg)
            .arg("--test")
            .arg(&testname)
            .args(&extra)
            .args(&test_args)
            .env("CARGO_TARGET_AARCH64_UNKNOWN_NONE_SOFTFLOAT_RUNNER", runner)
            .env("RUSTFLAGS", rustflags)
            .env("CARGO_PROFILE_TEST_PANIC", "abort")
            .env("CARGO_PROFILE_DEV_PANIC", "abort")
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TARGET_DIR", &target_dir)
            .env("CARGO_TERM_COLOR", "always")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let code = run_uboot_test_with_timeout(cmd, &label, 300);
        if code == 0 {
            passed.push(label);
        } else {
            eprintln!("Error: U-Boot test failed for {} with code {}", pkg, code);
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
        eprintln!("All tests passed (host + UEFI + U-Boot)");
    }
}

#[cfg(test)]
mod tests {
    use super::AnsiQueryFilter;

    fn filter_chunks(chunks: &[&[u8]]) -> Vec<u8> {
        let mut filter = AnsiQueryFilter::new();
        let mut out = Vec::new();
        for chunk in chunks {
            filter.push_filtered(chunk, &mut out);
        }
        filter.finish_into(&mut out);
        out
    }

    #[test]
    fn strips_cpr_sequence() {
        let out = filter_chunks(&[b"abc\x1b[6nxyz"]);
        assert_eq!(out, b"abcxyz");
    }

    #[test]
    fn strips_status_report_query() {
        let out = filter_chunks(&[b"\x1b[5n"]);
        assert_eq!(out, b"");
    }

    #[test]
    fn strips_device_attributes_query() {
        let out = filter_chunks(&[b"\x1b[0c"]);
        assert_eq!(out, b"");
    }

    #[test]
    fn strips_decid_sequence() {
        let out = filter_chunks(&[b"\x1bZ"]);
        assert_eq!(out, b"");
    }

    #[test]
    fn strips_private_cpr_sequence() {
        let out = filter_chunks(&[b"before\x1b[?6nafter"]);
        assert_eq!(out, b"beforeafter");
    }

    #[test]
    fn preserves_sgr_sequences() {
        let payload = b"\x1b[31mred\x1b[0m";
        let out = filter_chunks(&[payload]);
        assert_eq!(out, payload);
    }

    #[test]
    fn preserves_cursor_positioning_sequences() {
        let payload = b"\x1b[10;20Hmove";
        let out = filter_chunks(&[payload]);
        assert_eq!(out, payload);
    }

    #[test]
    fn preserves_non_query_csi_n_sequences() {
        let payload = b"\x1b[42n";
        let out = filter_chunks(&[payload]);
        assert_eq!(out, payload);
    }

    #[test]
    fn handles_chunk_boundaries() {
        let out = filter_chunks(&[b"abc\x1b[", b"6nxyz"]);
        assert_eq!(out, b"abcxyz");
    }
}
