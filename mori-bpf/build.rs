use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let vmlinux_rs = out_dir.join("vmlinux.rs");

    // Generate vmlinux.rs using aya-tool
    // Specify the types we need: file and path
    let status = Command::new("aya-tool")
        .args(["generate", "file", "path"])
        .output()
        .expect(
            "Failed to execute aya-tool. Make sure aya-tool is installed (cargo install aya-tool)",
        );

    if !status.status.success() {
        panic!(
            "aya-tool failed:\nstderr: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    // Write generated vmlinux.rs to OUT_DIR
    fs::write(&vmlinux_rs, status.stdout).expect("Failed to write vmlinux.rs");

    // Tell cargo to rerun this build script if /sys/kernel/btf/vmlinux changes
    // (though in practice this rarely changes without a reboot)
    println!("cargo:rerun-if-changed=/sys/kernel/btf/vmlinux");
}
