use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        // Skip eBPF compilation when building for non-Linux targets (e.g., macOS host).
        return Ok(());
    }

    println!("cargo:rerun-if-changed=mori-bpf/src");
    println!("cargo:rerun-if-changed=mori-bpf/Cargo.toml");

    let metadata = aya_build::cargo_metadata::MetadataCommand::new()
        .manifest_path("Cargo.toml")
        .exec()?;

    let package = metadata
        .packages
        .into_iter()
        .find(|pkg| pkg.name.as_str() == "mori-bpf-programs")
        .ok_or("mori-bpf-programs package not found in workspace")?;

    let out_dir: PathBuf = env::var("OUT_DIR")?.into();
    let elf_path = out_dir.join("mori-bpf");

    if elf_path.exists() {
        if elf_path.is_dir() {
            fs::remove_dir_all(&elf_path)?;
        } else {
            fs::remove_file(&elf_path)?;
        }
    }

    let saved_rustflags = env::var("RUSTFLAGS").ok();
    let saved_encoded_rustflags = env::var("CARGO_ENCODED_RUSTFLAGS").ok();

    if saved_rustflags.is_some() {
        // cargo llvm-cov injects -Z instrument-coverage via RUSTFLAGS so that host binaries link
        // the profiler runtime and emit coverage data. The BPF target has no such runtime, so we
        // temporarily clear the flag to let the eBPF build succeed.
        unsafe { env::remove_var("RUSTFLAGS") };
    }
    if saved_encoded_rustflags.is_some() {
        // Same reasoning as above, but for the encoded variant that cargo forwards.
        unsafe { env::remove_var("CARGO_ENCODED_RUSTFLAGS") };
    }

    let build_result = aya_build::build_ebpf([package]);

    if let Some(value) = saved_rustflags {
        unsafe { env::set_var("RUSTFLAGS", value) };
    }
    if let Some(value) = saved_encoded_rustflags {
        unsafe { env::set_var("CARGO_ENCODED_RUSTFLAGS", value) };
    }

    build_result?;
    println!("cargo:rustc-env=MORI_BPF_ELF={}", elf_path.display());

    Ok(())
}
