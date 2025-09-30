#[cfg(target_os = "linux")]
mod linux;
pub use linux::execute_with_network_control;

#[cfg(target_os = "macos")]
mod macos;
