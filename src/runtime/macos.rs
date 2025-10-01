use crate::policy::NetworkPolicy;
use tokio::process::Command;

pub async fn execute_with_network_control(
    command: &str,
    args: &[&str],
    policy: &NetworkPolicy,
) -> Result<i32, crate::error::MoriError> {
    use crate::policy::AllowPolicy;

    // For macOS, we use sandbox-exec to control network access
    // - AllowPolicy::All: run command directly
    // - AllowPolicy::Entries with empty lists: use sandbox-exec with network denial
    // - AllowPolicy::Entries with non-empty lists: return error (not supported on macOS)

    let mut child = match &policy.policy {
        AllowPolicy::All => {
            // Allow all network: execute command directly
            Command::new(command).args(args).spawn()?
        }
        AllowPolicy::Entries {
            allowed_ipv4,
            allowed_domains,
        } => {
            // Check if any entries are specified
            if !allowed_ipv4.is_empty() || !allowed_domains.is_empty() {
                return Err(crate::error::MoriError::EntryBasedPolicyNotSupported);
            }
            // Empty entries means deny all network
            let sandbox_profile = create_network_deny_profile();
            Command::new("sandbox-exec")
                .arg("-p")
                .arg(&sandbox_profile)
                .arg(command)
                .args(args)
                .spawn()
                .map_err(crate::error::MoriError::Io)?
        }
    };

    let status = child.wait().await.map_err(crate::error::MoriError::Io)?;

    Ok(status.code().unwrap_or(1))
}

/// Create a sandbox profile that denies network access
fn create_network_deny_profile() -> String {
    // Sandbox profile using SBPL (Sandbox Profile Language)
    // This profile:
    // - Allows all operations by default
    // - Explicitly denies only network operations
    r#"(version 1)
(allow default)
(deny network*)"#
        .to_string()
}
