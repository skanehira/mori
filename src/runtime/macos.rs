use crate::policy::Policy;
use tokio::process::Command;

pub async fn execute_with_control(
    command: &str,
    args: &[&str],
    policy: &Policy,
) -> Result<i32, crate::error::MoriError> {
    use crate::policy::AllowPolicy;

    // For macOS, we use sandbox-exec to control network access
    // - AllowPolicy::All: run command directly (allow all network)
    // - Otherwise (AllowPolicy::Entries): use sandbox-exec with network denial (deny all network)
    //
    // Note: macOS does not support domain-based filtering via sandbox-exec,
    // so we can only allow all or deny all network access.

    let mut child = match &policy.network.policy {
        AllowPolicy::All => {
            // Allow all network: execute command directly
            Command::new(command).args(args).spawn()?
        }
        _ => {
            // Deny all network: use sandbox-exec
            let sandbox_profile = r#"(version 1)
(allow default)
(deny network*)"#;
            Command::new("sandbox-exec")
                .arg("-p")
                .arg(sandbox_profile)
                .arg(command)
                .args(args)
                .spawn()
                .map_err(crate::error::MoriError::Io)?
        }
    };

    let status = child.wait().await.map_err(crate::error::MoriError::Io)?;

    Ok(status.code().unwrap_or(1))
}
