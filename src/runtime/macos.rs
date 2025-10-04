use crate::policy::{AccessMode, Policy};
use tokio::process::Command;

pub async fn execute_with_control(
    command: &str,
    args: &[&str],
    policy: &Policy,
) -> Result<i32, crate::error::MoriError> {
    use crate::policy::AllowPolicy;

    // For macOS, we use sandbox-exec to control network and file access
    // Note: macOS does not support domain-based network filtering via sandbox-exec,
    // so we can only allow all or deny all network access.

    let needs_sandbox =
        !matches!(policy.network.policy, AllowPolicy::All) || !policy.file.denied_paths.is_empty();

    let mut child = if needs_sandbox {
        // Use sandbox-exec with generated profile
        let sandbox_profile = create_sandbox_profile(policy);
        Command::new("sandbox-exec")
            .arg("-p")
            .arg(sandbox_profile)
            .arg(command)
            .args(args)
            .spawn()
            .map_err(crate::error::MoriError::Io)?
    } else {
        // No restrictions: execute command directly
        Command::new(command).args(args).spawn()?
    };

    let status = child.wait().await.map_err(crate::error::MoriError::Io)?;

    Ok(status.code().unwrap_or(1))
}

/// Create a sandbox profile based on the policy
fn create_sandbox_profile(policy: &Policy) -> String {
    use crate::policy::AllowPolicy;

    // Use (import "system.sb") + (deny default) approach like sbx
    // This is required because (allow default) doesn't work with deny rules
    let mut profile = String::from(
        r#"(version 1)
(import "system.sb")
(deny default)
"#,
    );

    // Allow reading system libraries for process execution
    profile.push_str(
        r#"(allow file-read*
(subpath "/opt/local/lib")
(subpath "/usr/lib")
(subpath "/usr/local/lib")
)"#,
    );

    // Allow all file operations by default (deny-list mode)
    profile.push_str("(allow file*)\n");

    // Add file access denials using (deny file-*) rules
    for (path, mode) in &policy.file.denied_paths {
        let path_str = path.display().to_string();
        match mode {
            AccessMode::Read => {
                // Deny read operations only
                profile.push_str(&format!(
                    "(deny file-read* (subpath \"{}\"))\n",
                    escape_path(&path_str)
                ));
            }
            AccessMode::Write => {
                // Deny write operations only
                profile.push_str(&format!(
                    "(deny file-write* (subpath \"{}\"))\n",
                    escape_path(&path_str)
                ));
            }
            AccessMode::ReadWrite => {
                // Deny both read and write operations
                profile.push_str(&format!(
                    "(deny file* (subpath \"{}\"))\n",
                    escape_path(&path_str)
                ));
            }
        }
    }

    // Add network denial if needed (at the end to override default allow)
    if !matches!(policy.network.policy, AllowPolicy::All) {
        profile.push_str("(deny network*)\n");
    }

    // Allow process execution for all commands
    profile.push_str("(allow process-exec*)\n");

    profile
}

/// Escape special characters in file paths for SBPL (Sandbox Profile Language)
fn escape_path(path: &str) -> String {
    // In SBPL, backslashes and quotes need to be escaped
    path.replace('\\', "\\\\").replace('"', "\\\"")
}
