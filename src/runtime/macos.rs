use crate::policy::NetworkPolicy;

pub async fn execute_with_network_control(
    _command: &str,
    _args: &[&str],
    _policy: &NetworkPolicy,
) -> Result<i32, crate::error::MoriError> {
    Err(crate::error::MoriError::Unsupported)
}
