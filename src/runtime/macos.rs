pub fn execute_with_network_control(
    _command: &str,
    _args: &[&str],
    _allow_network_rules: &[String],
) -> Result<i32, crate::error::MoriError> {
    Err(crate::error::MoriError::Unsupported)
}
