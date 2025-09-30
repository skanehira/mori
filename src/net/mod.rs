pub mod cache;
pub mod parser;
pub mod resolver;

// Re-export main types and functions
pub use parser::{NetworkRules, parse_allow_network};
pub use resolver::{ResolvedAddresses, resolve_domains};
