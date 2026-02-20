use crate::types::*;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdsError {
    #[error("failed to read ADS file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("validation failed: {0}")]
    Validation(String),
}

pub fn parse_file(path: &Path) -> Result<AgentDefinition, AdsError> {
    let content = std::fs::read_to_string(path)?;
    parse_str(&content)
}

pub fn parse_str(content: &str) -> Result<AgentDefinition, AdsError> {
    let def: AgentDefinition = toml::from_str(content)?;
    validate(&def)?;
    Ok(def)
}

pub fn validate(def: &AgentDefinition) -> Result<(), AdsError> {
    if def.agent.name.is_empty() {
        return Err(AdsError::Validation("agent.name cannot be empty".into()));
    }
    if !def.agent.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(AdsError::Validation(
            format!("agent.name '{}' contains invalid characters (use alphanumeric, dash, underscore)", def.agent.name),
        ));
    }
    if def.agent.trust_level == TrustLevel::Untrusted && def.capabilities.filesystem.deny.is_empty() {
        return Err(AdsError::Validation("untrusted agents must have at least one filesystem deny pattern".into()));
    }
    for endpoint in &def.capabilities.network.allow_egress {
        if !endpoint.starts_with("https://") && !endpoint.starts_with("http://") {
            return Err(AdsError::Validation(
                format!("network.allow_egress '{}' must start with http:// or https://", endpoint),
            ));
        }
    }
    if parse_memory_string(&def.resources.memory_limit).is_none() {
        return Err(AdsError::Validation(
            format!("resources.memory_limit '{}' is not a valid size (use e.g. 512M, 1G)", def.resources.memory_limit),
        ));
    }
    if def.resources.pids_limit == 0 {
        return Err(AdsError::Validation("resources.pids_limit cannot be 0".into()));
    }
    Ok(())
}

pub fn parse_memory_string(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let (num_str, multiplier) = if s.ends_with('G') || s.ends_with('g') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024u64)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len() - 1], 1024 * 1024u64)
    } else if s.ends_with('K') || s.ends_with('k') {
        (&s[..s.len() - 1], 1024u64)
    } else {
        (s, 1u64)
    };
    num_str.parse::<u64>().ok().map(|n| n * multiplier)
}

pub fn effective_permissions(def: &AgentDefinition) -> EffectivePermissions {
    EffectivePermissions {
        agent_name: def.agent.name.clone(),
        trust_level: def.agent.trust_level.clone(),
        fs_readable: def.capabilities.filesystem.read.clone(),
        fs_writable: def.capabilities.filesystem.write.clone(),
        fs_denied: def.capabilities.filesystem.deny.clone(),
        net_egress_allowed: def.capabilities.network.allow_egress.clone(),
        net_ingress: def.capabilities.network.allow_ingress,
        exec_allowed: def.capabilities.exec.allow.clone(),
        exec_denied: def.capabilities.exec.deny.clone(),
        api_scopes: def.capabilities.api.keys().cloned().collect(),
        resource_memory: def.resources.memory_limit.clone(),
        resource_pids: def.resources.pids_limit,
    }
}

#[derive(Debug, Clone)]
pub struct EffectivePermissions {
    pub agent_name: String,
    pub trust_level: TrustLevel,
    pub fs_readable: Vec<String>,
    pub fs_writable: Vec<String>,
    pub fs_denied: Vec<String>,
    pub net_egress_allowed: Vec<String>,
    pub net_ingress: bool,
    pub exec_allowed: Vec<String>,
    pub exec_denied: Vec<String>,
    pub api_scopes: Vec<String>,
    pub resource_memory: String,
    pub resource_pids: u64,
}

impl std::fmt::Display for EffectivePermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Agent: {} [trust={:?}]", self.agent_name, self.trust_level)?;
        writeln!(f)?;
        writeln!(f, "Filesystem:")?;
        writeln!(f, "  Read:  {}", if self.fs_readable.is_empty() { "(none)".into() } else { self.fs_readable.join(", ") })?;
        writeln!(f, "  Write: {}", if self.fs_writable.is_empty() { "(none)".into() } else { self.fs_writable.join(", ") })?;
        writeln!(f, "  Deny:  {}", if self.fs_denied.is_empty() { "(none)".into() } else { self.fs_denied.join(", ") })?;
        writeln!(f)?;
        writeln!(f, "Network:")?;
        writeln!(f, "  Egress: {}", if self.net_egress_allowed.is_empty() { "(none)".into() } else { self.net_egress_allowed.join(", ") })?;
        writeln!(f, "  Ingress: {}", if self.net_ingress { "allowed" } else { "blocked" })?;
        writeln!(f)?;
        writeln!(f, "Execution:")?;
        writeln!(f, "  Allow: {}", if self.exec_allowed.is_empty() { "(none)".into() } else { self.exec_allowed.join(", ") })?;
        writeln!(f, "  Deny:  {}", if self.exec_denied.is_empty() { "(none)".into() } else { self.exec_denied.join(", ") })?;
        writeln!(f)?;
        writeln!(f, "API Scopes: {}", if self.api_scopes.is_empty() { "(none)".into() } else { self.api_scopes.join(", ") })?;
        writeln!(f)?;
        writeln!(f, "Resources: memory={}, pids={}", self.resource_memory, self.resource_pids)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_ADS: &str = r#"
[agent]
name = "test-agent"
trust_level = "untrusted"

[capabilities.filesystem]
read = ["/tmp/test/**"]
write = ["/tmp/test/output/**"]
deny = ["/etc/**", "/home/**/.ssh/**"]
"#;

    const FULL_ADS: &str = r#"
[agent]
name = "inbox-manager"
version = "1.0.0"
framework = "openclaw"
runtime = "python3.12"
model = "claude-sonnet-4-5"
owner = "tyler@example.com"
restart_policy = "on-failure"
max_runtime = "4h"
trust_level = "untrusted"

[capabilities.filesystem]
read = ["/home/user/mail/**", "/tmp/aegis/inbox-manager/**"]
write = ["/tmp/aegis/inbox-manager/**"]
deny = ["/etc/**", "/home/user/.ssh/**", "**/*.key", "**/*.pem"]

[capabilities.network]
allow_egress = ["https://api.anthropic.com:443", "https://imap.gmail.com:993"]
deny_egress = ["*"]
allow_ingress = false
dns_policy = "restricted"

[capabilities.exec]
allow = ["python3"]
deny = ["bash", "sh", "nc", "wget", "curl", "ssh"]
allow_subprocess = false

[capabilities.api.gmail]
scopes = ["read", "send"]
rate_limit = "60/hour"

[capabilities.api.calendar]
scopes = ["read"]
rate_limit = "30/hour"

[resources]
cpu_shares = 256
memory_limit = "512M"
pids_limit = 64

[audit]
log_level = "actions"
retention = "90d"
hash_chain = true
export = ["file"]

[checkpoint]
interval = "30m"
max_snapshots = 10
before_high_risk = true
rollback_triggers = ["deny_violation_count > 5", "credential_access_attempt"]

[compliance]
frameworks = ["soc2", "cmmc-l2"]
review_interval = "30d"
"#;

    #[test]
    fn parse_minimal_ads() {
        let def = parse_str(MINIMAL_ADS).expect("should parse minimal ADS");
        assert_eq!(def.agent.name, "test-agent");
        assert_eq!(def.agent.trust_level, TrustLevel::Untrusted);
        assert_eq!(def.capabilities.filesystem.read.len(), 1);
        assert_eq!(def.capabilities.filesystem.deny.len(), 2);
        assert_eq!(def.resources.memory_limit, "512M");
        assert_eq!(def.resources.pids_limit, 64);
    }

    #[test]
    fn parse_full_ads() {
        let def = parse_str(FULL_ADS).expect("should parse full ADS");
        assert_eq!(def.agent.name, "inbox-manager");
        assert_eq!(def.agent.framework, AgentFramework::OpenClaw);
        assert_eq!(def.capabilities.network.allow_egress.len(), 2);
        assert_eq!(def.capabilities.exec.allow, vec!["python3"]);
        assert!(def.capabilities.api.contains_key("gmail"));
        assert!(def.capabilities.api.contains_key("calendar"));
        assert_eq!(def.checkpoint.rollback_triggers.len(), 2);
        assert_eq!(def.compliance.frameworks, vec!["soc2", "cmmc-l2"]);
    }

    #[test]
    fn reject_empty_name() {
        let toml = r#"
[agent]
name = ""
[capabilities.filesystem]
deny = ["/etc/**"]
"#;
        let result = parse_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn reject_untrusted_without_deny() {
        let toml = r#"
[agent]
name = "test"
trust_level = "untrusted"
"#;
        let result = parse_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("deny pattern"));
    }

    #[test]
    fn accept_trusted_without_deny() {
        let toml = r#"
[agent]
name = "test"
trust_level = "trusted"
"#;
        let result = parse_str(toml);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_invalid_network_endpoint() {
        let toml = r#"
[agent]
name = "test"
trust_level = "trusted"
[capabilities.network]
allow_egress = ["not-a-url"]
"#;
        let result = parse_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must start with http"));
    }

    #[test]
    fn parse_memory_strings() {
        assert_eq!(parse_memory_string("512M"), Some(512 * 1024 * 1024));
        assert_eq!(parse_memory_string("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_memory_string("64K"), Some(64 * 1024));
        assert_eq!(parse_memory_string("1024"), Some(1024));
        assert_eq!(parse_memory_string(""), None);
    }

    #[test]
    fn effective_permissions_display() {
        let def = parse_str(FULL_ADS).expect("should parse");
        let perms = effective_permissions(&def);
        let display = format!("{}", perms);
        assert!(display.contains("inbox-manager"));
        assert!(display.contains("Untrusted"));
        assert!(display.contains("api.anthropic.com"));
    }
}
